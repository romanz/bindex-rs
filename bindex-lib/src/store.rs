use std::fmt::Debug;
use std::{path::Path, time::Duration};

use bitcoin::hashes::Hash;
use log::*;

use crate::{client, db, headers, index, network::Network, Location};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("client failed: {0}")]
    Client(#[from] client::Error),

    #[error("use https://github.com/bitcoin/bitcoin/pull/33657")]
    NotSupported,

    #[error("indexing failed: {0:?}")]
    Index(#[from] index::Error),

    #[error("RocksDB failed: {0}")]
    RocksDB(#[from] rocksdb::Error),

    #[error("Genesis block hash mismatch: {0} != {1}")]
    ChainMismatch(bitcoin::BlockHash, bitcoin::BlockHash),

    #[error("rusqlite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("invalid address: {0}")]
    Address(#[from] bitcoin::address::ParseError),

    #[error("block not found: {0}")]
    BlockNotFound(#[from] headers::Reorg),
}

#[derive(Debug)]
pub struct Stats {
    pub tip: bitcoin::BlockHash,
    pub indexed_blocks: usize,
    pub size_read: usize,
    pub elapsed: Duration,
}

impl Stats {
    fn new(tip: bitcoin::BlockHash) -> Self {
        Self {
            tip,
            indexed_blocks: 0,
            size_read: 0,
            elapsed: Duration::ZERO,
        }
    }
}

pub struct IndexedChain {
    genesis_hash: bitcoin::BlockHash,
    headers: headers::Headers,
    client: client::Client,
    store: db::DB,
}

impl IndexedChain {
    /// Open an existing DB, or create if missing.
    /// Use binary format REST API for fetching the data from bitcoind.
    pub fn open(db_path: impl AsRef<Path>, url: impl Into<String>) -> Result<Self, Error> {
        let db_path = db_path.as_ref();
        let url = url.into();
        info!("index DB: {:?}, node URL: {}", db_path, url);
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .max_response_header_size(usize::MAX) // Disabled as a workaround
                .build(),
        );
        let client = client::Client::new(agent, url);
        let genesis_hash = client.get_blockhash_by_height(0)?;
        let genesis_block = client.get_block_bytes(genesis_hash)?;

        // make sure bitcoind supports the required REST API endpoints
        match client.get_spent_bytes(genesis_hash) {
            Err(client::Error::Http(ureq::Error::StatusCode(404))) => Err(Error::NotSupported)?,
            res => res?,
        };
        let size = genesis_block.len().try_into().unwrap();
        let txpos = index::TxBlockPos { offset: 0, size };
        match client.get_block_part(genesis_hash, txpos) {
            Err(client::Error::Http(ureq::Error::StatusCode(404))) => Err(Error::NotSupported)?,
            res => assert_eq!(index::BlockBytes::new(res?), genesis_block),
        };

        let store = db::DB::open(db_path)?;
        let headers = headers::Headers::new(store.headers()?);
        if let Some(indexed_genesis) = headers.genesis() {
            if indexed_genesis.hash() != genesis_hash {
                return Err(Error::ChainMismatch(indexed_genesis.hash(), genesis_hash));
            }
            info!(
                "block={} height={} headers loaded",
                headers.tip_hash(),
                headers.tip_height().unwrap(),
            );
        }
        Ok(IndexedChain {
            genesis_hash,
            headers,
            client,
            store,
        })
    }

    pub fn open_default(db_path: impl AsRef<Path>, network: Network) -> Result<Self, Error> {
        let bitcoin_network: bitcoin::Network = network.into();
        let default_db_path = db_path
            .as_ref()
            .to_path_buf()
            .join(bitcoin_network.to_string());
        let default_rest_url = format!("http://localhost:{}", network.default_rpc_port());
        Self::open(default_db_path, default_rest_url)
    }

    fn drop_tip(&mut self) -> Result<bitcoin::BlockHash, Error> {
        let stale = self
            .headers
            .pop()
            .expect("cannot drop tip of an empty chain");
        // "Re-index" stale block in order to delete its entries from the DB
        let stale_hash = stale.hash();
        let mut builder = index::IndexBuilder::new(self.headers.tip());
        builder.add(
            stale_hash,
            &self.client.get_block_bytes(stale_hash)?,
            &self.client.get_spent_bytes(stale_hash)?,
        )?;
        self.store.delete(&builder.into_batches())?;
        Ok(stale_hash)
    }

    fn fetch_new_headers(
        &mut self,
        limit: usize,
    ) -> Result<impl IntoIterator<Item = bitcoin::block::Header>, Error> {
        loop {
            // usually the first header is already part of the current chain
            let (mut blockhash, mut to_skip) = (self.headers.tip_hash(), 1);
            if blockhash == bitcoin::BlockHash::all_zeros() {
                // but if the chain is empty, we need also to fetch the genesis header
                (blockhash, to_skip) = (self.genesis_hash, 0)
            }
            let headers = self.client.get_headers(blockhash, limit)?;
            if !headers.is_empty() {
                return Ok(headers.into_iter().skip(to_skip));
            }
            warn!(
                "block={} height={} was rolled back",
                blockhash,
                self.headers.tip_height().unwrap(),
            );
            // drop stale tip and retry fetching
            assert_eq!(blockhash, self.drop_tip()?);
        }
    }

    /// Synchornize index with bitcoind.
    /// Compactions are started when no new blocks are indexed.
    pub fn sync_chain(&mut self, limit: usize) -> Result<Stats, Error> {
        let mut stats = Stats::new(self.headers.tip_hash());
        let t = std::time::Instant::now();

        let headers = self.fetch_new_headers(limit)?;

        let mut builder = index::IndexBuilder::new(self.headers.tip());
        for header in headers {
            let blockhash = header.block_hash();
            // TODO: can be done concurrently
            let block_bytes = self.client.get_block_bytes(blockhash)?;
            let spent_bytes = self.client.get_spent_bytes(blockhash)?;
            builder.add(blockhash, &block_bytes, &spent_bytes)?;

            stats.tip = blockhash;
            stats.size_read += block_bytes.len();
            stats.size_read += spent_bytes.len();
            stats.indexed_blocks += 1;
        }
        let batches = builder.into_batches();
        self.store.write(&batches)?;
        for batch in batches {
            self.headers.add(batch.header);
        }

        stats.elapsed = t.elapsed();
        if stats.indexed_blocks > 0 {
            self.store.flush()?;
            info!(
                "block={} height={}: indexed {} blocks, {:.3}[MB], dt = {:.3}[s]: {:.3} [ms/block], {:.3} [MB/block], {:.3} [MB/s]",
                self.headers.tip_hash(),
                self.headers.tip_height().unwrap(),
                stats.indexed_blocks,
                stats.size_read as f64 / (1e6),
                stats.elapsed.as_secs_f64(),
                stats.elapsed.as_secs_f64() * 1e3 / (stats.indexed_blocks as f64),
                stats.size_read as f64 / (1e6 * stats.indexed_blocks as f64),
                stats.size_read as f64 / (1e6 * stats.elapsed.as_secs_f64()),
            );
        } else {
            // Start autocompactions when there are no new indexed blocks
            self.store.start_compactions()?;
        }
        Ok(stats)
    }

    /// Collect transactions' locations spending/funding this scripthash.
    /// False-positive may occur, so post-filtering should be applied.
    pub fn locations_by_scripthash(
        &self,
        script_hash: &index::ScriptHash,
        latest_header: Option<&index::IndexedHeader>,
    ) -> Result<impl Iterator<Item = Location<'_>>, Error> {
        let from = latest_header
            .map(|header| header.next_txnum())
            .unwrap_or_default();
        let txnums = self.store.scan_by_script_hash(script_hash, from)?;
        Ok(txnums
            .into_iter()
            // chain and store must be in sync
            .map(|txnum| self.headers.find_by_txnum(txnum)))
    }

    /// Collect transactions' locations matching this txid.
    /// False-positive may occur, so post-filtering should be applied.
    pub fn locations_by_txid(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<impl Iterator<Item = Location<'_>>, Error> {
        let txnums = self.store.scan_by_txid(txid)?;
        Ok(txnums
            .into_iter()
            // chain and store must be in sync
            .map(|txnum| self.headers.find_by_txnum(txnum)))
    }

    /// Fetch transaction's bytes from bitcoind.
    pub fn get_tx_bytes(&self, location: &Location) -> Result<Vec<u8>, Error> {
        // Lookup tx position within its block (offset & size)
        let pos = self.store.get_tx_block_pos(location.txnum)?;
        // Fetch the bytes from bitcoind
        Ok(self
            .client
            .get_block_part(location.indexed_header.hash(), pos)?)
    }

    pub fn headers(&self) -> &headers::Headers {
        &self.headers
    }
}
