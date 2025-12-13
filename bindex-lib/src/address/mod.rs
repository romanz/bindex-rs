pub mod cache;

use std::{path::Path, time::Duration};

use bitcoin::hashes::Hash;
use log::*;

use crate::{
    chain::{self, Chain, Location},
    cli, client, db, index,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("client failed: {0}")]
    Client(#[from] client::Error),

    #[error("use https://github.com/bitcoin/bitcoin/pull/33657")]
    NotSupported,

    #[error("indexing failed: {0:?}")]
    Index(#[from] index::Error),

    #[error("DB failed: {0}")]
    DB(#[from] rocksdb::Error),

    #[error("Genesis block hash mismatch: {0} != {1}")]
    ChainMismatch(bitcoin::BlockHash, bitcoin::BlockHash),
}

pub struct Index {
    genesis_hash: bitcoin::BlockHash,
    chain: chain::Chain,
    client: client::Client,
    store: db::Store,
}

pub struct Stats {
    pub tip: bitcoin::BlockHash,
    pub indexed_blocks: usize,
    pub size_read: usize,
    pub elapsed: std::time::Duration,
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

impl Index {
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

        // make sure bitcoind supports required REST endpoints
        match client.get_spent_bytes(genesis_hash) {
            Err(client::Error::Http(ureq::Error::StatusCode(404))) => Err(Error::NotSupported)?,
            res => res?,
        };
        let dummy_txpos = index::TxBlockPos { offset: 0, size: 1 };
        match client.get_tx_bytes_from_block(genesis_hash, dummy_txpos) {
            Err(client::Error::Http(ureq::Error::StatusCode(404))) => Err(Error::NotSupported)?,
            res => res?,
        };

        let store = db::Store::open(db_path)?;
        let chain = chain::Chain::new(store.headers()?);
        if let Some(indexed_genesis) = chain.genesis() {
            if indexed_genesis.hash() != genesis_hash {
                return Err(Error::ChainMismatch(indexed_genesis.hash(), genesis_hash));
            }
            info!(
                "block={} height={} headers loaded",
                chain.tip_hash().unwrap(),
                chain.tip_height().unwrap(),
            );
        }
        Ok(Index {
            genesis_hash,
            chain,
            client,
            store,
        })
    }

    pub fn open_default(db_path: &str, network: cli::Network) -> Result<Self, Error> {
        let bitcoin_network: bitcoin::Network = network.into();
        let default_db_path = format!("{db_path}/{bitcoin_network}");
        let default_rpc_port = match network {
            cli::Network::Bitcoin => 8332,
            cli::Network::Testnet => 18332,
            cli::Network::Testnet4 => 48332,
            cli::Network::Signet => 38332,
            cli::Network::Regtest => 18443,
        };
        let default_rest_url = format!("http://localhost:{default_rpc_port}");
        Self::open(default_db_path, default_rest_url)
    }

    fn drop_tip(&mut self) -> Result<bitcoin::BlockHash, Error> {
        let stale = self.chain.pop().expect("cannot drop tip of an empty chain");
        let block_bytes = self.client.get_block_bytes(stale.hash())?;
        let spent_bytes = self.client.get_spent_bytes(stale.hash())?;
        let mut builder = index::Builder::new(&self.chain);
        builder.index(stale.hash(), &block_bytes, &spent_bytes)?;
        self.store.delete(&builder.into_batches())?;
        Ok(stale.hash())
    }

    pub fn sync_chain(&mut self, limit: usize) -> Result<Stats, Error> {
        let mut stats = Stats::new(
            self.chain
                .tip_hash()
                .unwrap_or_else(bitcoin::BlockHash::all_zeros),
        );
        let t = std::time::Instant::now();

        let headers = loop {
            let blockhash = self.chain.tip_hash().unwrap_or(self.genesis_hash);
            let headers = self.client.get_headers(blockhash, limit)?;
            if let Some(first) = headers.first() {
                // skip first response header (when asking for non-genesis block)
                let skip_first = Some(first.block_hash()) == self.chain.tip_hash();
                break headers.into_iter().skip(if skip_first { 1 } else { 0 });
            }
            warn!(
                "block={} height={} was rolled back",
                blockhash,
                self.chain.tip_height().unwrap(),
            );
            assert_eq!(blockhash, self.drop_tip()?);
        };

        let mut builder = index::Builder::new(&self.chain);
        for header in headers {
            let blockhash = header.block_hash();
            if self.chain.tip_hash() == Some(blockhash) {
                continue; // skip first header from response
            }
            // TODO: can be done concurrently
            let block_bytes = self.client.get_block_bytes(blockhash)?;
            let spent_bytes = self.client.get_spent_bytes(blockhash)?;
            builder.index(blockhash, &block_bytes, &spent_bytes)?;

            stats.tip = blockhash;
            stats.size_read += block_bytes.len();
            stats.size_read += spent_bytes.len();
            stats.indexed_blocks += 1;
        }
        let batches = builder.into_batches();
        self.store.write(&batches)?;
        for batch in batches {
            self.chain.add(batch.header);
        }

        stats.elapsed = t.elapsed();
        if stats.indexed_blocks > 0 {
            self.store.flush()?;
            info!(
                "block={} height={}: indexed {} blocks, {:.3}[MB], dt = {:.3}[s]: {:.3} [ms/block], {:.3} [MB/block], {:.3} [MB/s]",
                self.chain.tip_hash().unwrap(),
                self.chain.tip_height().unwrap(),
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

    fn locations_by_scripthash(
        &self,
        script_hash: &index::ScriptHash,
        from: index::TxNum,
    ) -> Result<impl Iterator<Item = Location<'_>>, Error> {
        Ok(self
            .store
            .scan_by_script_hash(script_hash, from)?
            .into_iter()
            // chain and store must be in sync
            .map(|txnum| self.chain.find_by_txnum(txnum).expect("invalid txnum")))
    }

    fn get_tx_bytes(&self, location: &Location) -> Result<Vec<u8>, Error> {
        // Lookup tx position within its block (offset & size)
        let pos = self.store.get_tx_block_pos(location.txnum)?;
        // Fetch the bytes from bitcoind
        Ok(self
            .client
            .get_tx_bytes_from_block(location.indexed_header.hash(), pos)?)
    }

    fn chain(&self) -> &Chain {
        &self.chain
    }
}
