use std::fmt::Debug;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use bitcoin::{hashes::Hash, Network};
use log::*;

use crate::{client, db, headers, index, Location};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("client failed: {0}")]
    Client(#[from] client::Error),

    #[error("use https://github.com/bitcoin/bitcoin/pull/33657")]
    NotSupported,

    #[error("indexing failed: {0:?}")]
    Index(#[from] index::Error),

    #[error("RocksDB failed: {0}")]
    RocksDB(#[from] rust_rocksdb::Error),

    #[error("Genesis block hash mismatch: {0} != {1}")]
    ChainMismatch(bitcoin::BlockHash, bitcoin::BlockHash),

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

#[derive(Debug)]
pub struct Config {
    db_path: PathBuf,
    url: String,
}

impl IndexedChain {
    /// Open an existing DB, or create if missing.
    /// Use binary format REST API for fetching the data from bitcoind.
    pub fn open(db_dir: impl AsRef<Path>, network: Network) -> Result<Self, Error> {
        let db_path = db_dir.as_ref().to_path_buf().join(network.to_string());
        let url = format!("http://localhost:{}", default_rpc_port(network));
        Self::from_config(Config { db_path, url })
    }

    fn from_config(config: Config) -> Result<Self, Error> {
        info!("index: {:?}", config);
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .max_response_header_size(usize::MAX) // Disabled as a workaround
                .build(),
        );
        let client = client::Client::new(agent, config.url);
        let genesis_hash = client.get_blockhash_by_height(0)?;
        let genesis_block = client.get_block_bytes(genesis_hash)?;

        // make sure bitcoind supports the required REST API endpoints
        // * /rest/getspenttxouts/ (added in https://github.com/bitcoin/bitcoin/pull/32540)
        match client.get_spent_bytes(genesis_hash) {
            Err(client::Error::Http(ureq::Error::StatusCode(404))) => Err(Error::NotSupported)?,
            res => res?,
        };
        // * /rest/blockpart/ (added in https://github.com/bitcoin/bitcoin/pull/33657)
        let txpos = index::TxBlockPos {
            offset: 0,
            size: genesis_block
                .len()
                .try_into()
                .expect("too large genesis block"),
        };
        match client.get_block_part(genesis_hash, txpos) {
            Err(client::Error::Http(ureq::Error::StatusCode(404))) => Err(Error::NotSupported)?,
            res => assert_eq!(index::BlockBytes::new(res?), genesis_block),
        };

        let store = db::DB::open(config.db_path)?;
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
    pub fn sync(&mut self, limit: usize) -> Result<Stats, Error> {
        let t = std::time::Instant::now();
        // get new headers (and drop stale ones if needed)
        let headers = self.fetch_new_headers(limit)?;
        // start indexing from a valid tip
        let mut stats = Stats::new(self.headers.tip_hash());

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

fn default_rpc_port(nework: Network) -> u16 {
    match nework {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{consensus::deserialize, Amount, Transaction};
    use corepc_node::{exe_path, Conf, Node};

    #[test]
    fn test_chain_bitcoind() -> Result<(), Box<dyn std::error::Error>> {
        let mut conf = Conf::default();
        conf.args.push("-rest");

        let node = Node::with_conf(exe_path().unwrap(), &conf).unwrap();

        let get_tip = || {
            node.client
                .get_best_block_hash()
                .unwrap()
                .block_hash()
                .unwrap()
        };
        let addr = node.client.new_address().unwrap();

        const BLOCKS: usize = 101; // so that the first coinbase will be spendable
        node.client.generate_to_address(BLOCKS, &addr).unwrap();

        let dir = tempfile::TempDir::with_prefix("bindex_db").unwrap();
        let config = Config {
            db_path: dir.path().to_path_buf(),
            url: format!("http://{}", node.params.rpc_socket),
        };
        let mut chain = IndexedChain::from_config(config).unwrap();
        let stats = chain.sync(1000).unwrap();
        assert_eq!(stats.indexed_blocks, BLOCKS + 1);
        assert_eq!(stats.tip, get_tip());

        let addr1 = node.client.new_address().unwrap();
        let addr2 = node.client.new_address().unwrap();

        let txid1 = node
            .client
            .send_to_address(&addr1, Amount::from_int_btc(20))
            .unwrap()
            .txid()
            .unwrap();
        let tx1 = node
            .client
            .get_raw_transaction(txid1)
            .unwrap()
            .transaction()
            .unwrap();
        let txid2 = node
            .client
            .send_to_address(&addr2, Amount::from_int_btc(40))
            .unwrap()
            .txid()
            .unwrap();
        let tx2 = node
            .client
            .get_raw_transaction(txid2)
            .unwrap()
            .transaction()
            .unwrap();
        node.client.generate_to_address(1, &addr).unwrap();
        assert_eq!(node.client.get_mempool_info().unwrap().size, 0);

        let stats = chain.sync(1000).unwrap();
        assert_eq!(stats.indexed_blocks, 1);
        assert_eq!(stats.tip, get_tip());
        let stats = chain.sync(1000).unwrap();
        assert_eq!(stats.indexed_blocks, 0);
        assert_eq!(stats.tip, get_tip());

        let loc1 = exactly_one(chain.locations_by_txid(&txid1).unwrap());
        assert_eq!(loc1.block_height, BLOCKS + 1);
        let tx_bytes = chain.get_tx_bytes(&loc1).unwrap();
        assert_eq!(deserialize::<Transaction>(&tx_bytes).unwrap(), tx1);

        let loc2 = exactly_one(chain.locations_by_txid(&txid2).unwrap());
        assert_eq!(loc1.block_height, BLOCKS + 1);
        let tx_bytes = chain.get_tx_bytes(&loc2).unwrap();
        assert_eq!(deserialize::<Transaction>(&tx_bytes).unwrap(), tx2);

        let txs: Vec<_> = chain
            .locations_by_scripthash(&index::ScriptHash::new(&addr.script_pubkey()), None)
            .unwrap()
            .collect();
        assert_eq!(txs.len(), BLOCKS + 2);

        let locations: Vec<_> = chain
            .locations_by_scripthash(&index::ScriptHash::new(&addr1.script_pubkey()), None)
            .unwrap()
            .collect();
        assert_eq!(locations, vec![loc1, loc2]);

        let locations: Vec<_> = chain
            .locations_by_scripthash(&index::ScriptHash::new(&addr2.script_pubkey()), None)
            .unwrap()
            .collect();
        assert_eq!(locations, vec![loc2]);

        // check reorg
        let old_tip = get_tip();
        node.client.invalidate_block(old_tip).unwrap();
        let stats = chain.sync(1000).unwrap();
        assert!(old_tip != stats.tip);
        assert_eq!(stats.indexed_blocks, 0);
        assert_eq!(stats.tip, get_tip());

        assert_eq!(chain.locations_by_txid(&txid1).unwrap().next(), None);
        assert_eq!(chain.locations_by_txid(&txid2).unwrap().next(), None);
        assert_eq!(
            chain
                .locations_by_scripthash(&index::ScriptHash::new(&addr1.script_pubkey()), None)
                .unwrap()
                .next(),
            None,
        );

        assert_eq!(
            chain
                .locations_by_scripthash(&index::ScriptHash::new(&addr2.script_pubkey()), None)
                .unwrap()
                .next(),
            None,
        );

        Ok(())
    }

    fn exactly_one<T>(mut iter: impl Iterator<Item = T>) -> T {
        let res = iter.next().unwrap();
        assert!(iter.next().is_none());
        res
    }
}
