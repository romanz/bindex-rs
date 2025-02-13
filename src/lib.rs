use std::path::Path;

use log::*;

mod chain;
mod client;
mod db;
mod index;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("client failed: {0}")]
    Client(#[from] client::Error),

    #[error("indexing failed: {0:?}")]
    Index(#[from] index::Error),

    #[error("DB failed: {0}")]
    DB(#[from] rocksdb::Error),

    #[error("Genesis block hash mismatch: {0} != {1}")]
    ChainMismatch(bitcoin::BlockHash, bitcoin::BlockHash),

    #[error("Invalid transaction position: {0:?}")]
    InvalidPosition(index::TxPos),

    #[error("Block {0} was rolled back")]
    Rollback(bitcoin::BlockHash),
}

pub struct AddrIndex {
    genesis_hash: bitcoin::BlockHash,
    chain: chain::Chain,
    client: client::Client,
    store: db::Store,
}

#[derive(Default)]
pub struct Stats {
    pub indexed_blocks: usize,
    pub size_read: usize,
    pub elapsed: std::time::Duration,
}

#[derive(PartialEq, Eq, PartialOrd)]
pub struct Location<'a> {
    pub height: usize, // block height
    pub offset: u64,   // tx position within its block
    pub indexed_header: &'a index::Header,
}

impl Ord for Location<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.height, self.offset).cmp(&(other.height, other.offset))
    }
}

impl AddrIndex {
    pub fn open(db_path: impl AsRef<Path>, url: impl Into<String>) -> Result<Self, Error> {
        let agent = ureq::Agent::new_with_config(
            ureq::config::Config::builder()
                .max_response_header_size(usize::MAX) // Disabled as a workaround
                .build(),
        );
        let client = client::Client::new(agent, url);
        let genesis_hash = client.get_blockhash_by_height(0)?;

        let store = db::Store::open(db_path)?;
        let chain = chain::Chain::new(store.headers()?);
        if let Some(indexed_genesis) = chain.get_by_height(0) {
            if indexed_genesis.hash() != genesis_hash {
                return Err(Error::ChainMismatch(indexed_genesis.hash(), genesis_hash));
            }
        }

        Ok(AddrIndex {
            genesis_hash,
            chain,
            client,
            store,
        })
    }

    fn get_next_headers(&self, limit: usize) -> Result<Vec<client::HeaderInfo>, Error> {
        Ok(match self.chain.tip_hash() {
            None => self.client.get_headers_info(self.genesis_hash, limit)?,
            Some(tip_hash) => {
                let mut infos = self.client.get_headers_info(tip_hash, limit)?;
                if infos.is_empty() {
                    return Err(Error::Rollback(tip_hash));
                }
                let first_info = &infos[0];
                assert_eq!(first_info.hash, tip_hash);
                infos.remove(0);
                infos
            }
        })
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

    pub fn sync(&mut self, limit: usize) -> Result<Stats, Error> {
        let mut stats = Stats::default();
        let t = std::time::Instant::now();

        let next_headers = loop {
            match self.get_next_headers(limit) {
                Ok(next_headers) => break next_headers,
                Err(Error::Rollback(blockhash)) => {
                    warn!(
                        "block={} height={} was rolled back",
                        blockhash,
                        self.chain.tip_height().unwrap(),
                    );
                    assert_eq!(blockhash, self.drop_tip()?);
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            };
        };
        let mut builder = index::Builder::new(&self.chain);
        for info in next_headers {
            // TODO: can be done concurrently
            let block_bytes = self.client.get_block_bytes(info.hash)?;
            let spent_bytes = self.client.get_spent_bytes(info.hash)?;
            builder.index(info.hash, &block_bytes, &spent_bytes)?;

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
                "block={} height={}: {} indexed, {:.3}[MB], dt = {:.3}[s]: {:.3} [ms/block], {:.3} [MB/block], {:.3} [MB/s]",
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
            self.store.start_compactions()?;
        }
        Ok(stats)
    }

    pub fn find(&self, script: &bitcoin::Script) -> Result<Vec<Location>, Error> {
        let positions = self.store.scan(script)?;
        positions
            .into_iter()
            .map(|txpos| {
                self.chain
                    .find_by_txpos(&txpos)
                    .ok_or_else(|| Error::InvalidPosition(txpos))
            })
            .collect::<Result<Vec<Location>, Error>>()
    }

    pub fn get_tx_bytes(&self, location: &Location) -> Result<Vec<u8>, Error> {
        Ok(self
            .client
            .get_tx_bytes_from_block(location.indexed_header.hash(), location.offset)?)
    }
}
