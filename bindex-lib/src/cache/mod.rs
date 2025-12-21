use std::{collections::BTreeSet, fmt::Debug};
use std::{path::Path, time::Duration};

use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    BlockHash, Txid,
};
use bitcoin_slices::{bsl, Parse};
use log::*;
use rusqlite::OptionalExtension;

use crate::{
    chain::{self, Chain, Location},
    cli, client, db,
    index::{self, ScriptHash},
};

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
    BlockNotFound(#[from] chain::Reorg),
}

pub struct IndexedChain {
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

        let store = db::Store::open(db_path)?;
        let chain = chain::Chain::new(store.headers()?);
        if let Some(indexed_genesis) = chain.genesis() {
            if indexed_genesis.hash() != genesis_hash {
                return Err(Error::ChainMismatch(indexed_genesis.hash(), genesis_hash));
            }
            info!(
                "block={} height={} headers loaded",
                chain.tip_hash(),
                chain.tip_height().unwrap(),
            );
        }
        Ok(IndexedChain {
            genesis_hash,
            chain,
            client,
            store,
        })
    }

    pub fn open_default(db_path: &str, network: cli::Network) -> Result<Self, Error> {
        let bitcoin_network: bitcoin::Network = network.into();
        let default_db_path = format!("{db_path}/{bitcoin_network}");
        let default_rest_url = format!("http://localhost:{}", network.default_rpc_port());
        Self::open(default_db_path, default_rest_url)
    }

    fn drop_tip(&mut self) -> Result<bitcoin::BlockHash, Error> {
        let stale = self.chain.pop().expect("cannot drop tip of an empty chain");
        let block_bytes = self.client.get_block_bytes(stale.hash())?;
        let spent_bytes = self.client.get_spent_bytes(stale.hash())?;
        let mut builder = index::IndexBuilder::new(&self.chain);
        builder.add(stale.hash(), &block_bytes, &spent_bytes)?;
        self.store.delete(&builder.into_batches())?;
        Ok(stale.hash())
    }

    fn fetch_new_headers(
        &mut self,
        limit: usize,
    ) -> Result<impl IntoIterator<Item = bitcoin::block::Header>, Error> {
        loop {
            // usually the first header is already part of the current chain
            let (mut blockhash, mut to_skip) = (self.chain.tip_hash(), 1);
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
                self.chain.tip_height().unwrap(),
            );
            assert_eq!(blockhash, self.drop_tip()?);
        }
    }

    pub fn sync_chain(&mut self, limit: usize) -> Result<Stats, Error> {
        let mut stats = Stats::new(self.chain.tip_hash());
        let t = std::time::Instant::now();

        let headers = self.fetch_new_headers(limit)?;

        let mut builder = index::IndexBuilder::new(&self.chain);
        for header in headers {
            let blockhash = header.block_hash();
            if self.chain.tip_hash() == blockhash {
                continue; // skip first header from response
            }
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
            self.chain.add(batch.header);
        }

        stats.elapsed = t.elapsed();
        if stats.indexed_blocks > 0 {
            self.store.flush()?;
            info!(
                "block={} height={}: indexed {} blocks, {:.3}[MB], dt = {:.3}[s]: {:.3} [ms/block], {:.3} [MB/block], {:.3} [MB/s]",
                self.chain.tip_hash(),
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
        let txnums = self.store.scan_by_script_hash(script_hash, from)?;
        Ok(txnums
            .into_iter()
            // chain and store must be in sync
            .map(|txnum| self.chain.find_by_txnum(txnum).expect("invalid txnum")))
    }

    #[allow(dead_code)]
    fn locations_by_txid(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<impl Iterator<Item = Location<'_>>, Error> {
        let txnums = self.store.scan_by_txid(txid)?;
        Ok(txnums
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
            .get_block_part(location.indexed_header.hash(), pos)?)
    }

    fn chain(&self) -> &Chain {
        &self.chain
    }
}

pub struct Cache {
    db: rusqlite::Connection,
}

impl Cache {
    pub fn open(db: rusqlite::Connection) -> Result<Self, Error> {
        // must be explicitly set outside a transaction - otherwise foreign keys constraints are ignored :(
        // https://www.sqlite.org/pragma.html#pragma_foreign_keys
        db.execute("PRAGMA foreign_keys = ON", ())?;
        let c = Cache { db };
        c.run("create", || c.create_tables())?;
        Ok(c)
    }

    fn run<T: Debug>(&self, op: &str, f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let start = std::time::Instant::now();
        self.db.execute("BEGIN", ())?;
        let res = match f() {
            Ok(v) => {
                self.db.execute("COMMIT", ())?;
                Ok(v)
            }
            Err(e) => {
                self.db.execute("ROLLBACK", ())?;
                Err(e)
            }
        };
        debug!("DB {} took {:?}, result={:?}", op, start.elapsed(), res);
        res
    }

    fn create_tables(&self) -> Result<(), Error> {
        // Split by ';' and drop empty entries
        let statements = include_str!("schema.sql")
            .split(";")
            .map(str::trim)
            .filter(|s| !str::is_empty(s));
        for s in statements {
            self.db.execute(s, ())?;
        }
        Ok(())
    }

    /// Synchornize index with current bitcoind state.
    /// Return `true` iff the chain tip has been updated.
    pub fn sync(&self, index: &IndexedChain, tip: &mut BlockHash) -> Result<bool, Error> {
        self.run("sync", || {
            self.drop_stale_blocks(&index.chain)?;
            let new_tip = index.chain.tip_hash();
            if *tip == new_tip {
                return Ok(false);
            }
            let new_history = self.new_history(index)?;
            let new_locations: BTreeSet<_> = new_history.iter().map(|(_, loc)| loc).collect();
            let new_headers: BTreeSet<_> = new_locations
                .iter()
                .map(|&loc| (loc.height, loc.indexed_header))
                .collect();
            if !new_history.is_empty() {
                info!(
                    "adding {} history entries, {} transactions, {} headers to cache={:?}",
                    new_history.len(),
                    new_locations.len(),
                    new_headers.len(),
                    self.db.path().unwrap_or("")
                );
            }
            // Note: some headers/transactions can be false-positives:
            self.add_headers(new_headers.into_iter())?;
            self.add_transactions(new_locations.into_iter(), index)?;
            self.add_history(new_history.into_iter())?;
            *tip = new_tip;
            Ok(true)
        })
    }

    fn drop_stale_blocks(&self, chain: &Chain) -> Result<(), Error> {
        let mut select = self
            .db
            .prepare("SELECT block_hash, block_height FROM headers ORDER BY block_height DESC")?;
        let rows = select.query_map((), |row| {
            let hash = bitcoin::BlockHash::from_byte_array(row.get(0)?);
            let height: usize = row.get(1)?;
            Ok((hash, height))
        })?;
        let mut delete_from = None;
        for row in rows {
            let (hash, height) = row?;
            match chain.get_header(hash, height) {
                Ok(_header) => break,
                Err(err) => {
                    warn!("reorg detected: {}", err);
                    delete_from = Some(height);
                }
            }
        }
        if let Some(height) = delete_from {
            let mut delete = self
                .db
                .prepare("DELETE FROM headers WHERE block_height >= ?1")?;
            delete.execute([height])?;
        }
        Ok(())
    }

    fn new_history<'a>(
        &self,
        index: &'a IndexedChain,
    ) -> Result<BTreeSet<(ScriptHash, Location<'a>)>, Error> {
        let mut stmt = self.db.prepare("SELECT script_hash FROM watch")?;
        let results = stmt.query_map((), |row| Ok(ScriptHash::from_byte_array(row.get(0)?)))?;

        let mut history = BTreeSet::<(ScriptHash, Location<'a>)>::new();
        for res in results {
            let script_hash = res?;
            self.new_history_for_script_hash(&script_hash, index, &mut history)?;
        }
        Ok(history)
    }

    /// Query index for new transactions, starting from last indexed block in cache.
    fn new_history_for_script_hash<'a>(
        &self,
        script_hash: &ScriptHash,
        index: &'a IndexedChain,
        history: &mut BTreeSet<(ScriptHash, Location<'a>)>,
    ) -> Result<(), Error> {
        let chain = index.chain();
        let from = self
            .last_indexed_header(script_hash, chain)?
            .map_or(index::TxNum::default(), index::IndexedHeader::next_txnum);
        index
            .locations_by_scripthash(script_hash, from)?
            .for_each(|loc| {
                history.insert((*script_hash, loc));
            });
        Ok(())
    }

    fn add_headers<'a>(
        &self,
        entries: impl Iterator<Item = (usize, &'a index::IndexedHeader)>,
    ) -> Result<usize, Error> {
        let mut insert = self
            .db
            .prepare("INSERT OR IGNORE INTO headers VALUES (?1, ?2, ?3)")?;
        let mut rows = 0;
        for (height, header) in entries {
            rows += insert.execute((
                height,
                header.hash().as_byte_array(),
                serialize(header.header()),
            ))?;
        }
        Ok(rows)
    }

    fn add_transactions<'a>(
        &self,
        locations: impl Iterator<Item = &'a Location<'a>>,
        index: &IndexedChain,
    ) -> Result<usize, Error> {
        let mut insert = self
            .db
            .prepare("INSERT OR IGNORE INTO transactions VALUES (?1, ?2, ?3, ?4)")?;
        let mut rows = 0;
        for loc in locations {
            let tx_bytes = index.get_tx_bytes(loc).expect("missing tx bytes");
            let parsed = bsl::Transaction::parse(&tx_bytes).expect("invalid tx");
            let txid = Txid::from(parsed.parsed().txid()).to_byte_array();
            rows += insert.execute((loc.height, loc.offset, txid, tx_bytes))?;
        }
        Ok(rows)
    }

    fn add_history<'a>(
        &self,
        entries: impl Iterator<Item = (ScriptHash, Location<'a>)>,
    ) -> Result<usize, Error> {
        let mut insert = self
            .db
            .prepare("INSERT INTO history VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
        let mut rows = 0;
        for (script_hash, loc) in entries {
            let tx: bitcoin::Transaction = self.db.query_row(
                "SELECT tx_bytes FROM transactions WHERE block_height = ?1 AND block_offset = ?2",
                (loc.height, loc.offset),
                |row| {
                    let tx_bytes: Vec<u8> = row.get(0)?;
                    Ok(deserialize(&tx_bytes).expect("invalid tx"))
                },
            )?;
            // Add spending entries
            for (i, input) in tx.input.iter().enumerate() {
                let prevout = input.previous_output;
                // txid -> (height, offset)
                let result = self
                    .db
                    .query_row(
                        "SELECT block_height, block_offset FROM transactions WHERE tx_id = ?1",
                        [prevout.txid.as_byte_array()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .optional()?;
                let (height, offset): (usize, usize) = match result {
                    Some(v) => v,
                    None => continue,
                };
                // (script_hash, height, offset, `true`, index) -> amount
                let result: Option<i64> = self.db.query_row(
                    "SELECT amount FROM history WHERE script_hash = ?1 AND block_height = ?2 AND block_offset = ?3 AND is_output = TRUE AND index_ = ?4",
                    (script_hash.as_byte_array(), height, offset, prevout.vout),
                    |row| row.get(0)
                ).optional()?;
                // Skip if not found (e.g. an input spending another script_hash)
                if let Some(amount) = result {
                    assert!(amount > 0);
                    rows += insert.execute((
                        script_hash.as_byte_array(),
                        loc.height,
                        loc.offset,
                        false,
                        i,
                        -amount,
                    ))?;
                }
            }
            // Add funding entries
            for (i, output) in tx.output.iter().enumerate() {
                // Skip if funding another script_hash
                if script_hash == ScriptHash::new(&output.script_pubkey) {
                    rows += insert.execute((
                        script_hash.as_byte_array(),
                        loc.height,
                        loc.offset,
                        true,
                        i,
                        output.value.to_sat(),
                    ))?;
                }
            }
        }
        Ok(rows)
    }

    fn last_indexed_header<'a>(
        &self,
        script_hash: &ScriptHash,
        chain: &'a Chain,
    ) -> Result<Option<&'a index::IndexedHeader>, Error> {
        let mut stmt = self.db.prepare(
            r"
            SELECT block_hash, block_height
            FROM history INNER JOIN headers USING (block_height)
            WHERE script_hash = ?1
            ORDER BY block_height DESC
            LIMIT 1",
        )?;
        stmt.query_row([script_hash.as_byte_array()], |row| {
            let blockhash = bitcoin::BlockHash::from_byte_array(row.get(0)?);
            let height: usize = row.get(1)?;
            Ok((blockhash, height))
        })
        .optional()?
        .map(|(blockhash, height)| Ok(chain.get_header(blockhash, height)?))
        .transpose()
    }

    pub fn add(&self, addresses: impl IntoIterator<Item = bitcoin::Address>) -> Result<(), Error> {
        let mut insert = self
            .db
            .prepare("INSERT OR IGNORE INTO watch VALUES (?1, ?2, ?3)")?;
        let mut rows = 0;
        for addr in addresses {
            let script = addr.script_pubkey();
            let script_hash = ScriptHash::new(&script);
            rows += insert.execute((
                script_hash.as_byte_array(),
                script.as_bytes(),
                addr.to_string(),
            ))?;
        }
        if rows > 0 {
            info!("added {} new addresses to watch", rows);
        }
        Ok(())
    }

    pub fn db(&self) -> &rusqlite::Connection {
        &self.db
    }
}
