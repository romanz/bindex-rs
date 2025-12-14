use std::{collections::BTreeSet, fmt::Debug};

use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    BlockHash, Txid,
};
use bitcoin_slices::{bsl, Parse};
use log::*;
use rusqlite::OptionalExtension;

use crate::{
    address,
    chain::{self, Chain, Location},
    index::{self, ScriptHash},
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rusqlite failed: {0}")]
    DB(#[from] rusqlite::Error),

    #[error("address index failed: {0}")]
    Index(#[from] address::Error),

    #[error("parse failed: {0}")]
    Address(#[from] bitcoin::address::ParseError),

    #[error("block not found: {0}")]
    BlockNotFound(#[from] chain::Reorg),
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
        self.db.execute(
            r"
            CREATE TABLE IF NOT EXISTS headers (
                block_height INTEGER NOT NULL,
                block_hash BLOB NOT NULL,
                header_bytes BLOB NOT NULL,
                PRIMARY KEY (block_height),
                UNIQUE (block_hash)
            ) WITHOUT ROWID",
            (),
        )?;
        self.db.execute(
            r"
            CREATE TABLE IF NOT EXISTS transactions (
                block_height INTEGER NOT NULL,
                block_offset INTEGER NOT NULL,
                tx_id BLOB,
                tx_bytes BLOB,
                PRIMARY KEY (block_height, block_offset),
                UNIQUE (tx_id),
                FOREIGN KEY (block_height) REFERENCES headers (block_height) ON DELETE CASCADE
            ) WITHOUT ROWID",
            (),
        )?;
        self.db.execute(
            r"
            CREATE TABLE IF NOT EXISTS history (
                script_hash BLOB NOT NULL REFERENCES watch (script_hash) ON DELETE CASCADE,
                block_height INTEGER NOT NULL,
                block_offset INTEGER NOT NULL,
                is_output BOOLEAN NOT NULL,     -- is it funding the address or not (= spending from it)
                index_ INTEGER NOT NULL,        -- input/output index within a transaction
                amount INTEGER NOT NULL,        -- in Satoshis (positive=funding, negative=spending)
                PRIMARY KEY (script_hash, block_height, block_offset, is_output, index_)
                FOREIGN KEY (block_height, block_offset) REFERENCES transactions (block_height, block_offset) ON DELETE CASCADE
            ) WITHOUT ROWID",
            (),
        )?;
        self.db.execute(
            r"
            CREATE TABLE IF NOT EXISTS watch (
                script_hash BLOB NOT NULL,
                script_bytes BLOB,
                address TEXT,
                PRIMARY KEY (script_hash)
            ) WITHOUT ROWID",
            (),
        )?;
        Ok(())
    }

    /// Synchornize index with current bitcoind state.
    /// Return `true` iff the chain tip has been updated.
    pub fn sync(&self, index: &address::Index, tip: &mut BlockHash) -> Result<bool, Error> {
        self.run("sync", || {
            self.drop_stale_blocks(&index.chain)?;
            let new_tip = index.chain.tip_hash().unwrap_or_else(BlockHash::all_zeros);
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

    pub fn drop_stale_blocks(&self, chain: &Chain) -> Result<(), Error> {
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
        index: &'a address::Index,
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

    fn new_history_for_script_hash<'a>(
        &self,
        script_hash: &ScriptHash,
        index: &'a address::Index,
        history: &mut BTreeSet<(ScriptHash, Location<'a>)>,
    ) -> Result<(), Error> {
        let chain = index.chain();
        let from = self
            .last_indexed_header(script_hash, chain)?
            .map(index::Header::next_txnum)
            .unwrap_or_default();
        index
            .locations_by_scripthash(script_hash, from)?
            .for_each(|loc| {
                history.insert((*script_hash, loc));
            });
        Ok(())
    }

    fn add_headers<'a>(
        &self,
        entries: impl Iterator<Item = (usize, &'a index::Header)>,
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
        index: &address::Index,
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
    ) -> Result<Option<&'a index::Header>, Error> {
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
