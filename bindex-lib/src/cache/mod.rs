use std::{collections::BTreeSet, fmt::Debug};

use bitcoin::{
    consensus::{deserialize, serialize},
    hashes::Hash,
    Txid,
};
use bitcoin_slices::{bsl, Parse};
use log::*;
use rusqlite::OptionalExtension;

use crate::{
    index::{self, ScriptHash},
    store::{self, IndexedChain},
    Location,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rusqlite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("invalid address: {0}")]
    Address(#[from] bitcoin::address::ParseError),

    #[error("store error: {0}")]
    Index(#[from] store::Error),
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
    pub fn sync(&self, chain: &IndexedChain) -> Result<(), Error> {
        self.run("sync", || {
            // Colect new transactions' locations (grouped per scripthash, sorted by txnum)
            // Also, drop stale blocks from cache.
            let new_history = self.sync_history(chain)?;
            // De-duplicate new transactions' locations (sorted by txnum)
            let new_locations: BTreeSet<_> = new_history
                .iter()
                .flat_map(|(_, locations)| locations.iter())
                .collect();
            // De-duplicate new block headers (sorted by height)
            let new_headers: BTreeSet<_> = new_locations
                .iter()
                .map(|&loc| (loc.block_height, loc.indexed_header))
                .collect();
            if !new_locations.is_empty() {
                info!(
                    "adding {} history entries, {} transactions, {} headers to cache={:?}",
                    new_history.len(),
                    new_locations.len(),
                    new_headers.len(),
                    self.db.path().unwrap_or("")
                );
            }
            // Some headers/transactions can be false-positives (since we don't store the full scripthash)
            self.add_headers(new_headers.into_iter())?;
            self.add_transactions(new_locations.into_iter(), chain)?;
            // Keep only history entries related to the watched scripthashes
            self.add_history(new_history.into_iter())?;
            Ok(())
        })
    }

    // Make sure the latest header is part of the active chain.
    fn drop_stale_blocks(&self, chain: &IndexedChain) -> Result<(), Error> {
        let mut select = self
            .db
            .prepare("SELECT block_hash, block_height FROM headers ORDER BY block_height DESC")?;
        let rows_iter = select.query_map((), |row| {
            let hash = bitcoin::BlockHash::from_byte_array(row.get(0)?);
            let height: usize = row.get(1)?;
            Ok((hash, height))
        })?;
        let mut delete_from = None;
        // Find the first non-stale block (scanning backwards from tip):
        for row in rows_iter {
            let (hash, height) = row?;
            match chain.check_header(hash, height) {
                Ok(_header) => break,
                Err(err) => {
                    warn!("reorg detected: {}", err);
                    delete_from = Some(height);
                    // continue (in case more blocks are stale)
                }
            }
        }
        if let Some(height) = delete_from {
            // Drop stale blocks, transactions and history entries (due to `ON DELETE CASCADE`)
            let mut delete = self
                .db
                .prepare("DELETE FROM headers WHERE block_height >= ?1")?;
            delete.execute([height])?;
        }
        Ok(())
    }

    /// Query index for new transactions, starting from last indexed block in cache.
    /// Also drop stale blocks from cache - handling chain reorgs.
    fn sync_history<'a>(
        &self,
        chain: &'a IndexedChain,
    ) -> Result<Vec<(ScriptHash, BTreeSet<Location<'a>>)>, Error> {
        self.drop_stale_blocks(chain)?;
        // Collect latest block height & its corresponding blockhash for each scripthash.
        let mut stmt = self.db.prepare(
            r"
            WITH max_heights AS (
                SELECT script_hash, max(block_height) AS `block_height`
                FROM watch LEFT JOIN history USING (script_hash)
                GROUP BY 1
            )
            SELECT script_hash, block_height, block_hash
            FROM max_heights LEFT JOIN headers USING (block_height)",
        )?;
        let rows_iter = stmt.query_map([], |row| {
            let script_hash = ScriptHash::from_byte_array(row.get(0)?);
            let block_height: Option<usize> = row.get(1)?;
            let latest_header = if let Some(height) = block_height {
                let block_hash = bitcoin::BlockHash::from_byte_array(row.get(2)?);
                let header = chain
                    .check_header(block_hash, height)
                    .expect("unexpected reorg");
                Some(header)
            } else {
                None
            };
            Ok((script_hash, latest_header))
        })?;
        // Collect new transactions' locations per scripthash (sorted by txnum)
        rows_iter
            .map(|row| {
                let (script_hash, latest_header) = row?;
                let locations = chain
                    .locations_by_scripthash(&script_hash, latest_header)?
                    .collect();
                Ok((script_hash, locations))
            })
            .collect::<Result<_, Error>>()
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
            rows += insert.execute((loc.block_height, loc.block_offset, txid, tx_bytes))?;
        }
        Ok(rows)
    }

    fn add_history<'a>(
        &self,
        entries: impl Iterator<Item = (ScriptHash, BTreeSet<Location<'a>>)>,
    ) -> Result<usize, Error> {
        let mut insert = self
            .db
            .prepare("INSERT INTO history VALUES (?1, ?2, ?3, ?4, ?5, ?6)")?;
        let mut rows = 0;
        for (script_hash, locations) in entries {
            for loc in locations {
                let tx: bitcoin::Transaction = self.db.query_row(
                    "SELECT tx_bytes FROM transactions WHERE block_height = ?1 AND block_offset = ?2",
                    (loc.block_height, loc.block_offset),
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
                    let result: Option<i64> = self
                        .db
                        .query_row(
                            r"
                        SELECT amount
                        FROM history
                        WHERE script_hash = ?1
                          AND block_height = ?2
                          AND block_offset = ?3
                          AND is_output = TRUE
                          AND index_ = ?4",
                            (script_hash.as_byte_array(), height, offset, prevout.vout),
                            |row| row.get(0),
                        )
                        .optional()?;
                    // Skip if not found (e.g. an input spending another script_hash)
                    if let Some(amount) = result {
                        assert!(amount > 0);
                        rows += insert.execute((
                            script_hash.as_byte_array(),
                            loc.block_height,
                            loc.block_offset,
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
                            loc.block_height,
                            loc.block_offset,
                            true,
                            i,
                            output.value.to_sat(),
                        ))?;
                    }
                }
            }
        }
        Ok(rows)
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
