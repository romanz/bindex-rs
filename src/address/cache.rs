use std::collections::{BTreeSet, HashSet};

use bitcoin::{hashes::Hash, ScriptBuf, Txid};
use bitcoin_slices::{bsl, Parse};
use log::*;
use rusqlite::OptionalExtension;

use crate::{address, Location, ScriptHash};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("rusqlite failed: {0}")]
    DB(#[from] rusqlite::Error),

    #[error("address index failed: {0}")]
    Index(#[from] address::Error),
}

pub struct Cache {
    db: rusqlite::Connection,
}

impl Cache {
    pub fn open(db: rusqlite::Connection) -> Result<Self, Error> {
        let c = Cache { db };
        c.run(|| c.create_tables())?;
        Ok(c)
    }

    fn run<T>(&self, f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.db.execute("BEGIN", ())?;
        match f() {
            Ok(v) => {
                self.db.execute("COMMIT", ())?;
                Ok(v)
            }
            Err(e) => {
                self.db.execute("ROLLBACK", ())?;
                Err(e)
            }
        }
    }

    fn create_tables(&self) -> Result<(), Error> {
        self.db.execute(
            r"
            CREATE TABLE IF NOT EXISTS history (
                script_hash BLOB NOT NULL,
                block_hash BLOB NOT NULL,
                block_offset INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                PRIMARY KEY (script_hash, block_hash, block_offset)
            ) WITHOUT ROWID",
            (),
        )?;
        self.db.execute(
            r"
            CREATE TABLE IF NOT EXISTS transactions (
                block_hash BLOB NOT NULL,
                block_offset INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                tx_id BLOB,
                tx_bytes BLOB,
                PRIMARY KEY (block_hash, block_offset)
            ) WITHOUT ROWID",
            (),
        )?;
        Ok(())
    }

    pub fn sync(&self, scripts: &HashSet<ScriptBuf>, index: &address::Index) -> Result<(), Error> {
        self.run(|| {
            let mut new_locations = BTreeSet::new();
            let mut entries = 0;
            for script in scripts {
                let script_hash = ScriptHash::new(script);
                entries += self.sync_history(&script_hash, index, &mut new_locations)?;
            }
            let transactions = self.sync_transactions(&new_locations, index)?;
            if entries > 0 || transactions > 0 {
                info!(
                    "added {} history entries, {} transactions to cache={:?}",
                    entries,
                    transactions,
                    self.db.path().unwrap_or("")
                );
            }
            Ok(())
        })
    }

    fn sync_history<'a>(
        &self,
        script_hash: &crate::ScriptHash,
        index: &'a address::Index,
        new_locations: &mut BTreeSet<Location<'a>>,
    ) -> Result<usize, Error> {
        let mut stmt = self
            .db
            .prepare("INSERT OR IGNORE INTO history VALUES (?1, ?2, ?3, ?4)")?; // TODO remove 'OR IGNORE'

        let chain = index.chain();
        let from = match self.latest_location(script_hash, chain)? {
            Some(loc) => loc.indexed_header.next_txpos(),
            None => Default::default(),
        };
        index
            .find_positions(script_hash, from)?
            .into_iter()
            .map(|txpos| {
                let loc = chain.find_by_txpos(&txpos).expect("TODO reorg");
                let block_hash = loc.indexed_header.hash();
                let inserted = stmt.execute((
                    script_hash.as_byte_array(),
                    block_hash.as_byte_array(),
                    loc.offset,
                    loc.height,
                ))?;
                if inserted > 0 {
                    new_locations.insert(loc);
                }
                Ok(inserted)
            })
            .sum()
    }

    fn sync_transactions(
        &self,
        locations: &BTreeSet<Location>,
        index: &address::Index,
    ) -> Result<usize, Error> {
        let mut insert = self.db.prepare(
            r"
            INSERT OR IGNORE INTO transactions(block_hash, block_offset, block_height)
            VALUES (?1, ?2, ?3)",
        )?;
        let mut update = self.db.prepare(
            r"
                UPDATE transactions SET tx_bytes = ?3, tx_id = ?4
                WHERE block_hash = ?1 AND block_offset = ?2",
        )?;
        let mut rows = 0;
        for loc in locations {
            let block_hash = loc.indexed_header.hash();
            let inserted = insert.execute((block_hash.as_byte_array(), loc.offset, loc.height))?;
            if inserted > 0 {
                // fetch transaction bytes only if needed
                let tx_bytes = index.get_tx_bytes(loc).expect("missing tx bytes");
                let parsed = bsl::Transaction::parse(&tx_bytes).expect("invalid tx");
                let txid = Txid::from(parsed.parsed().txid());
                update.execute((
                    block_hash.as_byte_array(),
                    loc.offset,
                    tx_bytes,
                    txid.as_byte_array(),
                ))?;
                rows += inserted;
            }
        }
        Ok(rows)
    }

    fn latest_location<'a>(
        &'a self,
        script_hash: &crate::ScriptHash,
        chain: &'a crate::Chain,
    ) -> Result<Option<Location<'a>>, Error> {
        let mut stmt = self.db.prepare(
            r"
            SELECT block_hash, block_height, block_offset
            FROM history
            WHERE script_hash = ?1
            ORDER BY block_height DESC
            LIMIT 1",
        )?;
        Ok(stmt
            .query_row([script_hash.as_byte_array()], |row| {
                let blockhash = bitcoin::BlockHash::from_byte_array(row.get(0)?);
                let height: usize = row.get(1)?;
                let offset: u64 = row.get(2)?;

                let header = chain.get_by_height(height).expect("TODO reorg");
                assert_eq!(blockhash, header.hash(), "TODO reorg");

                Ok(Location {
                    height,
                    offset,
                    indexed_header: header,
                })
            })
            .optional()?)
    }

    pub fn db(&self) -> &rusqlite::Connection {
        &self.db
    }
}
