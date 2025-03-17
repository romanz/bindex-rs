use std::{collections::BTreeSet, fmt::Debug};

use bitcoin::{consensus::serialize, hashes::Hash, Txid};
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
                PRIMARY KEY (block_height, block_offset)
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
                PRIMARY KEY (script_hash, block_height, block_offset)
                FOREIGN KEY (block_height, block_offset) REFERENCES transactions (block_height, block_offset) ON DELETE CASCADE
            ) WITHOUT ROWID",
            (),
        )?;
        self.db.execute(
            r"
            CREATE TABLE IF NOT EXISTS watch (
                script_hash BLOB NOT NULL,
                script_bytes BLOB NOT NULL,
                address TEXT NOT NULL,
                PRIMARY KEY (script_hash)
            ) WITHOUT ROWID",
            (),
        )?;
        Ok(())
    }

    pub fn sync(&self, index: &address::Index) -> Result<(), Error> {
        self.run("sync", || {
            self.drop_stale_blocks(&index.chain)?;
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

            self.sync_headers(new_headers.into_iter())?;
            self.sync_transactions(new_locations.into_iter(), index)?;
            self.sync_history(new_history.into_iter())?;
            Ok(())
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
            .map(index::Header::next_txpos)
            .unwrap_or_default();
        index.find_locations(script_hash, from)?.for_each(|loc| {
            history.insert((*script_hash, loc));
        });
        Ok(())
    }

    fn sync_headers<'a>(
        &self,
        entries: impl Iterator<Item = (usize, &'a index::Header)>,
    ) -> Result<usize, Error> {
        let mut insert = self.db.prepare("INSERT INTO headers VALUES (?1, ?2, ?3)")?;
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

    fn sync_transactions<'a>(
        &self,
        locations: impl Iterator<Item = &'a Location<'a>>,
        index: &address::Index,
    ) -> Result<usize, Error> {
        let mut insert = self.db.prepare(
            r"
            INSERT INTO transactions(block_height, block_offset, tx_bytes, tx_id)
            VALUES (?1, ?2, ?3, ?4)",
        )?;
        let mut rows = 0;
        for loc in locations {
            let tx_bytes = index.get_tx_bytes(loc).expect("missing tx bytes");
            let parsed = bsl::Transaction::parse(&tx_bytes).expect("invalid tx");
            let txid = Txid::from(parsed.parsed().txid()).to_byte_array();
            rows += insert.execute((loc.height, loc.offset, tx_bytes, txid))?;
        }
        Ok(rows)
    }

    fn sync_history<'a>(
        &self,
        entries: impl Iterator<Item = (ScriptHash, Location<'a>)>,
    ) -> Result<usize, Error> {
        let mut insert = self.db.prepare("INSERT INTO history VALUES (?1, ?2, ?3)")?;
        let mut rows = 0;
        for (script_hash, loc) in entries {
            rows += insert.execute((script_hash.as_byte_array(), loc.height, loc.offset))?;
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
