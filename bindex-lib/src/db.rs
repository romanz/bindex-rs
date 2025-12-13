use std::path::Path;

use crate::index::{self, TxBlockPosRow};

use log::*;

pub struct Store {
    db: rocksdb::DB,
    compacting: bool,
}

fn default_opts() -> rocksdb::Options {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_compaction_style(rocksdb::DBCompactionStyle::Level);
    opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
    opts.set_max_open_files(256);
    opts.set_keep_log_file_num(10);
    opts.set_disable_auto_compactions(true);

    let parallelism = std::thread::available_parallelism()
        .ok()
        .and_then(|v| u16::try_from(v.get()).ok())
        .unwrap_or(2)
        .clamp(1, 8);
    opts.increase_parallelism(parallelism.into());
    opts.set_max_subcompactions(parallelism.into());
    opts
}

const HEADERS_CF: &str = "headers";
const SCRIPT_HASH_CF: &str = "script_hash";
const TXPOS_CF: &str = "txpos";

const COLUMN_FAMILIES: &[&str] = &[HEADERS_CF, TXPOS_CF, SCRIPT_HASH_CF];

fn cf_descriptors(
    opts: &rocksdb::Options,
) -> impl IntoIterator<Item = rocksdb::ColumnFamilyDescriptor> + '_ {
    COLUMN_FAMILIES
        .iter()
        .map(|&name| rocksdb::ColumnFamilyDescriptor::new(name, opts.clone()))
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rocksdb::Error> {
        let opts = default_opts();
        let db = rocksdb::DB::open_cf_descriptors(&opts, path, cf_descriptors(&opts))?;

        let store = Self {
            db,
            compacting: false,
        };
        for &cf_name in COLUMN_FAMILIES {
            let cf = store.cf(cf_name);
            let metadata = store.db.get_column_family_metadata_cf(cf);
            info!(
                "CF {}: {} files, {:.6} MBs",
                cf_name,
                metadata.file_count,
                metadata.size as f64 / 1e6
            );
        }
        Ok(store)
    }

    fn cf(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("missing CF: {name}"))
    }

    pub fn write(&self, batches: &[index::Batch]) -> Result<(), rocksdb::Error> {
        if batches.is_empty() {
            return Ok(());
        }
        let mut write_batch = rocksdb::WriteBatch::default();

        let cf = self.cf(SCRIPT_HASH_CF);
        let mut script_hash_rows = vec![];
        for batch in batches {
            script_hash_rows.extend(batch.script_hash_rows.iter().map(index::Row::key));
        }
        script_hash_rows.sort_unstable();
        for row in script_hash_rows {
            write_batch.put_cf(cf, row, b"");
        }

        let cf = self.cf(TXPOS_CF);
        batches
            .iter()
            .flat_map(|batch| batch.txpos_rows.iter())
            .map(index::TxBlockPosRow::serialize)
            .for_each(|(k, v)| write_batch.put_cf(cf, k, v));

        let cf = self.cf(HEADERS_CF);
        for batch in batches {
            let (key, value) = batch.header.serialize();
            write_batch.put_cf(cf, key, value);
        }

        let opts = rocksdb::WriteOptions::default();
        self.db.write_opt(write_batch, &opts)?;
        Ok(())
    }

    pub fn delete(&self, batches: &[index::Batch]) -> Result<(), rocksdb::Error> {
        let mut write_batch = rocksdb::WriteBatch::default();
        let cf = self.cf(SCRIPT_HASH_CF);
        let mut script_hash_rows = vec![];
        for batch in batches {
            script_hash_rows.extend(batch.script_hash_rows.iter().map(index::Row::key));
        }
        // ScriptHashPrefixRow::key contains txnum, so it is safe to delete
        script_hash_rows.sort_unstable();
        for row in script_hash_rows {
            write_batch.delete_cf(cf, row);
        }

        let cf = self.cf(TXPOS_CF);
        batches
            .iter()
            .flat_map(|batch| batch.txpos_rows.iter())
            .map(index::TxBlockPosRow::serialize)
            .for_each(|(k, _v)| write_batch.delete_cf(cf, k));

        let cf = self.cf(HEADERS_CF);
        // index::Header key is next_txnum, so it is safe to delete
        for batch in batches {
            let (key, _value) = batch.header.serialize();
            write_batch.delete_cf(cf, key);
        }

        let opts = rocksdb::WriteOptions::default();
        self.db.write_opt(write_batch, &opts)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<(), rocksdb::Error> {
        let opts = rocksdb::FlushOptions::new();
        for cf in COLUMN_FAMILIES {
            self.db.flush_cf_opt(self.cf(cf), &opts)?;
        }
        Ok(())
    }

    pub fn start_compactions(&mut self) -> Result<(), rocksdb::Error> {
        if !self.compacting {
            const OPTION: (&str, &str) = ("disable_auto_compactions", "false");
            for &cf_name in COLUMN_FAMILIES {
                let cf = self.cf(cf_name);
                self.db.set_options_cf(cf, &[OPTION])?;
            }
            info!("started auto compactions");
            self.compacting = true;
        }
        Ok(())
    }

    /// Collect a list of `TxNum`s for specified `script_hash`.
    pub fn scan_by_script_hash(
        &self,
        script_hash: &index::ScriptHash,
        from: index::TxNum,
    ) -> Result<Vec<index::TxNum>, rocksdb::Error> {
        let cf = self.cf(SCRIPT_HASH_CF);
        let mut txnums = Vec::new();

        let hash_prefix = (*script_hash).into();
        let start = index::Row::new(hash_prefix, from);
        // Allow resuming iteration from a specified txnum (for incremental sync)
        let mode = rocksdb::IteratorMode::From(start.key(), rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(cf, mode) {
            let (key, _) = kv?;
            if !key.starts_with(hash_prefix.as_bytes()) {
                break;
            }
            let row = index::Row::from_bytes(key[..].try_into().unwrap());
            assert!(row.txnum() >= from);
            txnums.push(row.txnum());
        }
        Ok(txnums)
    }

    /// Lookup transaction position (offset & size) within its block.
    pub fn get_tx_block_pos(
        &self,
        txnum: index::TxNum,
    ) -> Result<index::TxBlockPos, rocksdb::Error> {
        let cf = self.cf(TXPOS_CF);

        let from_key = txnum.serialize();
        let mode = rocksdb::IteratorMode::From(&from_key, rocksdb::Direction::Forward);
        if let Some(kv) = self.db.iterator_cf(cf, mode).next() {
            let (key, value) = kv?;
            assert!(from_key[..] <= key[..]);
            let row = TxBlockPosRow::deserialize(&key, &value);
            return Ok(row.get_tx_block_pos(txnum));
        }
        panic!("Missing {:?}", txnum)
    }

    /// Load all headers from DB.
    pub fn headers(&self) -> Result<Vec<index::Header>, rocksdb::Error> {
        let cf = self.cf(HEADERS_CF);
        let mut result = vec![];
        for kv in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (key, value) = kv?;
            let row = index::Header::deserialize((
                key[..].try_into().unwrap(),
                value[..].try_into().unwrap(),
            ));
            result.push(row)
        }
        Ok(result)
    }
}
