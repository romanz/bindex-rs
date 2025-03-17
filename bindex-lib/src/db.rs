use std::path::Path;

use crate::index;

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

const COLUMN_FAMILIES: &[&str] = &[HEADERS_CF, SCRIPT_HASH_CF];

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
            .unwrap_or_else(|| panic!("missing CF: {}", name))
    }

    pub fn write(&self, batches: &[index::Batch]) -> Result<(), rocksdb::Error> {
        let mut write_batch = rocksdb::WriteBatch::default();
        let cf = self.cf(SCRIPT_HASH_CF);
        let mut script_hash_rows = vec![];
        for batch in batches {
            script_hash_rows.extend(
                batch
                    .script_hash_rows
                    .iter()
                    .map(index::ScriptHashPrefixRow::key),
            );
        }
        script_hash_rows.sort_unstable();
        for row in script_hash_rows {
            write_batch.put_cf(cf, row, b"");
        }

        let cf = self.cf(HEADERS_CF);
        for batch in batches {
            let (key, value) = batch.header.serialize();
            write_batch.put_cf(cf, key, value);
        }

        let mut opts = rocksdb::WriteOptions::default();
        opts.disable_wal(false);
        self.db.write_opt(write_batch, &opts)?;
        Ok(())
    }

    pub fn delete(&self, batches: &[index::Batch]) -> Result<(), rocksdb::Error> {
        let mut write_batch = rocksdb::WriteBatch::default();
        let cf = self.cf(SCRIPT_HASH_CF);
        let mut script_hash_rows = vec![];
        for batch in batches {
            script_hash_rows.extend(
                batch
                    .script_hash_rows
                    .iter()
                    .map(index::ScriptHashPrefixRow::key),
            );
        }
        // ScriptHashPrefixRow::key contains txpos, so it is safe to delete
        script_hash_rows.sort_unstable();
        for row in script_hash_rows {
            write_batch.delete_cf(cf, row);
        }

        let cf = self.cf(HEADERS_CF);
        // index::Header key is next_txpos, so it is safe to delete
        for batch in batches {
            let (key, _value) = batch.header.serialize();
            write_batch.delete_cf(cf, key);
        }

        let mut opts = rocksdb::WriteOptions::default();
        opts.disable_wal(true);
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

    pub fn scan(
        &self,
        script_hash: &index::ScriptHash,
        from: index::TxPos,
    ) -> Result<impl Iterator<Item = index::TxPos>, rocksdb::Error> {
        let cf = self.cf(SCRIPT_HASH_CF);
        let mut positions = Vec::new();

        let prefix = index::ScriptHashPrefix::new(script_hash);
        let start = index::ScriptHashPrefixRow::new(prefix, from);
        let mode = rocksdb::IteratorMode::From(start.key(), rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(cf, mode) {
            let (key, _) = kv?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            let row = index::ScriptHashPrefixRow::from_bytes(key[..].try_into().unwrap());
            assert!(row.txpos() >= from);
            positions.push(row.txpos());
        }
        Ok(positions.into_iter())
    }

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
