use std::fs::{self, File};
use std::path::Path;

use crate::index::{self, Prefix, TxBlockPosRow, TxNum};

use cdb64::{Cdb, CdbHash, CdbWriter};
use log::*;
use rust_rocksdb as rocksdb;

/// Key-value database
pub struct DB {
    db: rocksdb::DB,
    compacting: bool,
    cdb_txid: Option<Cdb<File, CdbHash>>,
    cdb_script_hash: Option<Cdb<File, CdbHash>>,
    cdb_finalized_txnum: Option<TxNum>,
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
const TXID_CF: &str = "txid";

const COLUMN_FAMILIES: &[&str] = &[HEADERS_CF, TXPOS_CF, TXID_CF, SCRIPT_HASH_CF];

/// Collect all txnums for `prefix` from RocksDB iterator (advancing past them),
/// keeping only those <= `max_txnum`. Returns the txnums as one concatenated vector.
fn collect_rdb_prefix(
    rdb_iter: &mut rocksdb::DBRawIterator<'_>,
    prefix: Prefix,
    max_txnum: TxNum,
) -> Vec<u8> {
    let prefix_bytes = prefix.as_bytes();
    let mut txnums_buf = Vec::new();
    loop {
        let (key_prefix, row_txnum) = match rdb_iter.key() {
            Some(k) if k.len() == index::HashPrefixRow::LEN => {
                let kp: [u8; Prefix::LEN] = k[..Prefix::LEN].try_into().unwrap();
                let txnum: [u8; TxNum::LEN] = k[Prefix::LEN..].try_into().unwrap();
                (kp, txnum)
            }
            Some(_) => break,
            None => {
                rdb_iter.status().expect("RocksDB iterator error");
                break;
            }
        };
        if key_prefix != prefix_bytes {
            break;
        }
        if TxNum::deserialize(row_txnum) <= max_txnum {
            txnums_buf.extend_from_slice(&row_txnum);
        }
        rdb_iter.next();
    }
    txnums_buf
}

fn cf_descriptors(
    opts: &rocksdb::Options,
) -> impl IntoIterator<Item = rocksdb::ColumnFamilyDescriptor> + '_ {
    COLUMN_FAMILIES
        .iter()
        .map(|&name| rocksdb::ColumnFamilyDescriptor::new(name, opts.clone()))
}

/// Find the highest txnum for which txid and script_hash CDB files both exist.
pub fn find_highest_finalized_cdb_txnum(cdb_path: &Path) -> Option<TxNum> {
    let entries = fs::read_dir(cdb_path).ok()?;
    let mut max_txnum: Option<TxNum> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str())?;
        let suffix = name.strip_prefix("txid")?.strip_suffix(".cdb")?;
        let n: u32 = suffix.parse().ok()?;
        let txnum = TxNum::from_u32(n);
        let script_hash_path = cdb_path.join(format!("script_hash{n}.cdb"));
        if script_hash_path.is_file() && max_txnum.is_none_or(|m| txnum > m) {
            max_txnum = Some(txnum);
        }
    }
    max_txnum
}

impl DB {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rocksdb::Error> {
        let opts = default_opts();
        let db = rocksdb::DB::open_cf_descriptors(&opts, path, cf_descriptors(&opts))?;

        let store = Self {
            db,
            compacting: false,
            cdb_txid: None,
            cdb_script_hash: None,
            cdb_finalized_txnum: None,
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

    /// Open CDB files for the given path and max txnum.
    pub fn open_cdb(&mut self, cdb_path: &Path, max_txnum: TxNum) -> Result<(), String> {
        let n = max_txnum.to_string();
        let txid_path = cdb_path.join(format!("txid{n}.cdb"));
        let script_hash_path = cdb_path.join(format!("script_hash{n}.cdb"));

        self.cdb_txid = Some(
            Cdb::<File, CdbHash>::open(&txid_path)
                .map_err(|e| format!("failed to open txid CDB at {txid_path:?}: {e}"))?,
        );
        self.cdb_script_hash =
            Some(Cdb::<File, CdbHash>::open(&script_hash_path).map_err(|e| {
                format!("failed to open script_hash CDB at {script_hash_path:?}: {e}")
            })?);
        self.cdb_finalized_txnum = Some(max_txnum);
        info!("CDB loaded");
        Ok(())
    }

    fn cf(&self, name: &str) -> &rocksdb::ColumnFamily {
        self.db
            .cf_handle(name)
            .unwrap_or_else(|| panic!("missing CF: {name}"))
    }

    fn apply_batch<F>(&self, f: F, batches: &[index::Batch]) -> Result<(), rocksdb::Error>
    where
        F: Fn(&mut rocksdb::WriteBatch, &rocksdb::ColumnFamily, &[u8], &[u8]),
    {
        if batches.is_empty() {
            return Ok(());
        }
        let mut write_batch = rocksdb::WriteBatch::default();

        // key = scripthash prefix || matching txnum, value = b""
        let cf = self.cf(SCRIPT_HASH_CF);
        let mut scripthash_rows = vec![];
        for batch in batches {
            scripthash_rows.extend(
                batch
                    .scripthash_rows
                    .iter()
                    .filter(|r| self.cdb_finalized_txnum.is_none_or(|max| r.txnum() > max))
                    .map(index::HashPrefixRow::key),
            );
        }
        scripthash_rows.sort_unstable();
        for row in scripthash_rows {
            f(&mut write_batch, cf, row, b"");
        }

        // key = txid prefix || matching txnum, value = b""
        let cf = self.cf(TXID_CF);
        let mut txid_rows = vec![];
        for batch in batches {
            txid_rows.extend(
                batch
                    .txid_rows
                    .iter()
                    .filter(|r| self.cdb_finalized_txnum.is_none_or(|max| r.txnum() > max))
                    .map(index::HashPrefixRow::key),
            );
        }
        txid_rows.sort_unstable();
        for row in txid_rows {
            f(&mut write_batch, cf, row, b"");
        }

        // key = last_txnum, value = chunk of offsets
        let cf = self.cf(TXPOS_CF);
        // Rows are sorted by `txnum`.
        batches
            .iter()
            .flat_map(|batch| batch.txpos_rows.iter())
            .map(index::TxBlockPosRow::serialize)
            .for_each(|(k, v)| f(&mut write_batch, cf, &k, &v));

        // key = next_txnum, value = blockhash || blockheader
        let cf = self.cf(HEADERS_CF);
        for batch in batches {
            let (key, value) = batch.header.serialize();
            f(&mut write_batch, cf, &key, &value);
        }

        let opts = rocksdb::WriteOptions::default();
        self.db.write_opt(write_batch, &opts)?;
        Ok(())
    }

    pub fn write(&self, batches: &[index::Batch]) -> Result<(), rocksdb::Error> {
        self.apply_batch(|wb, cf, k, v| wb.put_cf(cf, k, v), batches)
    }

    pub fn delete(&self, batches: &[index::Batch]) -> Result<(), rocksdb::Error> {
        // All keys contains txnum, so they are safe to delete in case of a reorg.
        self.apply_batch(|wb, cf, k, _v| wb.delete_cf(cf, k), batches)
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

    fn txnums_from_cdb_prefix(cdb: &Cdb<File, CdbHash>, prefix: &[u8], from: TxNum) -> Vec<TxNum> {
        let value = cdb
            .get(prefix)
            .expect("CDB read failed")
            .unwrap_or_default();
        value
            .chunks_exact(TxNum::LEN)
            .map(|chunk| TxNum::deserialize(chunk.try_into().unwrap()))
            .filter(|&txnum| txnum >= from)
            .collect()
    }

    /// Collect a list of `TxNum`s for specified `script_hash`.
    pub fn scan_by_script_hash(
        &self,
        script_hash: &index::ScriptHash,
        from: TxNum,
    ) -> Result<Vec<TxNum>, rocksdb::Error> {
        let mut txnums = Vec::new();

        let hash_prefix: Prefix = (*script_hash).into();
        // Allow resuming iteration from a specified txnum (for incremental sync)
        let prefix_bytes = hash_prefix.as_bytes();

        if let (Some(ref cdb), Some(max_txnum)) = (&self.cdb_script_hash, self.cdb_finalized_txnum)
        {
            if from <= max_txnum {
                txnums.extend(Self::txnums_from_cdb_prefix(cdb, prefix_bytes, from));
            }
        }
        let start = index::HashPrefixRow::new(hash_prefix, from);
        let cf = self.cf(SCRIPT_HASH_CF);
        let mode = rocksdb::IteratorMode::From(start.key(), rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(cf, mode) {
            let (key, _) = kv?;
            if !key.starts_with(prefix_bytes) {
                break;
            }
            let row_txnum = index::HashPrefixRow::from_bytes(key[..].try_into().unwrap()).txnum();
            assert!(row_txnum >= from);
            // Safety check if the RustDB is not clean and stil contains values that appear in the CDB.
            if self.cdb_finalized_txnum.is_none_or(|max| row_txnum > max) {
                txnums.push(row_txnum);
            }
        }
        Ok(txnums)
    }

    /// Collect a list of `TxNum`s for specified `txid`.
    #[allow(dead_code)]
    pub fn scan_by_txid(&self, txid: &bitcoin::Txid) -> Result<Vec<TxNum>, rocksdb::Error> {
        let mut txnums = Vec::new();

        let hash_prefix: Prefix = (*txid.as_raw_hash()).into();
        let prefix_bytes = hash_prefix.as_bytes();

        if let (Some(ref cdb), Some(_)) = (&self.cdb_txid, self.cdb_finalized_txnum) {
            txnums.extend(Self::txnums_from_cdb_prefix(
                cdb,
                prefix_bytes,
                TxNum::default(),
            ));
        }
        let cf = self.cf(TXID_CF);
        let start = index::HashPrefixRow::new(hash_prefix, TxNum::default());
        let mode = rocksdb::IteratorMode::From(start.key(), rocksdb::Direction::Forward);
        for kv in self.db.iterator_cf(cf, mode) {
            let (key, _) = kv?;
            if !key.starts_with(prefix_bytes) {
                break;
            }
            let row_txnum = index::HashPrefixRow::from_bytes(key[..].try_into().unwrap()).txnum();
            // Safety check if the RustDB is not clean and stil contains values that appear in the CDB.
            if self.cdb_finalized_txnum.is_none_or(|max| row_txnum > max) {
                txnums.push(row_txnum);
            }
        }
        Ok(txnums)
    }

    /// Lookup transaction position (offset & size) within its block.
    pub fn get_tx_block_pos(&self, txnum: TxNum) -> Result<index::TxBlockPos, rocksdb::Error> {
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

    /// Scan all rows in `cf`, group by 8-byte prefix, keep only txnums <= `max_txnum`,
    /// and write one CDB entry per prefix (value = concatenated big-endian u32 txnums).
    fn build_cdb_for_cf(
        db: &rocksdb::DB,
        cf: &rocksdb::ColumnFamily,
        path: &Path,
        max_txnum: TxNum,
        existing_cdb: Option<&Cdb<File, CdbHash>>,
    ) -> Result<(), String> {
        let mut writer = CdbWriter::<File, CdbHash>::create(path)
            .map_err(|e| format!("failed to create CDB writer at {path:?}: {e}"))?;

        let mut opts = rocksdb::ReadOptions::default();
        opts.fill_cache(false);
        let mut rdb_iter = db.raw_iterator_cf_opt(cf, opts);
        rdb_iter.seek_to_first();

        // Collect existing CDB entries for merge (CDB stores prefix -> concatenated txnums).
        // CDB's records section is in the order they were added. Since we build CDB by
        // scanning RocksDB in sorted key order, the CDB iterator yields prefixes in sorted order.
        let mut cdb_iter = existing_cdb.map(|c| {
            c.iter()
                .map(|r| {
                    let (k, v) = r.expect("CDB read failed");
                    let arr: [u8; Prefix::LEN] =
                        k[..Prefix::LEN].try_into().expect("invalid CDB key");
                    let prefix = Prefix::from(arr);
                    (prefix, v)
                })
                .peekable()
        });

        loop {
            let rdb_prefix: Option<Prefix> = rdb_iter.key().map(|k| {
                debug_assert_eq!(k.len(), index::HashPrefixRow::LEN);
                let arr: [u8; Prefix::LEN] = k[..Prefix::LEN].try_into().unwrap();
                Prefix::from(arr)
            });
            let cdb_prefix: Option<Prefix> =
                cdb_iter.as_mut().and_then(|it| it.peek().map(|(p, _)| *p));

            match (rdb_prefix, cdb_prefix) {
                (None, None) => break,
                (None, Some(_)) => {
                    let (prefix, cdb_val) = cdb_iter.as_mut().unwrap().next().unwrap();
                    writer
                        .put(prefix.as_bytes(), &cdb_val)
                        .map_err(|e| format!("CDB put failed: {e}"))?;
                }
                (Some(rp), None) => {
                    let txnums_buf = collect_rdb_prefix(&mut rdb_iter, rp, max_txnum);
                    if !txnums_buf.is_empty() {
                        writer
                            .put(rp.as_bytes(), &txnums_buf)
                            .map_err(|e| format!("CDB put failed: {e}"))?;
                    }
                }
                (Some(rp), Some(cp)) => match rp.cmp(&cp) {
                    std::cmp::Ordering::Less => {
                        let heights_buf = collect_rdb_prefix(&mut rdb_iter, rp, max_txnum);
                        if !heights_buf.is_empty() {
                            writer
                                .put(rp.as_bytes(), &heights_buf)
                                .map_err(|e| format!("CDB put failed: {e}"))?;
                        }
                    }
                    std::cmp::Ordering::Greater => {
                        let (prefix, cdb_val) = cdb_iter.as_mut().unwrap().next().unwrap();
                        writer
                            .put(prefix.as_bytes(), &cdb_val)
                            .map_err(|e| format!("CDB put failed: {e}"))?;
                    }
                    std::cmp::Ordering::Equal => {
                        // Prefix in both: start with the CDB value, then append only RDB
                        // heights not already present in the CDB (deduplication needed because
                        // RocksDB still holds all heights until cleanup is implemented).
                        let (_, cdb_val) = cdb_iter.as_mut().unwrap().next().unwrap();
                        let cdb_txnums: std::collections::HashSet<[u8; TxNum::LEN]> = cdb_val
                            .chunks_exact(TxNum::LEN)
                            .map(|c| c.try_into().unwrap())
                            .collect();
                        let mut txnums_buf = cdb_val;
                        for chunk in collect_rdb_prefix(&mut rdb_iter, rp, max_txnum)
                            .chunks_exact(TxNum::LEN)
                        {
                            if !cdb_txnums.contains(chunk) {
                                txnums_buf.extend_from_slice(chunk);
                            }
                        }
                        if !txnums_buf.is_empty() {
                            writer
                                .put(rp.as_bytes(), &txnums_buf)
                                .map_err(|e| format!("CDB put failed: {e}"))?;
                        }
                    }
                },
            }
        }

        writer
            .finalize()
            .map_err(|e| format!("failed to finalize CDB at {path:?}: {e}"))?;
        Ok(())
    }

    /// Build CDB files for txid and script_hash, covering txnums up to and including `max_txnum`.
    /// Writes to .tmp files, renames to .cdb, opens the new CDBs, and deletes old CDB files.
    pub fn synchronize_cdb(&mut self, cdb_path: &Path, max_txnum: TxNum) -> Result<(), String> {
        let old_txnum = self.cdb_finalized_txnum;
        if let Some(current) = old_txnum {
            if current > max_txnum {
                return Err("cdb_max_txnum cannot be decreased".into());
            }
            if current == max_txnum {
                return Ok(());
            }
        }

        let n = max_txnum.to_string();
        let txid_tmp_path = cdb_path.join(format!("txid{n}.cdb.tmp"));
        let script_hash_tmp_path = cdb_path.join(format!("script_hash{n}.cdb.tmp"));

        info!("building CDB for txnums up to {} at {:?}", n, cdb_path);

        Self::build_cdb_for_cf(
            &self.db,
            self.cf(TXID_CF),
            &txid_tmp_path,
            max_txnum,
            self.cdb_txid.as_ref(),
        )
        .map_err(|e| format!("failed to build txid CDB: {e}"))?;
        Self::build_cdb_for_cf(
            &self.db,
            self.cf(SCRIPT_HASH_CF),
            &script_hash_tmp_path,
            max_txnum,
            self.cdb_script_hash.as_ref(),
        )
        .map_err(|e| format!("failed to build script_hash CDB: {e}"))?;

        let txid_path = cdb_path.join(format!("txid{n}.cdb"));
        let script_hash_path = cdb_path.join(format!("script_hash{n}.cdb"));
        std::fs::rename(&txid_tmp_path, &txid_path)
            .map_err(|e| format!("failed to rename {txid_tmp_path:?} to {txid_path:?}: {e}"))?;
        std::fs::rename(&script_hash_tmp_path, &script_hash_path).map_err(|e| {
            format!("failed to rename {script_hash_tmp_path:?} to {script_hash_path:?}: {e}")
        })?;

        self.open_cdb(cdb_path, max_txnum)?;
        info!("CDB finalized at txnum {}", n);

        if let Some(old) = old_txnum {
            let old_n = old.to_string();
            let _ = std::fs::remove_file(cdb_path.join(format!("txid{old_n}.cdb")));
            let _ = std::fs::remove_file(cdb_path.join(format!("script_hash{old_n}.cdb")));
            info!("deleted old CDB files for txnum {}", old_n);
        }

        Ok(())
    }

    /// Load all headers from DB.
    pub fn headers(&self) -> Result<Vec<index::IndexedHeader>, rocksdb::Error> {
        let cf = self.cf(HEADERS_CF);
        let mut result = Vec::with_capacity(1_000_000);
        for kv in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (key, value) = kv?;
            let row = index::IndexedHeader::deserialize((
                key[..].try_into().unwrap(),
                value[..].try_into().unwrap(),
            ));
            result.push(row)
        }
        Ok(result)
    }
}
