use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    thread,
    time::Instant,
};

use bindex::{address, address::cache, Chain, Location};

use bitcoin::{consensus::deserialize, hashes::Hash, BlockHash, ScriptBuf, Txid};
use chrono::{TimeZone, Utc};
use clap::{Parser, ValueEnum};
use log::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(tabled::Tabled)]
struct Entry {
    txid: String,
    time: String,
    height: String,
    offset: String,
    delta: String,
    balance: String,
    bytes: String,
}

impl Entry {
    fn dots() -> Self {
        let s = "...";
        Self {
            txid: s.to_owned(),
            time: s.to_owned(),
            height: s.to_owned(),
            offset: s.to_owned(),
            delta: s.to_owned(),
            balance: s.to_owned(),
            bytes: s.to_owned(),
        }
    }
}

fn get_history(
    db: &rusqlite::Connection,
    scripts: &HashSet<ScriptBuf>,
    chain: &Chain,
) -> Result<Vec<Entry>> {
    let t = Instant::now();

    let mut stmt = db.prepare(
        r"
        SELECT block_hash, block_offset, block_height, tx_id, tx_bytes
        FROM transactions INNER JOIN headers USING (block_hash)
        ORDER BY block_height ASC, block_offset ASC",
    )?;
    let results = stmt.query_map([], |row| {
        let blockhash = BlockHash::from_byte_array(row.get(0)?);
        let offset: u64 = row.get(1)?;
        let height: usize = row.get(2)?;

        let location = Location {
            height,
            offset,
            indexed_header: chain.get_header(blockhash, height).expect("TODO reorg"),
        };

        let txid = Txid::from_byte_array(row.get(3)?);
        let tx_bytes: Vec<u8> = row.get(4)?;
        let tx: bitcoin::Transaction = deserialize(&tx_bytes).expect("bad tx bytes");
        assert_eq!(txid, tx.compute_txid());
        Ok((location, txid, tx_bytes, tx))
    })?;

    let mut unspent = HashMap::<bitcoin::OutPoint, bitcoin::Amount>::new();
    let mut balance = bitcoin::SignedAmount::ZERO;
    let mut byte_size = 0;

    let mut entries = vec![];
    for res in results {
        let (loc, txid, tx_bytes, tx) = res?;

        let mut delta = bitcoin::SignedAmount::ZERO;
        let mut skip_tx = true;
        for txi in tx.input {
            if let Some(spent) = unspent.remove(&txi.previous_output) {
                delta -= spent.to_signed().expect("spent overflow");
                skip_tx = false;
            }
        }
        for (n, txo) in tx.output.into_iter().enumerate() {
            if scripts.contains(txo.script_pubkey.as_script()) {
                delta += txo.value.to_signed().expect("txo.value overflow");
                unspent.insert(
                    bitcoin::OutPoint::new(txid, n.try_into().unwrap()),
                    txo.value,
                );
                skip_tx = false;
            }
        }
        if skip_tx {
            continue;
        }
        balance += delta;
        byte_size += tx_bytes.len();
        entries.push(Entry {
            txid: txid.to_string(),
            time: format!(
                "{}",
                Utc.timestamp_opt(loc.indexed_header.header().time.into(), 0)
                    .unwrap()
            ),
            height: loc.height.to_string(),
            offset: loc.offset.to_string(),
            delta: format!("{:+.8}", delta.to_btc()),
            balance: format!("{:.8}", balance.to_btc()),
            bytes: tx_bytes.len().to_string(),
        });
    }
    let dt = t.elapsed();
    info!(
        "{} address history: {} transactions, balance: {}, UTXOs: {}, total: {:.6} MB [{:?}]",
        scripts.len(),
        entries.len(),
        balance,
        unspent.len(),
        byte_size as f64 / 1e6,
        dt,
    );
    Ok(entries)
}

fn print_history(mut entries: Vec<Entry>, history_limit: usize) {
    if history_limit > 0 {
        let is_truncated = entries.len() > history_limit;
        entries.reverse();
        entries.truncate(history_limit);
        if is_truncated {
            entries.push(Entry::dots());
        }
        if entries.is_empty() {
            return;
        }
        let mut tbl = tabled::Table::new(entries);
        tbl.with(tabled::settings::Style::rounded());
        tbl.modify(
            tabled::settings::object::Rows::new(1..),
            tabled::settings::Alignment::right(),
        );
        if is_truncated {
            tbl.modify(
                tabled::settings::object::LastRow,
                tabled::settings::Alignment::center(),
            );
        }
        println!("{}", tbl);
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Network {
    Bitcoin,
    Testnet,
    Testnet4,
    Regtest,
    Signet,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Bitcoin address indexer
struct Args {
    #[arg(value_enum, short = 'n', long = "network", default_value_t = Network::Bitcoin)]
    network: Network,

    /// Limit on how many recent transactions to print
    #[arg(short = 'l', long = "limit", default_value_t = 100)]
    history_limit: usize,

    /// Text file, containing white-space separated addresses
    #[arg(short = 'a', long = "address-file")]
    address_file: Option<PathBuf>,

    /// SQLite3 database for storing address history and relevant transactions
    #[arg(short = 'c', long = "cache")]
    cache_file: Option<PathBuf>,
}

fn open_index(args: &Args) -> Result<address::Index> {
    let default_rpc_port = match args.network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Regtest => 18443,
        Network::Signet => 38332,
    };

    let default_index_dir = match args.network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };

    let url = format!("http://localhost:{}", default_rpc_port);
    let db_path = format!("db/{default_index_dir}");
    info!("index DB: {}, node URL: {}", db_path, url);

    Ok(address::Index::open(db_path, url)?)
}

fn collect_scripts(args: &Args) -> std::io::Result<HashSet<bitcoin::ScriptBuf>> {
    let addresses = args.address_file.as_ref().map_or_else(
        || Ok(String::new()),
        |path| {
            if path == Path::new("-") {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                return Ok(buf);
            }
            std::fs::read_to_string(path)
        },
    )?;
    let scripts: HashSet<_> = addresses
        .split_whitespace()
        .map(|addr| {
            bitcoin::Address::from_str(addr)
                .unwrap()
                .assume_checked()
                .script_pubkey()
        })
        .collect();
    if let Some(path) = args.address_file.as_ref() {
        info!("watching {} addresses from {:?}", scripts.len(), path);
    }
    Ok(scripts)
}

fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::builder().format_timestamp_micros().init();
    let cache_db = rusqlite::Connection::open(Path::new(match args.cache_file {
        Some(ref p) => p.as_path(),
        None => Path::new(":memory:"),
    }))?;

    let cache = cache::Cache::open(cache_db)?;
    let scripts = collect_scripts(&args)?;
    let mut index = open_index(&args)?;
    let mut updated = true; // to sync the cache on first iteration
    loop {
        while index.sync_chain(1000)?.indexed_blocks > 0 {
            updated = true;
        }
        if updated && !scripts.is_empty() {
            cache.sync(&scripts, &index)?;
            let entries = get_history(cache.db(), &scripts, index.chain())?;
            print_history(entries, args.history_limit);
        }
        updated = false;
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
