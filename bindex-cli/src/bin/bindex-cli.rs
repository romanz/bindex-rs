use bindex::{
    bitcoin::{self, consensus::deserialize, hashes::Hash, Network, Txid},
    cache, IndexedChain,
};
use chrono::{TimeZone, Utc};
use clap::{Parser, ValueEnum};
use log::*;
use std::{
    collections::HashSet,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
    time::Instant,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(tabled::Tabled)]
struct Entry {
    txid: String,
    time: String,
    height: String,
    offset: String,
    delta: String,
    balance: String,
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
        }
    }
}

fn get_history(db: &rusqlite::Connection) -> Result<Vec<Entry>> {
    let t = Instant::now();

    let addresses: usize = db.query_row("SELECT count(*) FROM watch", [], |row| {
        let sum: Option<usize> = row.get(0)?;
        Ok(sum.unwrap_or(0))
    })?;
    if addresses == 0 {
        return Ok(vec![]);
    }

    let mut select = db.prepare(
        r"
        WITH history_deltas AS (
            SELECT
                block_offset,
                block_height,
                sum(history.amount) AS delta
            FROM history
            GROUP BY 1, 2
        )
        SELECT
            h.header_bytes,
            t.block_offset,
            t.block_height,
            t.tx_id,
            d.delta
        FROM
            history_deltas d, transactions t, headers h
        WHERE
            d.block_height = t.block_height AND
            d.block_offset = t.block_offset AND
            d.block_height = h.block_height
        ORDER BY
            d.block_height ASC,
            d.block_offset ASC",
    )?;

    let mut balance = bitcoin::SignedAmount::ZERO;
    let entries = select
        .query([])?
        .and_then(|row| -> Result<Option<Entry>> {
            let header_bytes: Vec<u8> = row.get(0)?;
            let block_offset: u64 = row.get(1)?;
            let block_height: usize = row.get(2)?;
            let txid = Txid::from_byte_array(row.get(3)?);
            let delta = bitcoin::SignedAmount::from_sat(row.get(4)?);
            balance += delta;
            let header: bitcoin::block::Header =
                deserialize(&header_bytes).expect("bad header bytes");
            Ok(Some(Entry {
                txid: txid.to_string(),
                time: format!("{}", Utc.timestamp_opt(header.time.into(), 0).unwrap()),
                height: block_height.to_string(),
                offset: block_offset.to_string(),
                delta: format!("{:+.8}", delta.to_btc()),
                balance: format!("{:.8}", balance.to_btc()),
            }))
        })
        .filter_map(Result::transpose)
        .collect::<Result<Vec<Entry>>>()?;

    assert!(!balance.is_negative());
    let balance_check = db.query_row("SELECT sum(amount) FROM history", [], |row| {
        let sum: Option<i64> = row.get(0)?;
        Ok(bitcoin::SignedAmount::from_sat(sum.unwrap_or(0)))
    })?;
    assert_eq!(balance_check, balance);

    let utxos: usize = db.query_row("SELECT sum(sign(amount)) FROM history", [], |row| {
        let sum: Option<usize> = row.get(0)?;
        Ok(sum.unwrap_or(0))
    })?;

    info!(
        "{} address history: {} entries, balance: {}, UTXOs: {} [{:?}]",
        addresses,
        entries.len(),
        balance,
        utxos,
        t.elapsed(),
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
        println!("{tbl}");
    }
}

#[derive(Clone, Copy)]
struct NetworkArg(Network);

impl ValueEnum for NetworkArg {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            NetworkArg(Network::Bitcoin),
            NetworkArg(Network::Testnet),
            NetworkArg(Network::Testnet4),
            NetworkArg(Network::Signet),
            NetworkArg(Network::Regtest),
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        let name = self.0.to_string();
        Some(name.into())
    }
}

impl From<NetworkArg> for Network {
    fn from(value: NetworkArg) -> Self {
        value.0
    }
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Bitcoin address indexer
struct Args {
    #[arg(long = "db-path")]
    db_path: String,

    #[arg(value_enum, short = 'n', long = "network", default_value_t = NetworkArg(Network::Bitcoin))]
    network: NetworkArg,

    /// Limit on how many recent transactions to print
    #[arg(short = 'l', long = "limit", default_value_t = 0)]
    history_limit: usize,

    /// Text file, containing white-space separated addresses to add
    #[arg(short = 'a', long = "address-file")]
    address_file: Option<PathBuf>,

    /// SQLite3 database for storing address history and relevant transactions
    #[arg(short = 'c', long = "cache")]
    cache_file: Option<PathBuf>,

    /// Exit after one sync is over
    #[arg(short = '1', long = "sync-once", default_value_t = false)]
    sync_once: bool,
}

fn collect_addresses(args: &Args) -> Result<HashSet<bitcoin::Address>> {
    let text = args.address_file.as_ref().map_or_else(
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
    let addresses = text
        .split_whitespace()
        .map(|addr| -> Result<bitcoin::Address> {
            Ok(bitcoin::Address::from_str(addr)?.require_network(args.network.into())?)
        })
        .collect::<Result<_>>()?;
    Ok(addresses)
}

fn run() -> Result<()> {
    let args = Args::parse();
    env_logger::builder().format_timestamp_micros().init();

    let mut chain = IndexedChain::open(&args.db_path, args.network.into())?;
    let mut tip = chain.headers().tip_hash();

    let cache_db = rusqlite::Connection::open(Path::new(match args.cache_file {
        Some(ref p) => p.as_path(),
        None => Path::new(":memory:"),
    }))?;
    let cache = cache::Cache::open(cache_db)?;
    print_history(get_history(cache.db())?, args.history_limit);
    cache.add(collect_addresses(&args)?)?;

    loop {
        // index new blocks (also handle reorgs)
        while chain.sync(1000)?.indexed_blocks > 0 {}
        // make sure to update new scripthashes (even if there are no new blocks)
        cache.sync(&chain)?;
        if tip != chain.headers().tip_hash() {
            print_history(get_history(cache.db())?, args.history_limit);
            tip = chain.headers().tip_hash();
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        if args.sync_once {
            break;
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        error!("{}: {:?}", e, e)
    }
}
