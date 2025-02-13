use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use std::thread;

use bindex::{AddrIndex, Error, Location};

use bitcoin::consensus::deserialize;
use chrono::{TimeZone, Utc};
use clap::{Parser, ValueEnum};
use log::*;

#[derive(tabled::Tabled)]
struct Row {
    txid: String,
    time: String,
    height: String,
    offset: String,
    delta: String,
    balance: String,
    ms: String,
    bytes: String,
}

impl Row {
    fn dots() -> Self {
        let s = "...";
        Self {
            txid: s.to_owned(),
            time: s.to_owned(),
            height: s.to_owned(),
            offset: s.to_owned(),
            delta: s.to_owned(),
            balance: s.to_owned(),
            ms: s.to_owned(),
            bytes: s.to_owned(),
        }
    }
}

fn compute_balance(
    scripts: &HashSet<bitcoin::ScriptBuf>,
    index: &AddrIndex,
    history_limit: usize,
) -> Result<(), Error> {
    if scripts.len() == 0 {
        return Ok(());
    }
    let t = std::time::Instant::now();
    // sort and dedup transaction locations to be analyzed
    let locations = scripts
        .iter()
        .flat_map(|script| index.find(script).expect("script lookup failed"))
        .collect::<BTreeSet<Location>>();
    info!(
        "{} address history: {} txs ({:?})",
        scripts.len(),
        locations.len(),
        t.elapsed()
    );

    if locations.is_empty() {
        return Ok(());
    }

    let t = std::time::Instant::now();
    let mut rows = Vec::with_capacity(locations.len());
    let mut total_bytes = 0;
    let mut unspent = HashMap::<bitcoin::OutPoint, bitcoin::Amount>::new();
    let mut balance = bitcoin::SignedAmount::ZERO;
    for loc in &locations {
        let t = std::time::Instant::now();
        let tx_bytes = index.get_tx_bytes(loc)?;
        total_bytes += tx_bytes.len();
        let tx: bitcoin::Transaction = deserialize(&tx_bytes).expect("bad tx bytes");
        let txid = tx.compute_txid();
        let dt = t.elapsed();
        let mut delta = bitcoin::SignedAmount::ZERO;
        for txi in tx.input {
            if let Some(spent) = unspent.remove(&txi.previous_output) {
                delta -= spent.to_signed().expect("spent overflow");
            }
        }
        for (n, txo) in tx.output.into_iter().enumerate() {
            if scripts.contains(&txo.script_pubkey) {
                delta += txo.value.to_signed().expect("txo.value overflow");
                unspent.insert(
                    bitcoin::OutPoint::new(txid, n.try_into().unwrap()),
                    txo.value,
                );
            }
        }
        balance += delta;
        rows.push(Row {
            txid: txid.to_string(),
            time: format!(
                "{}",
                Utc.timestamp_opt(loc.indexed_header.header().time.into(), 0)
                    .unwrap()
                    .to_string()
            ),
            height: loc.height.to_string(),
            offset: loc.offset.to_string(),
            delta: format!("{:+.8}", delta.to_btc()),
            balance: format!("{:.8}", balance.to_btc()),
            ms: format!("{:.3}", dt.as_micros() as f64 / 1e3),
            bytes: tx_bytes.len().to_string(),
        });
    }

    let dt = t.elapsed();
    info!(
        "fetched {} txs, {:.3} MB, balance: {}, UTXOs: {} ({:?})",
        locations.len(),
        total_bytes as f64 / 1e6,
        balance,
        unspent.len(),
        dt,
    );

    if history_limit > 0 {
        let is_truncated = rows.len() > history_limit;
        rows.reverse();
        rows.truncate(history_limit);
        if is_truncated {
            rows.push(Row::dots());
        }

        let mut tbl = tabled::Table::new(rows);
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
    Ok(())
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Network {
    Bitcoin,
    Testnet,
    Testnet4,
    Regtest,
    Signet,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
/// Bitcoin address indexer
struct Args {
    #[arg(value_enum)]
    network: Network,

    #[arg(short = 'l', long = "limit", default_value_t = 100)]
    history_limit: usize,

    addresses: Vec<String>,
}

fn main() -> Result<(), Error> {
    let args = Args::parse();
    env_logger::builder().format_timestamp_micros().init();
    let default_rpc_port = match args.network {
        Network::Bitcoin => 8332,
        Network::Testnet => 18332,
        Network::Testnet4 => 48332,
        Network::Regtest => 18443,
        Network::Signet => 38332,
    };
    let default_db_dir = match args.network {
        Network::Bitcoin => "bitcoin",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
    };
    let url = format!("http://localhost:{}", default_rpc_port);
    let db_path = format!("db/{default_db_dir}");

    let scripts: HashSet<_> = args
        .addresses
        .iter()
        .map(|addr| {
            bitcoin::Address::from_str(addr)
                .unwrap()
                .assume_checked()
                .script_pubkey()
        })
        .collect();

    let mut index = AddrIndex::open(db_path, url)?;
    let mut updated = true;
    loop {
        while index.sync(1000)?.indexed_blocks > 0 {
            updated = true;
        }
        if updated {
            compute_balance(&scripts, &index, args.history_limit)?;
            updated = false;
        }
        thread::sleep(std::time::Duration::from_secs(1));
    }
}
