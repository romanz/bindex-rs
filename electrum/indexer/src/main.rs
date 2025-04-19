use std::path::{Path, PathBuf};

use bindex::{
    address::{self, cache},
    cli,
};
use clap::Parser;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Parser)]
#[command(version, about, long_about = None)]
/// Bitcoin address indexer
struct Args {
    #[arg(value_enum, short = 'n', long = "network", default_value_t = cli::Network::Bitcoin)]
    network: cli::Network,

    /// SQLite3 database for storing address history and relevant transactions
    #[arg(short = 'c', long = "cache")]
    cache_file: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    env_logger::builder().format_timestamp_micros().init();
    let cache_db = rusqlite::Connection::open(Path::new(args.cache_file.as_path()))?;
    let cache = cache::Cache::open(cache_db)?;
    let mut index = address::Index::open_default(args.network)?;
    let mut line = String::new();
    loop {
        let tip = loop {
            let stats = index.sync_chain(1000)?;
            if stats.indexed_blocks == 0 {
                break stats.tip;
            }
        };
        println!("{}", tip); // notify Electrum server
        line.clear();
        std::io::stdin().read_line(&mut line)?; // wait for notification
        cache.sync(&index)?;
    }
}
