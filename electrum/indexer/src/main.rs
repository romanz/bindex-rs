use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use bindex::{
    address::{self, cache},
    cli,
};
use clap::Parser;
use log::{debug, info};

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

    let mut server = Command::new("python")
        .arg("-m")
        .arg("electrum.server")
        .arg(args.cache_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    info!("Launched server @ pid={}", server.id());

    let mut child_stdin = server.stdin.take().unwrap();
    let mut child_stdout = BufReader::new(server.stdout.take().unwrap());

    let mut tip = None;
    loop {
        let new_tip = loop {
            let stats = index.sync_chain(1000)?;
            if stats.indexed_blocks == 0 {
                break stats.tip;
            }
        };
        if tip != Some(new_tip) {
            cache.sync(&index)?;
            tip = Some(new_tip);
        }
        // notify Electrum server
        debug!("chain best block={}", new_tip);
        writeln!(child_stdin, "{}", new_tip)?;
        child_stdin.flush()?;

        line.clear();
        child_stdout.read_line(&mut line)?; // wait for notification
    }
}
