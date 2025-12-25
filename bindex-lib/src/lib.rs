pub use bitcoin;

pub mod cache;

mod client;
mod db;
mod headers;
mod index;
mod network;
mod store;

pub use network::Network;
pub use store::IndexedChain;

#[derive(PartialEq, Eq, PartialOrd, Clone, Copy, Debug)]
pub struct Location<'a> {
    txnum: index::TxNum, // tx number (position within the chain)
    block_height: usize, // block height
    block_offset: u32,   // tx position within its block
    indexed_header: &'a index::IndexedHeader,
}

impl Location<'_> {
    pub fn blockhash(&self) -> bitcoin::BlockHash {
        self.indexed_header.hash()
    }
}

impl Ord for Location<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.txnum.cmp(&other.txnum)
    }
}
