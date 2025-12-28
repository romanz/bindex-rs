pub use bitcoin;

#[cfg(feature = "cache")]
pub mod cache;

mod chain;
mod client;
mod db;
mod headers;
mod index;

pub use chain::IndexedChain;
pub use headers::Headers;
pub use index::ScriptHash;

#[derive(PartialEq, Eq, PartialOrd, Clone, Copy, Debug)]
pub struct Location<'a> {
    txnum: index::TxNum, // tx number (position within the chain)
    block_height: usize, // block height
    block_offset: u32,   // tx position within its block
    indexed_header: &'a index::IndexedHeader,
}

impl Location<'_> {
    pub fn block_hash(&self) -> bitcoin::BlockHash {
        self.indexed_header.hash()
    }

    pub fn block_height(&self) -> usize {
        self.block_height
    }
}

impl Ord for Location<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.txnum.cmp(&other.txnum)
    }
}
