use crate::index;

use bitcoin::{hashes::Hash, BlockHash};

#[derive(thiserror::Error, Debug)]
pub enum Reorg {
    #[error("missing block={0} at height={1}")]
    Missing(bitcoin::BlockHash, usize),

    #[error("stale block={0} at height={1}")]
    Stale(bitcoin::BlockHash, usize),
}

pub struct Chain {
    rows: Vec<index::IndexedHeader>,
}

impl Chain {
    pub fn new(rows: Vec<index::IndexedHeader>) -> Self {
        let mut block_hash = bitcoin::BlockHash::all_zeros();
        for row in &rows {
            assert_eq!(row.header().prev_blockhash, block_hash);
            block_hash = row.hash();
        }
        Self { rows }
    }

    pub fn tip_hash(&self) -> Option<bitcoin::BlockHash> {
        self.rows.last().map(index::IndexedHeader::hash)
    }

    pub fn tip_height(&self) -> Option<usize> {
        self.rows.len().checked_sub(1)
    }

    pub fn next_txnum(&self) -> index::TxNum {
        self.rows
            .last()
            .map_or_else(index::TxNum::default, index::IndexedHeader::next_txnum)
    }

    pub fn add(&mut self, row: index::IndexedHeader) {
        assert_eq!(
            row.header().prev_blockhash,
            self.tip_hash().unwrap_or_else(BlockHash::all_zeros)
        );
        self.rows.push(row)
    }

    pub fn pop(&mut self) -> Option<index::IndexedHeader> {
        self.rows.pop()
    }

    pub fn genesis(&self) -> Option<&index::IndexedHeader> {
        self.rows.first()
    }

    pub fn get_header(
        &self,
        hash: BlockHash,
        height: usize,
    ) -> Result<&index::IndexedHeader, Reorg> {
        let header = self.rows.get(height).ok_or(Reorg::Missing(hash, height))?;
        if header.hash() == hash {
            Ok(header)
        } else {
            Err(Reorg::Stale(hash, height))
        }
    }

    pub fn find_by_txnum(&self, txnum: index::TxNum) -> Option<Location<'_>> {
        let height = match self
            .rows
            .binary_search_by_key(&txnum, index::IndexedHeader::next_txnum)
        {
            Ok(i) => i + 1, // hitting exactly a block boundary txnum -> next block
            Err(i) => i,
        };

        let indexed_header = self.rows.get(height)?;
        assert!(
            txnum < indexed_header.next_txnum(),
            "binary search failed to find the correct position"
        );

        let prev_txnum = self
            .rows
            .get(height - 1)
            .map_or_else(index::TxNum::default, index::IndexedHeader::next_txnum);

        assert!(
            txnum >= prev_txnum,
            "binary search failed to find the correct position"
        );
        let offset = txnum.offset_from(prev_txnum).unwrap();
        Some(Location {
            txnum,
            height,
            offset,
            indexed_header,
        })
    }
}

#[derive(PartialEq, Eq, PartialOrd, Clone, Copy, Debug)]
pub struct Location<'a> {
    pub txnum: index::TxNum, // tx number (position within the chain)
    pub height: usize,       // block height
    pub offset: u32,         // tx position within its block
    pub indexed_header: &'a index::IndexedHeader,
}

impl Ord for Location<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.txnum.cmp(&other.txnum)
    }
}
