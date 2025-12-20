use std::ops::ControlFlow;

use bitcoin_slices::{bsl, Visit as _};

use crate::index::{BlockBytes, BlockIndex, Error, HashPrefixRow, TxNum};

struct IndexVisitor<'a> {
    result: &'a mut BlockIndex<HashPrefixRow>,
}

impl bitcoin_slices::Visitor for IndexVisitor<'_> {
    fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
        let prefix = tx.txid().into();
        self.result
            .rows
            .push(HashPrefixRow::new(prefix, self.result.next_txnum));
        self.result.next_txnum.increment();
        ControlFlow::Continue(())
    }
}

pub fn index(block: &BlockBytes, txnum: TxNum) -> Result<BlockIndex<HashPrefixRow>, Error> {
    let mut result = BlockIndex::new(txnum);
    let mut visitor = IndexVisitor {
        result: &mut result,
    };
    let res = bsl::Block::visit(&block.0, &mut visitor).map_err(Error::Parse)?;
    if !res.remaining().is_empty() {
        return Err(Error::Leftover(res.remaining().len()));
    }
    Ok(result)
}
