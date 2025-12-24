use std::ops::ControlFlow;

use bitcoin::hashes::Hash;
use bitcoin_slices::{bsl, Parse, Visit};

use crate::index::{BlockBytes, Error, HashPrefixRow, IndexedBlock, SpentBytes, TxNum};

bitcoin::hashes::hash_newtype! {
    /// https://electrumx-spesmilo.readthedocs.io/en/latest/protocol-basics.html#script-hashes
    #[hash_newtype(backward)]
    pub struct ScriptHash(bitcoin::hashes::sha256::Hash);
}

impl ScriptHash {
    pub fn new(script: &bitcoin::Script) -> Self {
        Self::hash(script.as_bytes())
    }
}

struct IndexVisitor<'a> {
    rows: &'a mut Vec<HashPrefixRow>,
    txnum: TxNum,
}

impl<'a> IndexVisitor<'a> {
    fn new(txnum: TxNum, rows: &'a mut Vec<HashPrefixRow>) -> Self {
        Self { txnum, rows }
    }

    fn add(&mut self, script: &bitcoin::Script) {
        if script.is_op_return() {
            // skip indexing unspendable outputs
            return;
        }
        let prefix = ScriptHash::new(script).into();
        self.rows.push(HashPrefixRow::new(prefix, self.txnum));
    }

    fn finish_tx(&mut self) {
        self.txnum.increment()
    }
}

impl bitcoin_slices::Visitor for IndexVisitor<'_> {
    fn visit_tx_out(&mut self, _vout: usize, tx_out: &bsl::TxOut) -> ControlFlow<()> {
        self.add(bitcoin::Script::from_bytes(tx_out.script_pubkey()));
        ControlFlow::Continue(())
    }

    fn visit_transaction(&mut self, _tx: &bsl::Transaction) -> ControlFlow<()> {
        // Updated after all txouts are scanned
        self.finish_tx();
        ControlFlow::Continue(())
    }
}

struct Spent;

impl AsRef<[u8]> for Spent {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

fn visit_spent<'a>(
    slice: &'a [u8],
    visit: &mut IndexVisitor,
) -> bitcoin_slices::SResult<'a, Spent> {
    let mut consumed = 0;
    let txs_count = bsl::scan_len(slice, &mut consumed)?;

    for _ in 0..txs_count {
        let outputs_count = bsl::scan_len(&slice[consumed..], &mut consumed)?;

        for _ in 0..outputs_count {
            let tx_out = bsl::TxOut::parse(&slice[consumed..])?;
            consumed += tx_out.consumed();
            let script_pubkey = tx_out.parsed().script_pubkey();
            visit.add(bitcoin::Script::from_bytes(script_pubkey));
        }
        visit.finish_tx();
    }

    Ok(bitcoin_slices::ParseResult::new(&slice[consumed..], Spent))
}

fn add_block_rows(
    block: &BlockBytes,
    txnum: TxNum,
    rows: &mut Vec<HashPrefixRow>,
) -> Result<TxNum, Error> {
    let mut visitor = IndexVisitor::new(txnum, rows);
    let res = bsl::Block::visit(&block.0, &mut visitor).map_err(Error::Parse)?;
    if !res.remaining().is_empty() {
        return Err(Error::Leftover(res.remaining().len()));
    }
    Ok(visitor.txnum)
}

fn add_spent_rows(
    spent: &SpentBytes,
    txnum: TxNum,
    rows: &mut Vec<HashPrefixRow>,
) -> Result<TxNum, Error> {
    let mut visitor = IndexVisitor::new(txnum, rows);
    let res = visit_spent(&spent.0, &mut visitor).map_err(Error::Parse)?;
    if !res.remaining().is_empty() {
        return Err(Error::Leftover(res.remaining().len()));
    }
    Ok(visitor.txnum)
}

pub fn index(
    block: &BlockBytes,
    spent: &SpentBytes,
    txnum: TxNum,
) -> Result<IndexedBlock<HashPrefixRow>, Error> {
    let mut result = IndexedBlock::new(txnum);
    let txnum1 = add_block_rows(block, txnum, &mut result.rows)?;
    let txnum2 = add_spent_rows(spent, txnum, &mut result.rows)?;
    assert_eq!(txnum1, txnum2);
    result.next_txnum = txnum1;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::{deserialize, encode::Decodable};
    use hex_lit::hex;

    use super::*;
    use crate::index::{Batch, Prefix};

    // Block 100000
    const BLOCK_HEX: &str = "0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b57100401000000010000000000000000000000000000000000000000000000000000000000000000ffffffff08044c86041b020602ffffffff0100f2052a010000004341041b0e8c2567c12536aa13357b79a073dc4444acb83c4ec7a0e2f99dd7457516c5817242da796924ca4e99947d087fedf9ce467cb9f7c6287078f801df276fdf84ac000000000100000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc00779ac88fdf357a187000000008c493046022100c352d3dd993a981beba4a63ad15c209275ca9470abfcd57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055cf7b5ee1af1ebcc6028d9cdb1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a4e6ca164593c2527c038c0857eb67ee8e825dca65046b82c9331586c82e0fd1f633f25f87c161bc6f8a630121df2b3d3ffffffff0200e32321000000001976a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac000fe208010000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac000000000100000001c33ebff2a709f13d9f9a7569ab16a32786af7d7e2de09265e41c61d078294ecf010000008a4730440220032d30df5ee6f57fa46cddb5eb8d0d9fe8de6b342d27942ae90a3231e0ba333e02203deee8060fdc70230a7f5b4ad7d7bc3e628cbe219a886b84269eaeb81e26b4fe014104ae31c31bf91278d99b8377a35bbce5b27d9fff15456839e919453fc7b3f721f0ba403ff96c9deeb680e5fd341c0fc3a7b90da4631ee39560639db462e9cb850fffffffff0240420f00000000001976a914b0dcbf97eabf4404e31d952477ce822dadbe7e1088acc060d211000000001976a9146b1281eec25ab4e1e0793ff4e08ab1abb3409cd988ac0000000001000000010b6072b386d4a773235237f64c1126ac3b240c84b917a3909ba1c43ded5f51f4000000008c493046022100bb1ad26df930a51cce110cf44f7a48c3c561fd977500b1ae5d6b6fd13d0b3f4a022100c5b42951acedff14abba2736fd574bdb465f3e6f8da12e2c5303954aca7f78f3014104a7135bfe824c97ecc01ec7d7e336185c81e2aa2c41ab175407c09484ce9694b44953fcb751206564a9c24dd094d42fdbfdd5aad3e063ce6af4cfaaea4ea14fbbffffffff0140420f00000000001976a91439aa3d569e06a1d7926dc4be1193c99bf2eb9ee088ac00000000";
    const SPENT_HEX: &str = "04000100f2052a010000001976a91471d7dd96d9edda09180fe9d57a477b5acc9cad1188ac0100a3e111000000001976a91435fbee6a3bf8d99f17724ec54787567393a8a6b188ac0140420f00000000001976a914c4eb47ecfdcf609a1848ee79acc2fa49d3caad7088ac";

    #[test]
    fn test_index_block() -> Result<(), Error> {
        let block_bytes = BlockBytes(hex!(BLOCK_HEX).to_vec());
        let spent_bytes = SpentBytes(hex!(SPENT_HEX).to_vec());
        let txnum = TxNum(10);

        let mut block_rows = vec![];
        assert_eq!(
            add_block_rows(&block_bytes, txnum, &mut block_rows)?,
            TxNum(14)
        );

        assert_eq!(
            block_rows,
            vec![
                HashPrefixRow::new(Prefix(hex!("e2151d493a1f9999")), TxNum(10)),
                HashPrefixRow::new(Prefix(hex!("050b00fb9d5f7a63")), TxNum(11)),
                HashPrefixRow::new(Prefix(hex!("b5a1091a739a6aba")), TxNum(11)),
                HashPrefixRow::new(Prefix(hex!("03b0bfb44fd9d852")), TxNum(12)),
                HashPrefixRow::new(Prefix(hex!("0faa9934b57389f2")), TxNum(12)),
                HashPrefixRow::new(Prefix(hex!("4a569bc2092bcaf9")), TxNum(13))
            ]
        );

        let mut spent_rows = vec![];
        assert_eq!(
            add_spent_rows(&spent_bytes, txnum, &mut spent_rows)?,
            TxNum(14)
        );

        assert_eq!(
            spent_rows,
            vec![
                HashPrefixRow::new(Prefix(hex!("4d5bea28470692cd")), TxNum(11)),
                HashPrefixRow::new(Prefix(hex!("e9b09b065b5f43c2")), TxNum(12)),
                HashPrefixRow::new(Prefix(hex!("2e7cdb30882b427d")), TxNum(13)),
            ]
        );

        // Verify spent outputs indexing
        let mut test_spent_rows = vec![];
        assert_eq!(
            decode_spent(&spent_bytes.0, txnum, &mut test_spent_rows)?,
            TxNum(14)
        );
        assert_eq!(test_spent_rows, spent_rows);

        // Verify public interface
        let block: bitcoin::Block = deserialize(&block_bytes.0).unwrap();
        let batch = Batch::build(block.block_hash(), txnum, &block_bytes, &spent_bytes)?;

        assert_eq!(batch.header.next_txnum(), TxNum(14));
        assert_eq!(batch.header.hash(), block.block_hash());
        assert_eq!(batch.scripthash_rows, [block_rows, spent_rows].concat());

        Ok(())
    }

    fn decode_spent(
        buf: &[u8],
        txnum: TxNum,
        rows: &mut Vec<HashPrefixRow>,
    ) -> Result<TxNum, Error> {
        let mut visitor = IndexVisitor::new(txnum, rows);
        let mut r = bitcoin::io::Cursor::new(buf);
        let txs_count = bitcoin::VarInt::consensus_decode_from_finite_reader(&mut r)?.0;
        for _ in 0..txs_count {
            let outputs_count = bitcoin::VarInt::consensus_decode_from_finite_reader(&mut r)?.0;
            for _ in 0..outputs_count {
                let output = bitcoin::TxOut::consensus_decode_from_finite_reader(&mut r)?;
                visitor.add(&output.script_pubkey);
            }
            visitor.finish_tx();
        }
        let pos: usize = r.position().try_into().unwrap();
        if pos == buf.len() {
            Ok(visitor.txnum)
        } else {
            Err(Error::Leftover(buf.len() - pos))
        }
    }
}
