mod header;
mod scripthash;
mod txpos;

use bitcoin::{hashes::Hash, BlockHash};

use crate::chain::Chain;

pub use header::Header;
pub use scripthash::ScriptHash;
pub use txpos::{TxPos, TxPosRow};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("decoding failed: {0}")]
    Decode(#[from] bitcoin::consensus::encode::Error),

    #[error("parsing failed: {0:?}")]
    Parse(bitcoin_slices::Error),

    #[error("{0} bytes were not parsed")]
    Leftover(usize),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct Prefix([u8; Prefix::LEN]);

impl Prefix {
    const LEN: usize = 8;

    fn new(hash: &[u8]) -> Self {
        Self(hash[..Prefix::LEN].try_into().unwrap())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<ScriptHash> for Prefix {
    fn from(value: ScriptHash) -> Self {
        Self::new(&value[..])
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Default)]
pub struct TxNum(u64);

impl TxNum {
    const LEN: usize = std::mem::size_of::<Self>();

    pub fn offset_from(&self, base: TxNum) -> Option<u64> {
        self.0.checked_sub(base.0)
    }

    pub fn serialize(&self) -> [u8; Self::LEN] {
        self.0.to_be_bytes()
    }

    pub fn deserialize(bytes: [u8; Self::LEN]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct Row {
    bytes: [u8; Row::LEN],
}

impl Row {
    const LEN: usize = Prefix::LEN + TxNum::LEN;

    pub fn new(prefix: Prefix, txnum: TxNum) -> Self {
        let mut bytes = [0u8; Prefix::LEN + TxNum::LEN];
        bytes[..Prefix::LEN].copy_from_slice(&prefix.0);
        bytes[Prefix::LEN..].copy_from_slice(&txnum.serialize());
        Self { bytes }
    }

    pub fn key(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self { bytes }
    }

    pub fn txnum(&self) -> TxNum {
        TxNum::deserialize(self.bytes[Prefix::LEN..].try_into().unwrap())
    }
}

pub struct BlockBytes(Vec<u8>);

impl BlockBytes {
    pub fn new(data: Vec<u8>) -> Self {
        BlockBytes(data)
    }

    fn header(&self) -> &[u8] {
        &self.0[..bitcoin::block::Header::SIZE]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct SpentBytes(Vec<u8>);

impl SpentBytes {
    pub fn new(data: Vec<u8>) -> Self {
        SpentBytes(data)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

pub struct Batch {
    pub script_hash_rows: Vec<Row>,
    pub txpos_rows: Vec<txpos::TxPosRow>,
    pub header: Header,
}

impl Batch {
    fn build(
        hash: BlockHash,
        txnum: TxNum,
        block: &BlockBytes,
        spent: &SpentBytes,
    ) -> Result<Self, Error> {
        let mut script_hash_rows = vec![];
        let mut txpos_rows = vec![];
        let txnum = {
            let num1 = scripthash::add_block_rows(block, txnum, &mut script_hash_rows)?;
            let num2 = scripthash::add_spent_rows(spent, txnum, &mut script_hash_rows)?;
            assert_eq!(num1, num2); // both must have the same number of transactions
            let num3 = txpos::add_txpos_rows(block, txnum, &mut txpos_rows)?;
            assert_eq!(num1, num3); // both must have the same number of transactions
            num1
        };
        let header = bitcoin::consensus::encode::deserialize(block.header())?;
        Ok(Batch {
            script_hash_rows,
            txpos_rows,
            header: Header::new(txnum, hash, header),
        })
    }
}

pub struct Builder {
    batches: Vec<Batch>,
    next_txnum: TxNum,
    tip: bitcoin::BlockHash,
}

impl Builder {
    pub fn new(chain: &Chain) -> Self {
        Self {
            next_txnum: chain.next_txnum(),
            batches: vec![],
            tip: chain
                .tip_hash()
                .unwrap_or_else(bitcoin::BlockHash::all_zeros),
        }
    }

    pub fn index(
        &mut self,
        hash: bitcoin::BlockHash,
        block_bytes: &BlockBytes,
        spent_bytes: &SpentBytes,
    ) -> Result<(), Error> {
        let batch = Batch::build(hash, self.next_txnum, block_bytes, spent_bytes)?;
        assert_eq!(batch.header.header().prev_blockhash, self.tip);
        self.next_txnum = batch.header.next_txnum();
        self.tip = batch.header.hash();
        self.batches.push(batch);
        Ok(())
    }

    pub fn into_batches(self) -> Vec<Batch> {
        self.batches
    }
}

#[cfg(test)]
mod tests {
    use hex_lit::hex;

    use super::*;

    #[test]
    fn test_serde_row() {
        let txnum = TxNum(0x123456789ABCDEF0);
        let row = Row::new(Prefix([1, 2, 3, 4, 5, 6, 7, 8]), txnum);
        assert_eq!(row.txnum(), txnum);
        let data = row.bytes;
        assert_eq!(data, hex!("0102030405060708123456789abcdef0"));
        assert_eq!(Row::from_bytes(data), row);
    }

    #[test]
    fn test_map_txnum() {
        let txnum = [10, 20, 30, 40];

        assert_eq!(txnum.binary_search(&0), Err(0));
        assert_eq!(txnum.binary_search(&1), Err(0));
        assert_eq!(txnum.binary_search(&9), Err(0));
        assert_eq!(txnum.binary_search(&10), Ok(0));
        assert_eq!(txnum.binary_search(&11), Err(1));
        assert_eq!(txnum.binary_search(&19), Err(1));
        assert_eq!(txnum.binary_search(&20), Ok(1));
        assert_eq!(txnum.binary_search(&21), Err(2));
        assert_eq!(txnum.binary_search(&29), Err(2));
        assert_eq!(txnum.binary_search(&30), Ok(2));
        assert_eq!(txnum.binary_search(&31), Err(3));
        assert_eq!(txnum.binary_search(&39), Err(3));
        assert_eq!(txnum.binary_search(&40), Ok(3));
        assert_eq!(txnum.binary_search(&41), Err(4));
    }
}
