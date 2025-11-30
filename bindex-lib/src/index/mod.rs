mod scripthash;
mod txpos;

use bitcoin::{consensus::Encodable, hashes::Hash, BlockHash};

use crate::chain::Chain;

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
pub struct HashPrefix([u8; HashPrefix::LEN]);

impl HashPrefix {
    const LEN: usize = 8;

    fn new(hash: &[u8]) -> Self {
        Self(hash[..HashPrefix::LEN].try_into().unwrap())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<ScriptHash> for HashPrefix {
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
pub struct HashPrefixRow {
    key: [u8; HashPrefixRow::LEN],
}

impl HashPrefixRow {
    const LEN: usize = HashPrefix::LEN + TxNum::LEN;

    pub fn new(prefix: HashPrefix, txnum: TxNum) -> Self {
        let mut result = [0u8; HashPrefix::LEN + TxNum::LEN];
        result[..HashPrefix::LEN].copy_from_slice(&prefix.0);
        result[HashPrefix::LEN..].copy_from_slice(&txnum.serialize());
        Self { key: result }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn from_bytes(key: [u8; Self::LEN]) -> Self {
        Self { key }
    }

    pub fn txnum(&self) -> TxNum {
        TxNum::deserialize(self.key[HashPrefix::LEN..].try_into().unwrap())
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Header {
    next_txnum: TxNum,
    hash: bitcoin::BlockHash,
    header: bitcoin::block::Header,
}

const BLOCK_HASH_LEN: usize = bitcoin::BlockHash::LEN;
const BLOCK_HEADER_LEN: usize = bitcoin::block::Header::SIZE;

type SerializedHeaderRow = ([u8; TxNum::LEN], [u8; BLOCK_HASH_LEN + BLOCK_HEADER_LEN]);

impl Header {
    fn new(next_txnum: TxNum, hash: bitcoin::BlockHash, header: bitcoin::block::Header) -> Self {
        Self {
            next_txnum,
            hash,
            header,
        }
    }

    pub fn serialize(&self) -> SerializedHeaderRow {
        let key = self.next_txnum.serialize();
        let mut value = [0u8; BLOCK_HASH_LEN + BLOCK_HEADER_LEN];
        value[..BLOCK_HASH_LEN].copy_from_slice(self.hash.as_byte_array());
        self.header
            .consensus_encode(&mut &mut value[BLOCK_HASH_LEN..])
            .unwrap();
        (key, value)
    }

    pub fn deserialize((key, value): SerializedHeaderRow) -> Self {
        Self {
            next_txnum: TxNum(u64::from_be_bytes(key)),
            hash: BlockHash::from_byte_array(value[..BLOCK_HASH_LEN].try_into().unwrap()),
            header: bitcoin::consensus::encode::deserialize(&value[BLOCK_HASH_LEN..]).unwrap(),
        }
    }

    pub fn next_txnum(&self) -> TxNum {
        self.next_txnum
    }

    pub fn hash(&self) -> BlockHash {
        self.hash
    }

    pub fn header(&self) -> &bitcoin::block::Header {
        &self.header
    }
}

pub struct BlockBytes(Vec<u8>);

impl BlockBytes {
    pub fn new(data: Vec<u8>) -> Self {
        BlockBytes(data)
    }

    fn header(&self) -> &[u8] {
        &self.0[..BLOCK_HEADER_LEN]
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
    pub script_hash_rows: Vec<HashPrefixRow>,
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
        let header = Header::new(
            txnum,
            hash,
            bitcoin::consensus::encode::deserialize(block.header())?,
        );
        Ok(Batch {
            script_hash_rows,
            txpos_rows,
            header,
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
        self.tip = batch.header.hash;
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
        let row = HashPrefixRow::new(HashPrefix([1, 2, 3, 4, 5, 6, 7, 8]), txnum);
        assert_eq!(row.txnum(), txnum);
        let data = row.key;
        assert_eq!(data, hex!("0102030405060708123456789abcdef0"));
        assert_eq!(HashPrefixRow::from_bytes(data), row);
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
