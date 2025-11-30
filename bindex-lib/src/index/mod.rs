mod header;
mod scripthash;
mod txpos;

use bitcoin::{hashes::Hash, BlockHash};

use crate::chain::Chain;

pub use header::IndexedHeader;
pub use scripthash::ScriptHash;
pub use txpos::{TxBlockPos, TxBlockPosRow};

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

/// Fixed-size prefix of a hash (e.g. ScriptHash, Txid).
/// The resulting index uses less storage, but requires lookup post-filtering (to avoid false negatives).
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

/// Represents the "chronological" position of a confirmed transaction in the chain.
/// It is used as the globally unique transaction identifier for efficient storage encoding
/// (instead of 32-byte pseudo-random transaction hash).
/// There has been ~1.3e9 transactions at Dec. 2025, so using `u32` here should be OK till ~2060.
/// Big-endian encoding is used to make lexicographic order and "choronological" order the same.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Default)]
pub struct TxNum(u32);

impl TxNum {
    const LEN: usize = std::mem::size_of::<Self>();

    pub fn offset_from(&self, base: TxNum) -> Option<u32> {
        self.0.checked_sub(base.0)
    }

    fn increment(&mut self) {
        self.0 += 1;
    }

    pub fn serialize(&self) -> [u8; Self::LEN] {
        self.0.to_be_bytes()
    }

    pub fn deserialize(bytes: [u8; Self::LEN]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

/// Serialized and concatenated `prefix` & `txnum`, to be stored in a RockDB key-only entry.
/// RocksDB prefix scan is used to collect all `txnum`s matching a specific ScriptHash/Txid.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct HashPrefixRow {
    key: [u8; HashPrefixRow::LEN],
}

impl HashPrefixRow {
    const LEN: usize = Prefix::LEN + TxNum::LEN;

    pub fn new(prefix: Prefix, txnum: TxNum) -> Self {
        let mut key = [0u8; Prefix::LEN + TxNum::LEN];
        key[..Prefix::LEN].copy_from_slice(prefix.as_bytes());
        key[Prefix::LEN..].copy_from_slice(&txnum.serialize());
        Self { key }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    pub fn from_bytes(key: [u8; Self::LEN]) -> Self {
        Self { key }
    }

    pub fn txnum(&self) -> TxNum {
        TxNum::deserialize(self.key[Prefix::LEN..].try_into().unwrap())
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
    pub scripthash_rows: Vec<HashPrefixRow>,
    pub txpos_rows: Vec<txpos::TxBlockPosRow>,
    pub header: IndexedHeader,
}

pub struct BlockIndex<R> {
    next_txnum: TxNum,
    rows: Vec<R>,
}

impl<R> BlockIndex<R> {
    fn new(next_txnum: TxNum) -> Self {
        Self {
            next_txnum,
            rows: vec![],
        }
    }
}

impl Batch {
    fn build(
        hash: BlockHash,
        txnum: TxNum,
        block: &BlockBytes,
        spent: &SpentBytes,
    ) -> Result<Self, Error> {
        let scripthash = scripthash::index(block, spent, txnum)?;
        let txpos = txpos::index(block, txnum)?;

        // Both must have the same number of transactions
        assert_eq!(scripthash.next_txnum, txpos.next_txnum);
        let txnum = txpos.next_txnum;

        let header = bitcoin::consensus::encode::deserialize(block.header())?;
        Ok(Batch {
            scripthash_rows: scripthash.rows,
            txpos_rows: txpos.rows,
            header: IndexedHeader::new(txnum, hash, header),
        })
    }
}

pub struct IndexBuilder {
    batches: Vec<Batch>,
    next_txnum: TxNum,
    tip: bitcoin::BlockHash,
}

impl IndexBuilder {
    pub fn new(chain: &Chain) -> Self {
        Self {
            next_txnum: chain.next_txnum(),
            batches: vec![],
            tip: chain
                .tip_hash()
                .unwrap_or_else(bitcoin::BlockHash::all_zeros),
        }
    }

    pub fn add(
        &mut self,
        hash: bitcoin::BlockHash,
        block_bytes: &BlockBytes,
        spent_bytes: &SpentBytes,
    ) -> Result<(), Error> {
        let batch = Batch::build(hash, self.next_txnum, block_bytes, spent_bytes)?;
        let header = &batch.header;
        assert_eq!(header.header().prev_blockhash, self.tip);
        self.next_txnum = header.next_txnum();
        self.tip = header.hash();
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
        let txnum = TxNum(0x12345678);
        let row = HashPrefixRow::new(Prefix([1, 2, 3, 4, 5, 6, 7, 8]), txnum);
        assert_eq!(row.txnum(), txnum);
        let data = row.key;
        assert_eq!(data, hex!("010203040506070812345678"));
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
