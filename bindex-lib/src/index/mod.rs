mod header;
mod scripthash;
mod sptweak;
mod txid;
mod txpos;

use bitcoin::{hashes::sha256d, BlockHash};
use bitcoin_slices::bsl;

pub use header::IndexedHeader;
pub use scripthash::ScriptHash;
pub use sptweak::TxTweakRow;
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
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

// Used for Txid prefix extraction
impl From<sha256d::Hash> for Prefix {
    fn from(value: sha256d::Hash) -> Self {
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

    pub fn increment_by(&mut self, delta: u32) {
        self.0 = self.0.checked_add(delta).expect("txnum overflow");
    }

    pub fn serialize(&self) -> [u8; Self::LEN] {
        self.0.to_be_bytes()
    }

    pub fn deserialize(bytes: [u8; Self::LEN]) -> Self {
        Self(u32::from_be_bytes(bytes))
    }
}

pub struct TxNumRange {
    first: TxNum,
    next: TxNum,
    len: u32,
}

impl TxNumRange {
    pub fn new(first: TxNum, next: TxNum) -> Self {
        let len = next.offset_from(first).expect("invalid range");
        Self { first, next, len }
    }

    pub fn adjacent(prev: &TxNumRange, next: &TxNumRange) -> bool {
        prev.next == next.first
    }

    pub fn len(&self) -> u32 {
        self.len
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

#[derive(PartialEq, Eq, Debug)]
pub struct BlockBytes(Vec<u8>);

impl BlockBytes {
    pub fn new(data: Vec<u8>) -> Self {
        BlockBytes(data)
    }

    pub fn header(&self) -> &[u8] {
        &self.0[..bitcoin::block::Header::SIZE]
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn txs_count(&self) -> u32 {
        parse_txs_count(&self.0[bitcoin::block::Header::SIZE..])
    }

    #[cfg(test)]
    pub fn txdata(&self) -> Vec<bitcoin::Transaction> {
        use bitcoin::consensus::encode::deserialize;

        let block: bitcoin::Block = deserialize(&self.0).expect("invalid block");
        block.txdata
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

    pub fn txs_count(&self) -> u32 {
        parse_txs_count(&self.0)
    }
}

fn parse_txs_count(slice: &[u8]) -> u32 {
    let mut consumed = 0;
    bsl::scan_len(slice, &mut consumed)
        .expect("cannot parse txs count")
        .try_into()
        .expect("txs count too large")
}

struct IndexedBlock<R> {
    next_txnum: TxNum,
    rows: Vec<R>,
}

impl<R> IndexedBlock<R> {
    fn new(next_txnum: TxNum) -> Self {
        Self {
            next_txnum,
            rows: vec![],
        }
    }
}

pub struct Batch {
    pub scripthash_rows: Vec<HashPrefixRow>,
    pub txid_rows: Vec<HashPrefixRow>,
    pub txpos_rows: Vec<txpos::TxBlockPosRow>,
    pub sptweak_rows: Vec<sptweak::TxTweakRow>,
    pub header: IndexedHeader,
}

pub struct Context(sptweak::Context);

impl Context {
    pub fn new() -> Self {
        Self(sptweak::Context::new())
    }

    pub fn index(
        &self,
        txnum_range: TxNumRange,
        blockhash: BlockHash,
        block: &BlockBytes,
        spent: &SpentBytes,
    ) -> Result<Batch, Error> {
        let first_txnum = txnum_range.first;
        let scripthash = scripthash::index(block, spent, first_txnum)?;
        let txpos = txpos::index(block, first_txnum)?;
        let txid = txid::index(block, first_txnum)?;
        let sptweak = self.0.index(block, spent, first_txnum)?;

        // All must have the same number of transactions
        assert_eq!(txnum_range.next, scripthash.next_txnum);
        assert_eq!(txnum_range.next, txpos.next_txnum);
        assert_eq!(txnum_range.next, txid.next_txnum);
        assert_eq!(txnum_range.next, sptweak.next_txnum);

        Ok(Batch {
            scripthash_rows: scripthash.rows,
            txpos_rows: txpos.rows,
            txid_rows: txid.rows,
            sptweak_rows: sptweak.rows,
            header: IndexedHeader::new(txnum_range.next, blockhash, block),
        })
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
