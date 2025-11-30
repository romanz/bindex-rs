use bitcoin::{consensus::Encodable as _, hashes::Hash as _, BlockHash};

use crate::index::TxNum;

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
    pub fn new(
        next_txnum: TxNum,
        hash: bitcoin::BlockHash,
        header: bitcoin::block::Header,
    ) -> Self {
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
            next_txnum: TxNum::deserialize(key),
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
