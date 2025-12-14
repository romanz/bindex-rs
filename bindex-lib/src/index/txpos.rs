use std::ops::ControlFlow;

use super::{BlockBytes, BlockIndex, Error, TxNum};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin_slices::{bsl, Visit as _};

/// Transaction position within a block.
/// It is used for fetching the transaction bytes via `/blockpart` REST API.
#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct TxBlockPos {
    pub offset: u32,
    pub size: u32,
}

/// Allows efficient encoding of ascending offsets' list.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Offsets(Vec<u32>);

impl Offsets {
    fn get_tx_block_pos(&self, i: usize) -> TxBlockPos {
        let begin = self.0[i];
        let end = self.0[i + 1];
        TxBlockPos {
            offset: begin,
            size: end - begin,
        }
    }
}

impl Encodable for Offsets {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        w: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;

        let offsets_len = self.0.len();
        // last offset is used only for encoding the last transaction size
        let txs_count = offsets_len.checked_sub(1).expect("no offsets");
        // only small (<256) chunks of transactions are supported
        let sizes_count = u8::try_from(txs_count).expect("too many transactions");
        // serialize transaction's count
        len += sizes_count.consensus_encode(w)?;

        // compute transactions' sizes
        let iter_sizes = || self.0.windows(2).map(|pair| pair[1] - pair[0]);

        // compute and serialize minimal transaction size (for delta encoding)
        let min_tx_size = iter_sizes().min().expect("no transactions");
        len += bitcoin::VarInt(min_tx_size.into()).consensus_encode(w)?;
        // serialize first transaction's offset
        len += bitcoin::VarInt(self.0.first().copied().expect("no offsets").into())
            .consensus_encode(w)?;

        // serialize transactions' (delta-)sizes
        for tx_size in iter_sizes() {
            let delta_from_min = tx_size - min_tx_size;
            len += bitcoin::VarInt(delta_from_min.into()).consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for Offsets {
    #[inline]
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        // deserialize transaction's count
        let sizes_count = u8::consensus_decode_from_finite_reader(r)?;
        let mut offsets = Vec::with_capacity(usize::from(sizes_count) + 1);

        // deserialize minimal transaction size (for delta decoding)
        let min_tx_size: u32 = bitcoin::VarInt::consensus_decode_from_finite_reader(r)?
            .0
            .try_into()
            .expect("too large min_tx_size");

        // deserialize first transaction's offset
        let mut offset: u32 = bitcoin::VarInt::consensus_decode_from_finite_reader(r)?
            .0
            .try_into()
            .expect("too large first offset");

        offsets.push(offset);
        // decode transactions' sizes and offsets
        for _ in 0..sizes_count {
            let delta_from_min: u32 = bitcoin::VarInt::consensus_decode_from_finite_reader(r)?
                .0
                .try_into()
                .expect("too large delta_from_min");
            offset += min_tx_size + delta_from_min;
            offsets.push(offset);
        }
        Ok(Offsets(offsets))
    }
}

/// Chunk of ascending transaction offsets.
/// It is used for efficient encoding for DB storage.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxBlockPosRow {
    last_txnum: TxNum, // key = maximal txnum in this row
    offsets: Offsets,  // value = N+1 offsets (for N transactions)
}

impl TxBlockPosRow {
    fn new(last_txnum: TxNum, offsets: Vec<u32>) -> Self {
        Self {
            last_txnum,
            offsets: Offsets(offsets),
        }
    }

    const CHUNK_SIZE: usize = 64;

    /// Chunkify `positions` into a list of `TxBlockPosRow` entries.
    fn chunkify(positions: &[(TxNum, TxBlockPos)]) -> Vec<TxBlockPosRow> {
        for pair in positions.windows(2) {
            let (prev_num, prev_pos) = pair[0];
            let (next_num, next_pos) = pair[1];
            assert_eq!(next_num.offset_from(prev_num), Some(1));
            assert_eq!(prev_pos.offset + prev_pos.size, next_pos.offset);
        }
        positions
            .chunks(Self::CHUNK_SIZE)
            .map(|chunk| {
                let (last_txnum, last_txpos) = *chunk.last().expect("empty chunk");
                let mut offsets = Vec::with_capacity(chunk.len() + 1);
                offsets.extend(chunk.iter().map(|(_, txpos)| txpos.offset));
                offsets.push(last_txpos.offset + last_txpos.size); //  last tx ending offset
                TxBlockPosRow::new(last_txnum, offsets) // last tx num (for query optimization)
            })
            .collect()
    }

    pub fn get_tx_block_pos(&self, txnum: TxNum) -> TxBlockPos {
        let last_index = self.offsets.0.len().checked_sub(1).expect("empty Offsets");
        let delta_from_last = self.last_txnum.offset_from(txnum).expect("TxNum too large") as usize;
        self.offsets.get_tx_block_pos(
            last_index
                .checked_sub(delta_from_last + 1)
                .expect("TxNum too small"),
        )
    }

    pub fn serialize(&self) -> ([u8; TxNum::LEN], Vec<u8>) {
        let key = self.last_txnum.serialize();
        let value = bitcoin::consensus::serialize(&self.offsets);
        (key, value)
    }

    pub fn deserialize(key: &[u8], value: &[u8]) -> Self {
        Self {
            last_txnum: TxNum::deserialize(key.try_into().expect("invalid TxNum")),
            offsets: Offsets::consensus_decode_from_finite_reader(&mut &value[..])
                .expect("invalid Offsets"),
        }
    }
}

struct TxPosVisitor<'a> {
    positions: &'a mut Vec<(TxNum, TxBlockPos)>,
    tx_num: TxNum,
    tx_offset: u32,
}

impl<'a> TxPosVisitor<'a> {
    fn new(positions: &'a mut Vec<(TxNum, TxBlockPos)>, tx_num: TxNum) -> Self {
        Self {
            positions,
            tx_num,
            tx_offset: bitcoin::block::Header::SIZE as u32,
        }
    }
}

impl bitcoin_slices::Visitor for TxPosVisitor<'_> {
    fn visit_block_begin(&mut self, n: usize) {
        self.tx_offset += bitcoin::VarInt(n as u64).size() as u32;
    }

    fn visit_transaction(&mut self, tx: &bsl::Transaction) -> ControlFlow<()> {
        // Updated after all txouts are scanned
        let tx_size = tx.as_ref().len() as u32;
        let tx_pos = TxBlockPos {
            offset: self.tx_offset,
            size: tx_size,
        };
        self.positions.push((self.tx_num, tx_pos));
        self.tx_num.0 += 1;
        self.tx_offset += tx_size;
        ControlFlow::Continue(())
    }
}

pub fn index(block: &BlockBytes, txnum: TxNum) -> Result<BlockIndex<TxBlockPosRow>, Error> {
    let mut positions = vec![];
    let mut visitor = TxPosVisitor::new(&mut positions, txnum);
    let res = bsl::Block::visit(&block.0, &mut visitor).map_err(Error::Parse)?;
    if !res.remaining().is_empty() {
        return Err(Error::Leftover(res.remaining().len()));
    }
    Ok(BlockIndex {
        next_txnum: visitor.tx_num,
        rows: TxBlockPosRow::chunkify(&positions),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_txposrow() {
        let row = TxBlockPosRow::new(TxNum(103), vec![10, 11, 13, 16, 20]);
        assert_eq!(
            row.get_tx_block_pos(TxNum(100)),
            TxBlockPos {
                offset: 10,
                size: 1
            }
        );
        assert_eq!(
            row.get_tx_block_pos(TxNum(101)),
            TxBlockPos {
                offset: 11,
                size: 2
            }
        );
        assert_eq!(
            row.get_tx_block_pos(TxNum(102)),
            TxBlockPos {
                offset: 13,
                size: 3
            }
        );
        assert_eq!(
            row.get_tx_block_pos(TxNum(103)),
            TxBlockPos {
                offset: 16,
                size: 4
            }
        );
        let (key, value) = row.serialize();
        assert_eq!(TxBlockPosRow::deserialize(&key, &value), row);
    }

    #[test]
    fn test_get_txpos() {
        let rows = TxBlockPosRow::chunkify(
            &(0..1000u16)
                .map(|i| {
                    (
                        TxNum(i.into()),
                        TxBlockPos {
                            offset: u32::from(i) * 10,
                            size: 10,
                        },
                    )
                })
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            rows[0].get_tx_block_pos(TxNum(50)),
            TxBlockPos {
                offset: 500,
                size: 10
            }
        );
        assert_eq!(
            rows[1].get_tx_block_pos(TxNum(100)),
            TxBlockPos {
                offset: 1000,
                size: 10
            }
        );
        assert_eq!(
            rows[1].get_tx_block_pos(TxNum(127)),
            TxBlockPos {
                offset: 1270,
                size: 10
            }
        );
        assert_eq!(
            rows[2].get_tx_block_pos(TxNum(128)),
            TxBlockPos {
                offset: 1280,
                size: 10
            }
        );
    }
}
