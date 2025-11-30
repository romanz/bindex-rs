use std::ops::ControlFlow;

use super::{BlockBytes, Error, TxNum};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin_slices::{bsl, Visit as _};

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub struct TxPos {
    pub offset: u32,
    pub size: u32,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Offsets(Vec<u32>);

impl Offsets {
    fn get_tx_pos(&self, i: usize) -> TxPos {
        let begin = self.0[i];
        let end = self.0[i + 1];
        TxPos {
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

        // only small chunks of offsets are supported (<=256)
        let sizes_count: u8 = self
            .0
            .len()
            .checked_sub(1)
            .expect("no transactions")
            .try_into()
            .expect("too many offsets");
        len += sizes_count.consensus_encode(w)?;

        let iter_sizes = || self.0.windows(2).map(|pair| pair[1] - pair[0]);

        let min_tx_size = iter_sizes().min().expect("no transactions");
        len += bitcoin::VarInt(min_tx_size.into()).consensus_encode(w)?;
        len += bitcoin::VarInt(self.0.first().copied().expect("no offsets").into())
            .consensus_encode(w)?;

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
        let sizes_count = u8::consensus_decode_from_finite_reader(r)?;
        let mut offsets = Vec::with_capacity(usize::from(sizes_count) + 1);

        let min_tx_size: u32 = bitcoin::VarInt::consensus_decode_from_finite_reader(r)?
            .0
            .try_into()
            .expect("too large min_tx_size");

        let mut offset: u32 = bitcoin::VarInt::consensus_decode_from_finite_reader(r)?
            .0
            .try_into()
            .expect("too large first offset");

        offsets.push(offset);
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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxPosRow {
    last_txnum: TxNum, // = maximal txnum in this row
    offsets: Offsets,  // = N+1 offsets (for N transactions)
}

impl TxPosRow {
    fn new(last_txnum: TxNum, offsets: Vec<u32>) -> Self {
        Self {
            last_txnum,
            offsets: Offsets(offsets),
        }
    }

    const CHUNK_SIZE: usize = 64;

    fn group(positions: &[(TxNum, TxPos)]) -> Vec<TxPosRow> {
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
                TxPosRow::new(last_txnum, offsets) // last tx num (for query optimization)
            })
            .collect()
    }

    pub fn get_tx_pos(&self, txnum: TxNum) -> TxPos {
        let last_index = self.offsets.0.len().checked_sub(1).expect("empty Offsets");
        let delta_from_last = self.last_txnum.offset_from(txnum).expect("TxNum too large") as usize;
        self.offsets.get_tx_pos(
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
    positions: &'a mut Vec<(TxNum, TxPos)>,
    tx_num: TxNum,
    tx_offset: u32,
}

impl<'a> TxPosVisitor<'a> {
    fn new(positions: &'a mut Vec<(TxNum, TxPos)>, tx_num: TxNum) -> Self {
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
        let tx_pos = TxPos {
            offset: self.tx_offset,
            size: tx_size,
        };
        self.positions.push((self.tx_num, tx_pos));
        self.tx_num.0 += 1;
        self.tx_offset += tx_size;
        ControlFlow::Continue(())
    }
}

pub fn add_txpos_rows(
    block: &BlockBytes,
    tx_num: TxNum,
    txpos_rows: &mut Vec<TxPosRow>,
) -> Result<TxNum, Error> {
    let mut positions = vec![];
    let mut visitor = TxPosVisitor::new(&mut positions, tx_num);
    let res = bsl::Block::visit(&block.0, &mut visitor).map_err(Error::Parse)?;
    if !res.remaining().is_empty() {
        return Err(Error::Leftover(res.remaining().len()));
    }
    let next_txnum = visitor.tx_num;
    *txpos_rows = TxPosRow::group(&positions);
    Ok(next_txnum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_txposrow() {
        let row = TxPosRow::new(TxNum(103), vec![10, 11, 13, 16, 20]);
        assert_eq!(
            row.get_tx_pos(TxNum(100)),
            TxPos {
                offset: 10,
                size: 1
            }
        );
        assert_eq!(
            row.get_tx_pos(TxNum(101)),
            TxPos {
                offset: 11,
                size: 2
            }
        );
        assert_eq!(
            row.get_tx_pos(TxNum(102)),
            TxPos {
                offset: 13,
                size: 3
            }
        );
        assert_eq!(
            row.get_tx_pos(TxNum(103)),
            TxPos {
                offset: 16,
                size: 4
            }
        );
        let (key, value) = row.serialize();
        assert_eq!(TxPosRow::deserialize(&key, &value), row);
    }

    #[test]
    fn test_get_txpos() {
        let rows = TxPosRow::group(
            &(0..1000u16)
                .map(|i| {
                    (
                        TxNum(i.into()),
                        TxPos {
                            offset: u32::from(i) * 10,
                            size: 10,
                        },
                    )
                })
                .collect::<Vec<_>>(),
        );
        assert_eq!(
            rows[0].get_tx_pos(TxNum(50)),
            TxPos {
                offset: 500,
                size: 10
            }
        );
        assert_eq!(
            rows[1].get_tx_pos(TxNum(100)),
            TxPos {
                offset: 1000,
                size: 10
            }
        );
        assert_eq!(
            rows[1].get_tx_pos(TxNum(127)),
            TxPos {
                offset: 1270,
                size: 10
            }
        );
        assert_eq!(
            rows[2].get_tx_pos(TxNum(128)),
            TxPos {
                offset: 1280,
                size: 10
            }
        );
    }
}
