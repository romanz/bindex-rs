use bitcoin::Transaction;
use bitcoin::{consensus::Decodable, secp256k1, Txid};
use bitcoin::{
    hashes::{sha256t_hash_newtype, Hash, HashEngine},
    OutPoint,
};
use secp256k1::{PublicKey, Scalar};

use silentpayments::utils::receiving::get_pubkey_from_input;

use crate::index::{self, BlockBytes, Error, IndexedBlock, SpentBytes, TxNum};

pub struct TxTweakRow {
    pub txid: Txid,
    pub tweak: secp256k1::PublicKey,
}

impl TxTweakRow {
    const KEY_LEN: usize = TxNum::LEN + Txid::LEN;

    pub fn serialize(
        &self,
        header: &index::IndexedHeader,
    ) -> (
        [u8; Self::KEY_LEN],
        [u8; secp256k1::constants::PUBLIC_KEY_SIZE],
    ) {
        let mut key = [0; Self::KEY_LEN];
        key[..TxNum::LEN].copy_from_slice(&header.next_txnum().serialize());
        key[TxNum::LEN..].copy_from_slice(&self.txid[..]);
        (key, self.tweak.serialize())
    }
}

struct PerInput {
    outpoint: OutPoint,
    pubkey: PublicKey,
}

impl PerInput {
    fn new(txin: &bitcoin::TxIn, pubkey: PublicKey) -> Self {
        Self {
            outpoint: txin.previous_output,
            pubkey,
        }
    }

    fn combine(&self, other: &PerInput) -> Result<Self, secp256k1::Error> {
        Ok(PerInput {
            outpoint: self.outpoint.min(other.outpoint),
            pubkey: self.pubkey.combine(&other.pubkey)?,
        })
    }
}

pub fn index(
    block: &BlockBytes,
    spent: &SpentBytes,
    next_txnum: TxNum,
) -> Result<IndexedBlock<TxTweakRow>, Error> {
    let mut result = IndexedBlock::new(next_txnum);

    let secp = secp256k1::Secp256k1::verification_only(); // OPTIMIZE

    let block = bitcoin::Block::consensus_decode_from_finite_reader(&mut &block.0[..])?;
    let spent = decode_spent(&spent.0)?;
    assert_eq!(block.txdata.len(), spent.len());
    for (tx, txouts_spent) in block.txdata.into_iter().zip(spent.into_iter()) {
        result.next_txnum.increment();
        if !maybe_silent_payment(&tx) {
            continue;
        }
        assert_eq!(tx.input.len(), txouts_spent.len());

        // Iterate through each input of the transaction and collect its eligible pubkey:
        let per_input_entries =
            tx.input
                .iter()
                .zip(txouts_spent.into_iter())
                .filter_map(|(txin, spent_txout)| {
                    match get_pubkey_from_input(
                        txin.script_sig.as_bytes(),
                        &txin.witness.to_vec(),
                        spent_txout.script_pubkey.as_bytes(),
                    ) {
                        Ok(input_pubkey) => {
                            // return None if no matching output was found:
                            input_pubkey.map(|pubkey| Ok(PerInput::new(txin, pubkey)))
                        }
                        Err(err) => Some(Err(err)),
                    }
                });

        // Reduce into (smallest_outpoint, A_sum) pair:
        match per_input_entries.reduce(|a, b| Ok(a?.combine(&b?)?)) {
            Some(Ok(total)) => {
                let PerInput {
                    outpoint: smallest_outpoint,
                    pubkey: A_sum,
                } = total;
                // Calculate the tweak data based on the public keys and outpoints
                let input_hash = InputsHash::from_outpoint_and_A_sum(smallest_outpoint, A_sum);
                let tweak = A_sum
                    .mul_tweak(&secp, &input_hash.to_scalar())
                    .expect("`mul_tweak()` failed");
                let txid = tx.compute_txid();
                result.rows.push(TxTweakRow { txid, tweak });
            }
            Some(Err(err)) => log::warn!("txid {}: {}", tx.compute_txid(), err),
            None => (), // no relevant inputs
        };
    }
    Ok(result)
}

fn maybe_silent_payment(tx: &Transaction) -> bool {
    if tx.is_coinbase() {
        return false;
    }
    return tx.output.iter().any(|txo| txo.script_pubkey.is_p2tr());
}

sha256t_hash_newtype! {
    pub(crate) struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    pub(crate) struct InputsHash(_);
}

impl InputsHash {
    fn from_outpoint_and_A_sum(smallest_outpoint: OutPoint, A_sum: PublicKey) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(&smallest_outpoint.txid[..]);
        eng.input(&smallest_outpoint.vout.to_le_bytes());
        eng.input(&A_sum.serialize());
        InputsHash::from_engine(eng)
    }
    fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

fn decode_spent(buf: &[u8]) -> Result<Vec<Vec<bitcoin::TxOut>>, Error> {
    let mut r = bitcoin::io::Cursor::new(buf);
    let txs_count = bitcoin::VarInt::consensus_decode_from_finite_reader(&mut r)?.0 as usize;
    let mut block_result = Vec::with_capacity(txs_count);
    for _ in 0..txs_count {
        let outputs_count =
            bitcoin::VarInt::consensus_decode_from_finite_reader(&mut r)?.0 as usize;
        let mut tx_result = Vec::with_capacity(outputs_count);
        for _ in 0..outputs_count {
            let output = bitcoin::TxOut::consensus_decode_from_finite_reader(&mut r)?;
            tx_result.push(output);
        }
        block_result.push(tx_result);
    }
    Ok(block_result)
}
