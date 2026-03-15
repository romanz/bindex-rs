use bitcoin::Transaction;
use bitcoin::{consensus::Decodable, secp256k1, Txid};
use bitcoin::{
    hashes::{sha256t_hash_newtype, Hash, HashEngine},
    OutPoint,
};
use secp256k1::{PublicKey, Scalar};

use crate::index::{self, BlockBytes, Error, IndexedBlock, SpentBytes, TxNum};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct TxTweakRow {
    pub txid: Txid,
    pub tweak: secp256k1::PublicKey,
}

impl TxTweakRow {
    const TXID_PREFIX_LEN: usize = 8;
    const KEY_LEN: usize = TxNum::LEN + Self::TXID_PREFIX_LEN;
    const LEN: usize = Self::KEY_LEN + secp256k1::constants::PUBLIC_KEY_SIZE;

    pub fn serialize(&self, header: &index::IndexedHeader) -> [u8; Self::LEN] {
        let mut key = [0; Self::LEN];
        // group by block height + order by txid prefix

        key[..TxNum::LEN].copy_from_slice(&header.next_txnum().serialize());
        key[TxNum::LEN..Self::KEY_LEN].copy_from_slice(&self.txid[..Self::TXID_PREFIX_LEN]);
        key[Self::KEY_LEN..].copy_from_slice(&self.tweak.serialize());
        key
    }
}

struct PerInput<'a> {
    outpoint: &'a OutPoint,
    pubkey: PublicKey,
}

impl<'a> PerInput<'a> {
    fn new(txin: &'a bitcoin::TxIn, pubkey: PublicKey) -> Self {
        Self {
            outpoint: &txin.previous_output,
            pubkey,
        }
    }

    fn combine(self, other: PerInput<'a>) -> Result<Self, SpError> {
        Ok(PerInput {
            outpoint: self.outpoint.min(&other.outpoint),
            pubkey: self.pubkey.combine(&other.pubkey)?,
        })
    }
}

pub fn index(
    block: &BlockBytes,
    spent: &SpentBytes,
    next_txnum: TxNum,
) -> Result<IndexedBlock<TxTweakRow>, Error> {
    let secp = secp256k1::Secp256k1::verification_only(); // OPTIMIZE
    let mut result = IndexedBlock::new(next_txnum);
    let block = bitcoin::Block::consensus_decode_from_finite_reader(&mut &block.0[..])?;
    let spent = decode_spent(&spent.0)?;
    assert_eq!(block.txdata.len(), spent.len());
    for (tx, txouts_spent) in block.txdata.into_iter().zip(spent.into_iter()) {
        result.next_txnum.increment();
        if !maybe_silent_payment(&tx) {
            // no taproot outputs, or coinbase
            continue;
        }
        assert_eq!(tx.input.len(), txouts_spent.len());
        // let per_input_entries = tx.input.into_iter().zip(txouts_spent.into_iter());
        // Iterate through each input of the transaction and collect its eligible pubkey:
        let per_input_entries = tx
            .input
            .iter()
            .zip(txouts_spent.into_iter())
            .filter_map(|(txin, spent_txout)| get_pubkey_from_input(txin, spent_txout).transpose());

        // Reduce into (smallest_outpoint, A_sum) pair:
        let PerInput {
            outpoint: smallest_outpoint,
            pubkey: A_sum,
        } = match per_input_entries.into_iter().reduce(|a, b| a?.combine(b?)) {
            Some(Ok(total)) => total,
            Some(Err(err)) => {
                log::warn!("skipping {}: {}", tx.compute_txid(), err);
                continue;
            }
            None => continue,
        };
        // Calculate the tweak data based on the public keys and outpoints
        let input_hash = InputsHash::from_outpoint_and_A_sum(smallest_outpoint, A_sum).to_scalar();
        let tweak = A_sum
            .mul_tweak(&secp, &input_hash)
            .expect("`mul_tweak()` failed");
        let txid = tx.compute_txid();
        result.rows.push(TxTweakRow { txid, tweak });
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
    fn from_outpoint_and_A_sum(smallest_outpoint: &OutPoint, A_sum: PublicKey) -> InputsHash {
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

/// [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)-defined 'Nothing Up My Sleeve' point.
pub const NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

// Define OP_CODES used in script template matching for readability
const OP_1: u8 = 0x51;
const OP_0: u8 = 0x00;
const OP_PUSHBYTES_20: u8 = 0x14;
const OP_PUSHBYTES_32: u8 = 0x20;
const OP_HASH160: u8 = 0xA9;
const OP_EQUAL: u8 = 0x87;
const OP_DUP: u8 = 0x76;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSIG: u8 = 0xAC;

// Only compressed pubkeys are supported for silent payments
const COMPRESSED_PUBKEY_SIZE: usize = 33;

#[derive(thiserror::Error, Debug)]
enum SpError {
    #[error("invalid vin: {0}")]
    InvalidVin(&'static str),
    #[error("secp256k1 error: {0}")]
    Secp256k1Error(#[from] secp256k1::Error),
}

/// Get the public keys from a set of input data.
///
/// # Arguments
///
/// * `script_sig` - The script signature as a byte array.
/// * `txinwitness` - The witness data.
/// * `script_pub_key` - The scriptpubkey from the output spent. This requires looking up the previous output.
///
/// # Returns
///
/// If no errors occur, this function will optionally return a [PublicKey] if this input is silent payment-eligible.
///
/// # Errors
///
/// This function will error if:
///
/// * The provided Vin data is incorrect.
fn get_pubkey_from_input(
    txin: &bitcoin::TxIn,
    spent_txout: bitcoin::TxOut,
) -> Result<Option<PerInput<'_>>, SpError> {
    use bitcoin::hashes::{hash160, Hash};
    use secp256k1::PublicKey;
    use secp256k1::XOnlyPublicKey;

    let txinwitness = &txin.witness;
    let script_sig = txin.script_sig.as_bytes();
    let script_pub_key = spent_txout.script_pubkey.as_bytes();

    if is_p2pkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (true, false) => {
                let spk_hash = &script_pub_key[3..23];
                for i in (COMPRESSED_PUBKEY_SIZE..=script_sig.len()).rev() {
                    if let Some(pubkey_bytes) = script_sig.get(i - COMPRESSED_PUBKEY_SIZE..i) {
                        let pubkey_hash = hash160::Hash::hash(pubkey_bytes);
                        if &pubkey_hash[..] == spk_hash {
                            let pubkey = PublicKey::from_slice(pubkey_bytes)
                                .map_err(SpError::Secp256k1Error)?;
                            return Ok(Some(PerInput::new(txin, pubkey)));
                        }
                    } else {
                        return Ok(None);
                    }
                }
            }
            (_, true) => return Err(SpError::InvalidVin("Empty script_sig for spending a p2pkh")),
            (false, _) => {
                return Err(SpError::InvalidVin(
                    "non empty witness for spending a p2pkh",
                ))
            }
        }
    } else if is_p2sh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, false) => {
                let redeem_script = &script_sig[1..];
                if is_p2wpkh(redeem_script) {
                    if let Some(value) = txinwitness.last() {
                        match (
                            PublicKey::from_slice(value),
                            value.len() == COMPRESSED_PUBKEY_SIZE,
                        ) {
                            (Ok(pubkey), true) => {
                                return Ok(Some(PerInput::new(txin, pubkey)));
                            }
                            (_, false) => {
                                return Ok(None);
                            }
                            // Not sure how we could get an error here, so just return none for now
                            // if the pubkey cant be parsed
                            (Err(_), _) => {
                                return Ok(None);
                            }
                        }
                    }
                }
            }
            (_, true) => return Err(SpError::InvalidVin("Empty script_sig for spending a p2sh")),
            (true, false) => return Ok(None),
        }
    } else if is_p2wpkh(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                if let Some(value) = txinwitness.last() {
                    match (
                        PublicKey::from_slice(value),
                        value.len() == COMPRESSED_PUBKEY_SIZE,
                    ) {
                        (Ok(pubkey), true) => {
                            return Ok(Some(PerInput::new(txin, pubkey)));
                        }
                        (_, false) => {
                            return Ok(None);
                        }
                        // Not sure how we could get an error here, so just return none for now
                        // if the pubkey cant be parsed
                        (Err(_), _) => {
                            return Ok(None);
                        }
                    }
                } else {
                    return Err(SpError::InvalidVin("Empty witness"));
                }
            }
            (_, false) => {
                return Err(SpError::InvalidVin(
                    "Non empty script sig for spending a segwit output",
                ))
            }
            (true, _) => {
                return Err(SpError::InvalidVin(
                    "Empty witness for spending a segwit output",
                ))
            }
        }
    } else if is_p2tr(script_pub_key) {
        match (txinwitness.is_empty(), script_sig.is_empty()) {
            (false, true) => {
                // check for the optional annex
                let annex = match txinwitness.last().and_then(|value| value.first()) {
                    Some(&0x50) => 1,
                    Some(_) => 0,
                    None => return Err(SpError::InvalidVin("Empty or invalid witness")),
                };

                // Check for script path
                let stack_size = txinwitness.len();
                if stack_size > annex && txinwitness[stack_size - annex - 1][1..33] == NUMS_H {
                    return Ok(None);
                }

                // Return the pubkey from the script pubkey
                return XOnlyPublicKey::from_slice(&script_pub_key[2..34])
                    .map_err(SpError::Secp256k1Error)
                    .map(|x_only_public_key| {
                        Some(PerInput::new(
                            txin,
                            x_only_public_key.public_key(secp256k1::Parity::Even),
                        ))
                    });
            }
            (_, false) => {
                return Err(SpError::InvalidVin(
                    "Non empty script sig for spending a segwit output",
                ))
            }
            (true, _) => {
                return Err(SpError::InvalidVin(
                    "Empty witness for spending a segwit output",
                ))
            }
        }
    }
    Ok(None)
}

// script templates for inputs allowed in BIP352 shared secret derivation

/// Check if a script_pub_key is taproot.
fn is_p2tr(spk: &[u8]) -> bool {
    matches!(spk, [OP_1, OP_PUSHBYTES_32, ..] if spk.len() == 34)
}

fn is_p2wpkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_0, OP_PUSHBYTES_20, ..] if spk.len() == 22)
}

fn is_p2sh(spk: &[u8]) -> bool {
    matches!(spk, [OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUAL] if spk.len() == 23)
}

fn is_p2pkh(spk: &[u8]) -> bool {
    matches!(spk, [OP_DUP, OP_HASH160, OP_PUSHBYTES_20, .., OP_EQUALVERIFY, OP_CHECKSIG] if spk.len() == 25)
}
