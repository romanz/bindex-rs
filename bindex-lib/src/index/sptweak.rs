use bitcoin::secp256k1::VerifyOnly;
use bitcoin::{consensus::Decodable, secp256k1, Transaction};
use bitcoin::{
    hashes::{sha256t_hash_newtype, Hash, HashEngine},
    OutPoint,
};
use secp256k1::{PublicKey, Scalar, Secp256k1, XOnlyPublicKey};

use crate::index::{BlockBytes, Error, IndexedBlock, Prefix, SpentBytes, TxNum};

use secp256k1::constants::PUBLIC_KEY_SIZE;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct TxTweakRow {
    data: [u8; Self::LEN],
}

impl TxTweakRow {
    const LEN: usize = Prefix::LEN + PUBLIC_KEY_SIZE;

    pub fn new(txid_prefix: Prefix, tweak: &PublicKey) -> Self {
        let mut data = [0u8; Self::LEN];
        data[..Prefix::LEN].copy_from_slice(txid_prefix.as_bytes());
        data[Prefix::LEN..].copy_from_slice(&tweak.serialize());
        Self { data }
    }

    pub fn serialize(&self) -> &[u8] {
        &self.data
    }

    pub fn deserialize(data: [u8; Self::LEN]) -> Self {
        Self { data }
    }

    pub fn prefix(&self) -> Prefix {
        Prefix::new(&self.data)
    }

    pub fn tweak(&self) -> PublicKey {
        PublicKey::from_slice(&self.data[Prefix::LEN..]).expect("invalid tweak")
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
            outpoint: self.outpoint.min(other.outpoint),
            pubkey: self.pubkey.combine(&other.pubkey)?,
        })
    }
}

pub struct Context(Secp256k1<VerifyOnly>);

impl Context {
    pub fn new() -> Self {
        Self(Secp256k1::verification_only())
    }

    pub fn index(
        &self,
        block: &BlockBytes,
        spent: &SpentBytes,
        next_txnum: TxNum,
    ) -> Result<IndexedBlock<TxTweakRow>, Error> {
        let mut result = IndexedBlock::new(next_txnum);
        let block = bitcoin::Block::consensus_decode_from_finite_reader(&mut &block.0[..])?;
        let spent = decode_spent(&spent.0)?;
        assert_eq!(block.txdata.len(), spent.len());
        for (tx, txouts_spent) in block.txdata.into_iter().zip(spent.into_iter()) {
            result.next_txnum.increment_by(1);
            if !maybe_silent_payment(&tx) {
                // no taproot outputs, or coinbase
                continue;
            }
            assert_eq!(tx.input.len(), txouts_spent.len());
            // let per_input_entries = tx.input.into_iter().zip(txouts_spent.into_iter());
            // Iterate through each input of the transaction and collect its eligible pubkey:
            let per_input_entries =
                tx.input
                    .iter()
                    .zip(txouts_spent.into_iter())
                    .filter_map(|(txin, spent_txout)| {
                        get_pubkey_from_input(txin, spent_txout).transpose()
                    });

            // Reduce into (smallest_outpoint, A_sum) pair:
            let total = match per_input_entries.into_iter().reduce(|a, b| a?.combine(b?)) {
                Some(Ok(total)) => total,
                Some(Err(err)) => {
                    log::warn!("skipping {}: {}", tx.compute_txid(), err);
                    continue;
                }
                None => continue,
            };
            // Calculate the tweak data based on the public keys and outpoints
            let tweak = self.compute_tweak(total);
            let txid = tx.compute_txid();
            result
                .rows
                .push(TxTweakRow::new(txid.to_raw_hash().into(), &tweak));
        }
        Ok(result)
    }

    fn compute_tweak(&self, total: PerInput) -> PublicKey {
        let PerInput {
            outpoint: smallest_outpoint,
            pubkey: sum_pubkeys,
        } = total;
        let input_hash = InputsHash::new(smallest_outpoint, sum_pubkeys).to_scalar();
        sum_pubkeys
            .mul_tweak(&self.0, &input_hash)
            .expect("`mul_tweak()` failed")
    }
}

fn maybe_silent_payment(tx: &Transaction) -> bool {
    if tx.is_coinbase() {
        return false;
    }
    tx.output.iter().any(|txo| txo.script_pubkey.is_p2tr())
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
    fn new(smallest_outpoint: &OutPoint, sum_pubkeys: PublicKey) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(&smallest_outpoint.txid[..]);
        eng.input(&smallest_outpoint.vout.to_le_bytes());
        eng.input(&sum_pubkeys.serialize());
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

// !!! The code below has been vendored from https://github.com/cygnet3/spdk/blob/ce68148d8621e58a33abe251e28b7587b04998dd/silentpayments/src/utils/receiving.rs !!!

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;

    use bitcoin::{hex::prelude::*, key::TweakedPublicKey, ScriptBuf};
    use hex_lit::hex;
    use secp256k1::SecretKey;
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct TestVector {
        bip352_tweaks: Vec<String>,
    }

    impl TestVector {
        fn read<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
            let data = std::fs::read(path)?;
            Ok(serde_json::from_slice(&data)?)
        }

        fn assert_equal(&self, indexed: &IndexedBlock<TxTweakRow>) {
            assert_eq!(self.bip352_tweaks.len(), indexed.rows.len());
            for (hex_tweak, row) in self.bip352_tweaks.iter().zip(&indexed.rows) {
                assert_eq!(*hex_tweak, row.tweak().serialize().to_lower_hex_string());
            }
        }
    }

    #[test]
    fn test_index_signet_block_200000() -> Result<(), Box<dyn std::error::Error>> {
        const TXS_COUNT: u32 = 141;
        let ctx = Context::new();

        // Generated by `curl -v http://localhost:38332/rest/block/0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c.bin`.
        let block_bytes = BlockBytes(std::fs::read("src/tests/signet/block_0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c.bin")?);
        assert_eq!(block_bytes.txs_count(), TXS_COUNT);

        // Generated by `curl -v http://localhost:38332/rest/spenttxouts/000000182c6f19960871023d851d2b758fc1123aa14645c56666e54673386780.bin`.
        let spent_bytes = SpentBytes(std::fs::read("src/tests/signet/spent_0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c.bin")?);
        assert_eq!(spent_bytes.txs_count(), TXS_COUNT);

        let mut txnum = TxNum(100000);
        let indexed = ctx.index(&block_bytes, &spent_bytes, txnum)?;
        txnum.increment_by(TXS_COUNT);
        assert_eq!(indexed.next_txnum, txnum);

        // Generated by `bitcoin-cli -signet getsilentpaymentblockdata 0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c`.
        // (https://github.com/Sjors/bitcoin/pull/86/changes/03ce1ad0a58c044937f51d67e5cad5ccc3f206b0)
        TestVector::read("src/tests/signet/bip352_tweaks_0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c.json")?.assert_equal(&indexed);
        Ok(())
    }

    #[test]
    fn test_scan_signet_block_295125() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Context::new();
        let secp = Secp256k1::new();

        let block_bytes = BlockBytes(std::fs::read("src/tests/signet/block_00000012c5a8005cd56f2cb97334b038fc6dc442c1c1682ba9065e4402b3eaa0.bin")?);
        let spent_bytes = SpentBytes(std::fs::read("src/tests/signet/spent_00000012c5a8005cd56f2cb97334b038fc6dc442c1c1682ba9065e4402b3eaa0.bin")?);
        let indexed = ctx.index(&block_bytes, &spent_bytes, TxNum::default())?;
        assert_eq!(indexed.next_txnum, TxNum(68));
        TestVector::read("src/tests/signet/bip352_tweaks_00000012c5a8005cd56f2cb97334b038fc6dc442c1c1682ba9065e4402b3eaa0.json")?.assert_equal(&indexed);

        let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let scan_pk = scan_sk.public_key(&secp);
        let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let spend_pk = spend_sk.public_key(&secp);

        use silentpayments::receiving::{Label, Receiver};

        let change_label = Label::new(scan_sk, 0);
        let recv = Receiver::new(
            0,
            scan_pk,
            spend_pk,
            change_label,
            silentpayments::Network::Testnet,
        )?;

        let txs: HashMap<Prefix, Transaction> = block_bytes
            .txdata()
            .into_iter()
            .map(|tx| (tx.compute_txid().to_raw_hash().into(), tx))
            .collect();

        let mut found = HashMap::<Option<Label>, Vec<(XOnlyPublicKey, Scalar)>>::new();
        for row in indexed.rows {
            let txouts = &txs.get(&row.prefix()).expect("missing tx").output[..];
            let shared = row.tweak().mul_tweak(&secp, &scan_sk.into()).unwrap();
            // Scan transaction for relevant P2TR public keys and key tweaks
            let matches = recv.scan_transaction(&shared, p2tr_pubkeys(&txouts))?;
            for (label, items) in matches {
                found.entry(label).or_default().extend(items.into_iter());
            }
        }
        assert_eq!(found.len(), 1);
        let pubkey = XOnlyPublicKey::from_slice(&hex!(
            "dbd93fdd869e3522405749a594c2e3f4833ac98d0f4e70da6e7294f6623258c3"
        ))
        .unwrap();
        let tweak = Scalar::from_be_bytes(hex!(
            "78258954dccdba6597729dab70068bc4353ebd046f7156d9a3f8db8438b62aa5"
        ))
        .unwrap();
        assert_eq!(found, HashMap::from_iter([(None, vec![(pubkey, tweak)])]));

        // Verify that tweaked spending secret key matches tweaked public key
        let tweaked_spend_sk = spend_sk.add_tweak(&tweak).unwrap();
        let tweaked_spend_pk = tweaked_spend_sk.x_only_public_key(&secp).0;
        assert_eq!(tweaked_spend_pk, pubkey);

        // Verify the relevant transaction (93a9b81f81244f8e6be29d8d6b0a9dbe6d6de6d2d4b018001ebf855bc870be88):
        assert_eq!(
            block_bytes.txdata()[33].output[0].script_pubkey,
            ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(pubkey))
        );
        Ok(())
    }

    fn p2tr_pubkeys(txos: &[bitcoin::TxOut]) -> Vec<XOnlyPublicKey> {
        txos.iter()
            .filter_map(|txo| {
                let script = &txo.script_pubkey;
                if !script.is_p2tr() {
                    return None;
                }
                let bytes = &script.as_bytes()[2..];
                Some(XOnlyPublicKey::from_slice(bytes).expect("invalid public key"))
            })
            .collect()
    }
}
