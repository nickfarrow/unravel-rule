//! The forward out of the hop address Y to the destination X, or to the exchange, with the
//! service fee as its own output.

use bitcoin::{
    Amount, FeeRate, OutPoint, ScriptBuf, Sequence, TapSighash, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
    transaction::Version,
};

/// Builds the forward of one deposit. `prevout.value` must be the amount that actually
/// arrived, since exchanges deduct their own fees.
///
/// `service_fee` adds the fee as its own output; `None` pays `x` alone.
///
/// Returns `None` if the deposit can't cover the service fee, the miner fee and a
/// non-dust payment to `x`.
pub fn build(
    deposit: OutPoint,
    prevout: &TxOut,
    x: ScriptBuf,
    service_fee: Option<(ScriptBuf, Amount)>,
    fee_rate: FeeRate,
) -> Option<Transaction> {
    let fee_amount = service_fee.as_ref().map_or(Amount::ZERO, |(_, fee)| *fee);
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: deposit,
            script_sig: ScriptBuf::new(),
            // Signals RBF, so the service can also replace the forward instead of CPFP.
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: dummy_key_spend_witness(),
        }],
        output: std::iter::once(TxOut {
            value: Amount::ZERO,
            script_pubkey: x,
        })
        .chain(service_fee.map(|(script_pubkey, value)| TxOut {
            value,
            script_pubkey,
        }))
        .collect(),
    };
    let miner_fee = fee_rate.fee_vb(tx.vsize() as u64)?;
    let to_x = prevout
        .value
        .checked_sub(fee_amount)?
        .checked_sub(miner_fee)?;
    if to_x < tx.output[0].script_pubkey.minimal_non_dust() {
        return None;
    }
    tx.output[0].value = to_x;
    tx.input[0].witness = Witness::new();
    Some(tx)
}

/// The key-path sighash for spending the single input. `SIGHASH_DEFAULT` commits to the
/// whole transaction and to the prevout's amount and script.
pub fn sighash(tx: &Transaction, prevout: &TxOut) -> TapSighash {
    SighashCache::new(tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .expect("one input with one prevout")
}

pub fn finalize(tx: &mut Transaction, signature: [u8; 64]) {
    let signature = taproot::Signature {
        signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
            .expect("64 bytes"),
        sighash_type: TapSighashType::Default,
    };
    tx.input[0].witness = Witness::p2tr_key_spend(&signature);
}

fn dummy_key_spend_witness() -> Witness {
    Witness::from_slice(&[[0u8; 64]])
}
