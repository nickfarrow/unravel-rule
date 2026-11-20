//! Emergency spend of the hop address Y through the hidden leaf, signed by the destination
//! X's own key.
//!
//! This is what a cold wallet would need to support. The leaf key is X's *tweaked* output
//! key, so the signer needs `q = d + t`: its plain secret `d` plus the BIP-86 tweak `t`.

use bitcoin::{
    Amount, FeeRate, OutPoint, PrivateKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    hashes::Hash,
    key::{Keypair, Parity, TapTweak, TweakedPublicKey},
    secp256k1::{Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{self, LeafVersion, TapLeafHash},
    transaction::Version,
};

use miniscript::{Descriptor, DescriptorPublicKey};

use crate::Deposit;

/// Sweeps one Y output to `destination` through the safety-net leaf.
///
/// `x_secret` is the untweaked secret key behind X (for example the BIP-86 child key a
/// software wallet derives from the seed). X must be a key-path-only (BIP-86) address.
/// Returns `None` when the fee would leave nothing or only dust, since nothing relays dust.
pub fn sweep(
    deposit: &Deposit,
    outpoint: OutPoint,
    prevout: &TxOut,
    destination: ScriptBuf,
    fee_rate: FeeRate,
    x_secret: SecretKey,
) -> Option<Transaction> {
    let secp = Secp256k1::new();
    let leaf = deposit.safety_net_leaf().clone();
    let control_block = deposit.safety_net_control_block();

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[
                vec![0u8; 64],
                leaf.to_bytes(),
                control_block.serialize(),
            ]),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: destination,
        }],
    };
    let miner_fee = fee_rate.fee_vb(tx.vsize() as u64)?;
    tx.output[0].value = prevout.value.checked_sub(miner_fee)?;
    // Nothing relays a dust output, so a sweep that leaves one is no sweep at all.
    if tx.output[0].value < tx.output[0].script_pubkey.minimal_non_dust() {
        return None;
    }

    let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("one input");

    let tweaked = tweaked(x_secret);
    let signature =
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &tweaked);
    let signature = taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    };

    tx.input[0].witness = Witness::from_slice(&[
        signature.to_vec(),
        leaf.to_bytes(),
        control_block.serialize(),
    ]);
    Some(tx)
}

/// Y's descriptor with the leaf's key as X's tweaked private key, in WIF. Bitcoin Core can
/// import it into a blank wallet and spend Y through the leaf, which no wallet does from a
/// seed. `None` if `x_secret` isn't the untweaked key behind X.
pub fn private_descriptor(deposit: &Deposit, x_secret: SecretKey) -> Option<String> {
    let secp = Secp256k1::new();
    let tweaked = tweaked(x_secret);
    let (q, parity) = tweaked.x_only_public_key();
    let x_spk = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(q));
    if x_spk != deposit.x().script_pubkey() {
        return None;
    }
    // The key whose full public key is the leaf's x-only one, so no signer has to negate it.
    let secret = match parity {
        Parity::Even => tweaked.secret_key(),
        Parity::Odd => tweaked.secret_key().negate(),
    };
    let network = deposit.network();
    let wif = PrivateKey::new(secret, network).to_wif();
    let internal = deposit.descriptor().strip_prefix("tr(")?.split_once(',')?.0;
    let (descriptor, keys) = Descriptor::<DescriptorPublicKey>::parse_descriptor(
        &secp,
        &format!("tr({internal},pk({wif}))"),
    )
    .ok()?;
    let address = descriptor
        .at_derivation_index(0)
        .ok()?
        .address(network)
        .ok()?;
    (address == deposit.address()).then(|| descriptor.to_string_with_secret(&keys))
}

/// X's tweaked key pair. BIP-86: no script tree, so the tweak commits to the internal key only.
fn tweaked(x_secret: SecretKey) -> Keypair {
    let secp = Secp256k1::new();
    Keypair::from_secret_key(&secp, &x_secret)
        .tap_tweak(&secp, None)
        .to_keypair()
}
