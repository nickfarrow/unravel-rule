//! BIP-322 "simple" signatures for a P2TR key path.

use bitcoin::{
    Address, TapSighash, Witness,
    base64::{Engine, engine::general_purpose::STANDARD},
    consensus::Encodable,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
};

/// Sparrow signs taproot BIP-322 with `SIGHASH_ALL` (a 65-byte signature), and Bitaroo
/// accepts Sparrow's signatures, so match it.
pub const SIGHASH_TYPE: TapSighashType = TapSighashType::All;

/// The `to_sign` sighash that the hop address Y's key signs for `message`.
pub fn sighash(y: &Address, message: &str) -> TapSighash {
    sighash_with(y, message, SIGHASH_TYPE)
}

fn sighash_with(y: &Address, message: &str, sighash_type: TapSighashType) -> TapSighash {
    let to_spend = ::bip322::create_to_spend(y, message).expect("infallible");
    let to_sign = ::bip322::create_to_sign(&to_spend, None, Default::default())
        .expect("infallible")
        .unsigned_tx;
    SighashCache::new(&to_sign)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&to_spend.output), sighash_type)
        .expect("one input")
}

pub fn witness(signature: [u8; 64]) -> Witness {
    let signature = taproot::Signature {
        signature: bitcoin::secp256k1::schnorr::Signature::from_slice(&signature)
            .expect("64 bytes"),
        sighash_type: SIGHASH_TYPE,
    };
    Witness::p2tr_key_spend(&signature)
}

/// Base64 of the consensus-encoded witness, the form wallets and exchanges paste.
///
/// BIP-322 v2 adds an optional `smp` prefix. It is left off because older verifiers
/// (Sparrow, and probably exchanges) don't expect it.
pub fn encode(witness: &Witness) -> String {
    let mut bytes = vec![];
    witness.consensus_encode(&mut bytes).expect("vec write");
    STANDARD.encode(bytes)
}

/// Vectors from the BIP's `basic-test-vectors.json`. They check the virtual transactions
/// independently of the `bip322` crate, which both our signer and our verifier use.
#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::{
        consensus::Decodable,
        hashes::Hash,
        secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr},
    };

    fn address(s: &str) -> Address {
        s.parse::<Address<_>>().unwrap().assume_checked()
    }

    #[test]
    fn virtual_transactions_match_spec() {
        let a = address("bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l");
        for (message, to_spend_txid, to_sign_txid) in [
            (
                "",
                "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
                "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6",
            ),
            (
                "Hello World",
                "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
                "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf",
            ),
        ] {
            let to_spend = ::bip322::create_to_spend(&a, message).unwrap();
            let to_sign = ::bip322::create_to_sign(&to_spend, None, Default::default())
                .unwrap()
                .unsigned_tx;
            assert_eq!(to_spend.compute_txid().to_string(), to_spend_txid);
            assert_eq!(to_sign.compute_txid().to_string(), to_sign_txid);
        }
    }

    #[test]
    fn taproot_vector_signature_verifies_against_our_sighash() {
        let y = address("bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler");
        let message = "No prefix fallback";
        let encoded = "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R";
        let witness =
            Witness::consensus_decode(&mut STANDARD.decode(encoded).unwrap().as_slice()).unwrap();
        let signature = schnorr::Signature::from_slice(&witness[0]).unwrap();
        let key = XOnlyPublicKey::from_slice(&y.script_pubkey().as_bytes()[2..]).unwrap();
        let sighash = sighash_with(&y, message, TapSighashType::Default);
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                &Message::from_digest(sighash.to_byte_array()),
                &key,
            )
            .unwrap();
        // And re-encoding the witness gives back the vector byte for byte.
        assert_eq!(encode(&witness), encoded);
    }
}
