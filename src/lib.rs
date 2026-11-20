//! The hop address described in the README.
//!
//! The hop address Y is a taproot output. Its key path is MuSig2(U, S), the browser key U
//! and the server key S combined into one shared key. Its single leaf, the safety net, is
//! `<Q> OP_CHECKSIG`, where Q is the output key read from the destination X.

pub mod bip322;
pub mod deposit;
pub mod forward;
pub mod pow;
pub mod protocol;
pub mod rescue;
pub mod safety_net;
pub mod watch;

pub use deposit::Deposit;
pub use rescue::RescueKey;

use schnorr_fun::{musig, nonce};
use sha2::Sha256;

pub type MuSig =
    musig::MuSig<Sha256, nonce::Synthetic<Sha256, nonce::GlobalRng<rand::rngs::ThreadRng>>>;

pub fn musig() -> MuSig {
    musig::new_with_synthetic_nonces::<Sha256, rand::rngs::ThreadRng>()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The destination X is not a valid `bc1p` address on the expected network.
    NotTaproot,
    /// The request doesn't match what this party agreed to sign.
    Refused(&'static str),
    /// No pending session with this id: it finished already or never existed.
    UnknownSession,
    /// The other party's partial signature didn't verify.
    BadPartialSignature,
    /// The rescue key has the wrong length, a non-hex character or a bad checksum.
    BadRescueKey,
    /// The exchange's deposit address isn't an address on the expected network.
    BadExchangeAddress,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::NotTaproot => write!(
                f,
                "the destination must be a taproot address (bc1p…)"
            ),
            Error::Refused(why) => write!(f, "refused to sign: {why}"),
            Error::UnknownSession => write!(f, "unknown or finished signing session"),
            Error::BadPartialSignature => write!(f, "partial signature did not verify"),
            Error::BadRescueKey => write!(f, "that rescue key has a typo"),
            Error::BadExchangeAddress => write!(
                f,
                "the exchange's deposit address isn't a bitcoin address on this network"
            ),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
pub(crate) mod test_util {
    use bitcoin::{Address, Network, key::Keypair, secp256k1::Secp256k1};
    use schnorr_fun::fun::{Point, Scalar};

    pub fn random_point() -> Point {
        crate::musig()
            .new_keypair(Scalar::random(&mut rand::thread_rng()))
            .public_key()
    }

    /// A BIP-86 regtest address.
    pub fn random_x() -> String {
        let secp = Secp256k1::new();
        let (xonly, _) = Keypair::new(&secp, &mut rand::thread_rng()).x_only_public_key();
        Address::p2tr(&secp, xonly, None, Network::Regtest).to_string()
    }
}
