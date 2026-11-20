use bitcoin::{
    Address, AddressType, Network, Script, ScriptBuf, WitnessVersion,
    hashes::Hash,
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::{ControlBlock, LeafVersion, TaprootBuilder, TaprootSpendInfo},
};
use miniscript::Descriptor;
use schnorr_fun::{
    fun::{G, Point, Scalar, g, marker::*},
    musig::AggKey,
};
use sha2::{Digest, Sha256};

use crate::{Error, MuSig};

/// The hop address Y for one destination X.
#[derive(Clone, Debug)]
pub struct Deposit {
    x: Address,
    /// The exchange's deposit address, for a hop address that deposits to an exchange.
    exchange: Option<Address>,
    /// What the server key S is offset by in this hop address's shared key. Only a hop
    /// address with an exchange has one.
    service_tweak: Option<Scalar<Public, Zero>>,
    /// The shared key MuSig2(U, S) of the browser key U and the server key S, with the
    /// BIP-341 tweak applied so it signs for Y's output key.
    signing_key: AggKey<EvenY>,
    spend_info: TaprootSpendInfo,
    leaf: ScriptBuf,
    network: Network,
    descriptor: String,
}

/// Index of each party in the MuSig2 key list. Both sides must agree on the order.
pub const USER_INDEX: usize = 0;
pub const SERVICE_INDEX: usize = 1;

const EXCHANGE_TAG: &[u8] = b"unravel/exchange/v1";

impl Deposit {
    /// A hop address that forwards to X.
    pub fn new(
        musig: &MuSig,
        x: &str,
        network: Network,
        user: Point,
        service: Point,
    ) -> Result<Self, Error> {
        Self::with_exchange(musig, x, None, network, user, service)
    }

    /// A hop address that forwards to `exchange` when there is one, and otherwise to X. The
    /// safety net is X's either way.
    ///
    /// With an exchange, S is replaced by S + t·G, where t = TaggedHash("unravel/exchange/v1",
    /// S compressed ‖ the exchange's scriptPubKey) mod n, so Y itself names the exchange. A page
    /// can't register the hop address again with another exchange address: it would give a
    /// different Y. Without one, or with the exchange address equal to X, Y is exactly what
    /// [`Deposit::new`] gives.
    pub fn with_exchange(
        musig: &MuSig,
        x: &str,
        exchange: Option<&str>,
        network: Network,
        user: Point,
        service: Point,
    ) -> Result<Self, Error> {
        let x = parse_x(x, network)?;
        let q = output_key_of(&x)?;
        let exchange = exchange
            .map(|exchange| parse_exchange(exchange, network))
            .transpose()?
            .filter(|exchange| *exchange != x);
        let service_tweak = exchange
            .as_ref()
            .map(|exchange| exchange_tweak(service, exchange));
        let service = match service_tweak {
            Some(t) => g!(service + t * G)
                .normalize()
                .non_zero()
                .expect("computationally unreachable: t is a hash"),
            None => service,
        };

        let internal = musig.new_agg_key(vec![user, service]).into_xonly_key();
        let internal_xonly = to_xonly(internal.agg_public_key());

        let leaf = safety_net_script(q);
        let secp = Secp256k1::verification_only();
        let spend_info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .expect("one leaf at depth 0")
            .finalize(&secp, internal_xonly)
            .expect("tree is complete");

        let tweak = Scalar::<Public, Zero>::from_bytes(spend_info.tap_tweak().to_byte_array())
            .expect("rust-bitcoin already rejects tweaks >= n");
        let signing_key = internal.tweak(tweak).expect("tweak is not -secret");
        assert_eq!(
            to_xonly(signing_key.agg_public_key()),
            spend_info.output_key().to_x_only_public_key(),
            "secp256kfun and rust-bitcoin must agree on Y's output key"
        );
        let descriptor: Descriptor<XOnlyPublicKey> = format!("tr({internal_xonly},pk({q}))")
            .parse()
            .expect("well-formed descriptor");
        assert_eq!(
            descriptor.address(network).expect("tr has an address"),
            Address::p2tr_tweaked(spend_info.output_key(), network),
            "miniscript must derive the same Y from the descriptor"
        );

        Ok(Self {
            x,
            exchange,
            service_tweak,
            signing_key,
            spend_info,
            leaf,
            network,
            descriptor: descriptor.to_string(),
        })
    }

    pub fn address(&self) -> Address {
        Address::p2tr_tweaked(self.spend_info.output_key(), self.network)
    }

    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address().script_pubkey()
    }

    /// The destination X.
    pub fn x(&self) -> &Address {
        &self.x
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// The exchange's deposit address, if this hop address deposits to an exchange.
    pub fn exchange(&self) -> Option<&Address> {
        self.exchange.as_ref()
    }

    /// Where a forward goes unless the user asks for X: the exchange, or else X.
    pub fn onward(&self) -> &Address {
        self.exchange.as_ref().unwrap_or(&self.x)
    }

    /// Whether a forward may pay `script_pubkey`: X, or the exchange. Paying X is how
    /// coins the exchange sends back reach the user.
    pub fn may_pay(&self, script_pubkey: &Script) -> bool {
        *script_pubkey == self.x.script_pubkey()
            || self
                .exchange
                .as_ref()
                .is_some_and(|exchange| *script_pubkey == exchange.script_pubkey())
    }

    /// What S's secret is offset by to sign for this hop address. See [`Deposit::with_exchange`].
    pub fn service_tweak(&self) -> Option<Scalar<Public, Zero>> {
        self.service_tweak
    }

    pub fn signing_key(&self) -> &AggKey<EvenY> {
        &self.signing_key
    }

    pub fn safety_net_leaf(&self) -> &ScriptBuf {
        &self.leaf
    }

    /// Y's spending conditions, `tr(<internal key>,pk(<Q>))` with its checksum. Anyone can
    /// check it derives Y. It is also the backup the safety net needs: spending through the
    /// leaf takes the internal key, which Y doesn't reveal and only U and S know.
    pub fn descriptor(&self) -> &str {
        &self.descriptor
    }

    pub fn safety_net_control_block(&self) -> ControlBlock {
        self.spend_info
            .control_block(&(self.leaf.clone(), LeafVersion::TapScript))
            .expect("leaf is in the tree")
    }
}

/// Parses the destination X. The browser needs it before it can derive U.
pub fn parse_x(x: &str, network: Network) -> Result<Address, Error> {
    let x = x
        .parse::<Address<_>>()
        .map_err(|_| Error::NotTaproot)?
        .require_network(network)
        .map_err(|_| Error::NotTaproot)?;
    output_key_of(&x)?;
    Ok(x)
}

/// The exchange's deposit address, of any standard type. Y commits to its script through S's
/// tweak. An unknown witness version or a pay-to-anchor output is anyone-can-spend, and a
/// taproot address without a valid key can never be spent, so neither is accepted. With
/// these types, no output a forward pays is bigger than a taproot one.
pub fn parse_exchange(exchange: &str, network: Network) -> Result<Address, Error> {
    let exchange = exchange
        .parse::<Address<_>>()
        .ok()
        .and_then(|exchange| exchange.require_network(network).ok())
        .ok_or(Error::BadExchangeAddress)?;
    match exchange.address_type() {
        Some(AddressType::P2tr) => output_key_of(&exchange)
            .map(|_| exchange)
            .map_err(|_| Error::BadExchangeAddress),
        Some(AddressType::P2pkh | AddressType::P2sh | AddressType::P2wpkh | AddressType::P2wsh) => {
            Ok(exchange)
        }
        _ => Err(Error::BadExchangeAddress),
    }
}

/// t in S + t·G. The hash covers the exchange's script, so the same address in upper or
/// lower case gives the same hop address.
fn exchange_tweak(service: Point, exchange: &Address) -> Scalar<Public, Zero> {
    let tag = Sha256::digest(EXCHANGE_TAG);
    let hash = Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(service.to_bytes())
        .chain_update(exchange.script_pubkey().as_bytes())
        .finalize();
    Scalar::from_bytes_mod_order(hash.into())
}

/// The x-only output key Q of a taproot address. Parsing it as a key checks it is on the curve.
fn output_key_of(x: &Address) -> Result<XOnlyPublicKey, Error> {
    if x.address_type() != Some(AddressType::P2tr) {
        return Err(Error::NotTaproot);
    }
    let program = x.witness_program().ok_or(Error::NotTaproot)?;
    debug_assert_eq!(program.version(), WitnessVersion::V1);
    XOnlyPublicKey::from_slice(program.program().as_bytes()).map_err(|_| Error::NotTaproot)
}

/// `<Q> OP_CHECKSIG`. Q must be the 32-byte x-only key: a 33-byte key in tapscript is an
/// "unknown public key type" that any signature satisfies.
fn safety_net_script(q: XOnlyPublicKey) -> ScriptBuf {
    bitcoin::script::Builder::new()
        .push_x_only_key(&q)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script()
}

fn to_xonly(point: Point<EvenY>) -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&point.to_xonly_bytes()).expect("valid point")
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_util::{random_point, random_x};

    #[test]
    fn rejects_non_taproot_x() {
        let musig = crate::musig();
        let (u, s) = (random_point(), random_point());
        let p2wpkh = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        assert_eq!(
            Deposit::new(&musig, p2wpkh, Network::Regtest, u, s).unwrap_err(),
            Error::NotTaproot
        );
        assert_eq!(
            Deposit::new(&musig, &random_x(), Network::Bitcoin, u, s).unwrap_err(),
            Error::NotTaproot
        );
    }

    /// The internal key is BIP-327 KeyAgg of [U, S] in that order, so any BIP-327
    /// implementation can rebuild it. Vectors from bip-0327/vectors/key_agg_vectors.json.
    #[test]
    fn key_agg_matches_bip327() {
        let pubkeys: Vec<Point> = [
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        ]
        .map(|hex| hex.parse().unwrap())
        .to_vec();
        let cases = [
            (&[0, 1, 2][..], "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C"),
            (&[2, 1, 0], "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B"),
            (&[0, 0, 0], "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935"),
            (&[0, 0, 1, 1], "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E"),
        ];
        let musig = crate::musig();
        for (indices, expected) in cases {
            let keys = indices.iter().map(|&i| pubkeys[i]).collect();
            let agg = musig.new_agg_key(keys).into_xonly_key();
            assert_eq!(to_xonly(agg.agg_public_key()).to_string(), expected.to_lowercase());
        }
    }

    #[test]
    fn an_exchange_changes_only_the_server_key() {
        let musig = crate::musig();
        let (u, s) = (random_point(), random_point());
        let x = random_x();
        let plain = Deposit::new(&musig, &x, Network::Regtest, u, s).unwrap();
        let with = |exchange: Option<&str>| {
            Deposit::with_exchange(&musig, &x, exchange, Network::Regtest, u, s)
        };
        // No exchange, or X itself as the exchange, gives the plain address, so a hop address
        // registered without one keeps its address.
        for exchange in [None, Some(x.as_str())] {
            let same = with(exchange).unwrap();
            assert_eq!(same.address(), plain.address());
            assert!(same.exchange().is_none() && same.service_tweak().is_none());
        }

        let p2wpkh = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let deposit = with(Some(p2wpkh)).unwrap();
        assert_ne!(deposit.address(), plain.address());
        assert_eq!(deposit.safety_net_leaf(), plain.safety_net_leaf());
        assert_eq!(deposit.onward().to_string(), p2wpkh);
        assert!(deposit.may_pay(&deposit.onward().script_pubkey()));
        assert!(deposit.may_pay(&plain.x().script_pubkey()));
        assert!(!plain.may_pay(&deposit.onward().script_pubkey()));
        assert!(!deposit.may_pay(&deposit.script_pubkey()));
        assert_ne!(
            with(Some(&random_x())).unwrap().address(),
            deposit.address()
        );

        let mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        for bad in [mainnet, "", "not an address"] {
            assert_eq!(with(Some(bad)).unwrap_err(), Error::BadExchangeAddress);
        }
    }

    #[test]
    fn exchange_addresses_must_be_spendable_by_their_owner_alone() {
        use bitcoin::{KnownHrp, PublicKey, WitnessProgram, key::Keypair, secp256k1::Secp256k1};
        let secp = Secp256k1::new();
        let key = PublicKey::new(Keypair::new(&secp, &mut rand::thread_rng()).public_key());
        let script = ScriptBuf::new_p2pk(&key);
        let good = [
            Address::p2pkh(key, Network::Regtest),
            Address::p2sh(&script, Network::Regtest).unwrap(),
            Address::p2wpkh(&key.try_into().unwrap(), Network::Regtest),
            Address::p2wsh(&script, Network::Regtest),
            random_x().parse::<Address<_>>().unwrap().assume_checked(),
        ];
        for address in good {
            assert!(parse_exchange(&address.to_string(), Network::Regtest).is_ok());
        }
        let program = |version, bytes: &[u8]| {
            Address::from_witness_program(
                WitnessProgram::new(version, bytes).unwrap(),
                KnownHrp::Regtest,
            )
            .to_string()
        };
        let bad = [
            // Pay-to-anchor: anyone can spend it.
            "bcrt1pfeesnyr2tx".to_string(),
            // A future witness version: anyone can spend it today.
            program(WitnessVersion::V2, &[1; 32]),
            // Taproot with no valid key: nobody can ever spend it.
            program(WitnessVersion::V1, &[0; 32]),
        ];
        for address in bad {
            assert_eq!(
                parse_exchange(&address, Network::Regtest).unwrap_err(),
                Error::BadExchangeAddress,
                "{address}"
            );
        }
    }

    /// Computes the tweak with libsecp and bitcoin's own SHA-256, independently of the code
    /// above, so the spec in [`Deposit::with_exchange`]'s doc is checked against what the code
    /// does.
    #[test]
    fn the_exchange_tweak_matches_its_spec() {
        use bitcoin::hashes::{HashEngine, sha256};
        use bitcoin::secp256k1::{self, Secp256k1};
        let musig = crate::musig();
        let (u, s) = (random_point(), random_point());
        let (x, exchange) = (random_x(), "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");
        let spk = exchange
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked()
            .script_pubkey();
        let tag = sha256::Hash::hash(b"unravel/exchange/v1");
        let mut engine = sha256::Hash::engine();
        engine.input(tag.as_ref());
        engine.input(tag.as_ref());
        engine.input(&s.to_bytes());
        engine.input(spk.as_bytes());
        let t = secp256k1::Scalar::from_be_bytes(sha256::Hash::from_engine(engine).to_byte_array())
            .unwrap();
        let tweaked = secp256k1::PublicKey::from_slice(&s.to_bytes())
            .unwrap()
            .add_exp_tweak(&Secp256k1::new(), &t)
            .unwrap();
        let tweaked = Point::from_bytes(tweaked.serialize()).unwrap();

        let with = Deposit::with_exchange(&musig, &x, Some(exchange), Network::Regtest, u, s);
        let by_hand = Deposit::new(&musig, &x, Network::Regtest, u, tweaked).unwrap();
        assert_eq!(with.unwrap().address(), by_hand.address());
    }

    #[test]
    fn y_commits_to_x() {
        let musig = crate::musig();
        let x = random_x();
        let deposit =
            Deposit::new(&musig, &x, Network::Regtest, random_point(), random_point()).unwrap();
        let q = output_key_of(deposit.x()).unwrap();
        assert_eq!(deposit.safety_net_leaf().as_bytes()[1..33], q.serialize());
        assert_ne!(deposit.address().to_string(), x);
        let (body, checksum) = deposit.descriptor().split_once('#').unwrap();
        assert!(body.ends_with(&format!(",pk({q}))")));
        assert_eq!(checksum.len(), 8);
    }
}
