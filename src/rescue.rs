//! The rescue key: the one backup that brings back the browser key U.
//!
//! U is derived from the rescue key and the destination X, so a user who saved the rescue
//! key can rebuild the hop address Y's internal key KeyAgg(U, S), with S the server key,
//! after the browser and the service are both gone. That internal key is what spending
//! through the safety net needs.

use bitcoin::{
    Address,
    hex::{DisplayHex, FromHex},
};
use rand::RngCore;
use schnorr_fun::fun::Scalar;
use sha2::{Digest, Sha256};

use crate::Error;

/// Both tags carry the kit format, so a key from another format derives nothing in common
/// with this one, and typing one in fails its checksum instead of rebuilding wrong addresses.
const TAG: &[u8] = b"unravel/browser-key/v1";
const CHECKSUM_TAG: &[u8] = b"unravel/rescue-key/v1";

/// 16 random bytes, shown as hex with a 2-byte checksum.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RescueKey([u8; 16]);

impl RescueKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// U's secret for every hop address whose destination is `x`. The exchange, if any, isn't
    /// part of it.
    pub fn tab_secret(&self, x: &Address) -> Scalar {
        let tag = Sha256::digest(TAG);
        let hash = Sha256::new()
            .chain_update(tag)
            .chain_update(tag)
            .chain_update(self.0)
            .chain_update(x.script_pubkey().as_bytes())
            .finalize();
        Scalar::from_bytes_mod_order(hash.into())
            .non_zero()
            .expect("computationally unreachable: hash is zero mod n")
    }

    fn checksum(&self) -> [u8; 2] {
        let tag = Sha256::digest(CHECKSUM_TAG);
        let hash = Sha256::new()
            .chain_update(tag)
            .chain_update(tag)
            .chain_update(self.0)
            .finalize();
        [hash[0], hash[1]]
    }
}

impl core::fmt::Display for RescueKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let hex = [&self.0[..], &self.checksum()]
            .concat()
            .to_lower_hex_string();
        let groups: Vec<&str> = (0..hex.len()).step_by(4).map(|i| &hex[i..i + 4]).collect();
        f.write_str(&groups.join("-"))
    }
}

/// Never print the key itself into logs.
impl core::fmt::Debug for RescueKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RescueKey(..)")
    }
}

impl core::str::FromStr for RescueKey {
    type Err = Error;

    /// Accepts the key however the user copied it down: any case, any spacing and dashes.
    fn from_str(s: &str) -> Result<Self, Error> {
        let hex: String = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let bytes = <[u8; 18]>::from_hex(&hex).map_err(|_| Error::BadRescueKey)?;
        let key = Self(bytes[..16].try_into().expect("16 bytes"));
        if key.checksum() != bytes[16..] {
            return Err(Error::BadRescueKey);
        }
        Ok(key)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::Network;

    /// The BIP-86 test vector's first receive address.
    const X: &str = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";

    fn x() -> Address {
        X.parse::<Address<_>>()
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap()
    }

    fn other_x() -> Address {
        crate::test_util::random_x()
            .parse::<Address<_>>()
            .unwrap()
            .assume_checked()
    }

    fn tab_key(key: &RescueKey, x: &Address) -> schnorr_fun::fun::Point {
        crate::musig().new_keypair(key.tab_secret(x)).public_key()
    }

    #[test]
    fn round_trips_through_its_display_form() {
        let key = RescueKey::generate();
        let shown = key.to_string();
        assert_eq!(shown.len(), 36 + 8);
        assert_eq!(shown.split('-').count(), 9);
        assert!(shown.split('-').all(|g| g.len() == 4));
        assert_eq!(shown.parse::<RescueKey>().unwrap(), key);
    }

    #[test]
    fn catches_a_typo() {
        // A fixed key: the 2-byte checksum misses about one random typo in 65536.
        let shown = KAT_DISPLAY.to_string();
        for i in shown
            .char_indices()
            .filter(|(_, c)| *c != '-')
            .map(|(i, _)| i)
        {
            let mut typo = shown.clone().into_bytes();
            typo[i] = if typo[i] == b'0' { b'1' } else { b'0' };
            let typo = String::from_utf8(typo).unwrap();
            assert_eq!(
                typo.parse::<RescueKey>(),
                Err(Error::BadRescueKey),
                "{typo}"
            );
        }
        assert_eq!(
            shown[..shown.len() - 1].parse::<RescueKey>(),
            Err(Error::BadRescueKey)
        );
        assert_eq!(
            format!("{shown}0").parse::<RescueKey>(),
            Err(Error::BadRescueKey)
        );
        assert_eq!(
            shown
                .replacen(|c: char| c.is_ascii_digit(), "g", 1)
                .parse::<RescueKey>(),
            Err(Error::BadRescueKey)
        );
    }

    #[test]
    fn ignores_case_spaces_and_dashes() {
        let key = RescueKey::generate();
        let messy = format!(
            " {}\n",
            key.to_string()
                .to_uppercase()
                .replace('-', " - ")
                .replace("  ", "\t")
        );
        assert_eq!(messy.parse::<RescueKey>().unwrap(), key);
        let bare = key.to_string().replace('-', "");
        assert_eq!(bare.parse::<RescueKey>().unwrap(), key);
    }

    #[test]
    fn same_key_and_x_give_the_same_u() {
        let key = RescueKey::generate();
        let copy: RescueKey = key.to_string().parse().unwrap();
        assert_eq!(tab_key(&key, &x()), tab_key(&copy, &x()));
        assert_ne!(tab_key(&key, &x()), tab_key(&key, &other_x()));
        assert_ne!(tab_key(&key, &x()), tab_key(&RescueKey::generate(), &x()));
    }

    /// Pins the derivation: changing it would strand every rescue key already written down.
    /// The expected values were cross-checked with an independent Python implementation.
    #[test]
    fn known_answer() {
        let key = RescueKey(core::array::from_fn(|i| i as u8));
        assert_eq!(key.to_string(), KAT_DISPLAY);
        assert_eq!(
            key.tab_secret(&x()).to_bytes().to_lower_hex_string(),
            KAT_SECRET
        );
        assert_eq!(tab_key(&key, &x()).to_string(), KAT_U);
    }

    /// The whole chain a kit is recovered with: rescue key, X and S give Y and its descriptor.
    #[test]
    fn known_answer_hop_address() {
        let key = RescueKey(core::array::from_fn(|i| i as u8));
        let service = crate::musig()
            .new_keypair(schnorr_fun::fun::Scalar::from(2u32).non_zero().unwrap())
            .public_key();
        let deposit = crate::Deposit::new(
            &crate::musig(),
            X,
            Network::Bitcoin,
            tab_key(&key, &x()),
            service,
        )
        .unwrap();
        assert_eq!(deposit.address().to_string(), KAT_Y);
        assert_eq!(deposit.descriptor(), KAT_DESCRIPTOR);
    }

    /// The same chain for a hop address that deposits to an exchange, which recovery also
    /// rebuilds. Pinned from this code, not cross-checked independently.
    #[test]
    fn known_answer_hop_address_with_exchange() {
        let key = RescueKey(core::array::from_fn(|i| i as u8));
        let service = crate::musig()
            .new_keypair(schnorr_fun::fun::Scalar::from(2u32).non_zero().unwrap())
            .public_key();
        let deposit = crate::Deposit::with_exchange(
            &crate::musig(),
            X,
            Some(KAT_EXCHANGE),
            Network::Bitcoin,
            tab_key(&key, &x()),
            service,
        )
        .unwrap();
        assert_eq!(deposit.address().to_string(), KAT_Y_EXCHANGE);
        assert_eq!(deposit.descriptor(), KAT_DESCRIPTOR_EXCHANGE);
    }

    const KAT_EXCHANGE: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const KAT_Y_EXCHANGE: &str = "bc1pqdnze8nm3qh052q8qhz6vh5shuzsd72wgs89ace8svktcecnypvqghc9r9";
    const KAT_DESCRIPTOR_EXCHANGE: &str = "tr(c58a27eb9efd8b489c6c3aea0e1a229bc7cbfcacc950a7e8919dd846753ca1a3,pk(a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c))#9f47ew38";
    const KAT_Y: &str = "bc1ph6w8r296e6md65fvpp0d7lulg55925pgrarldptcgv9fucncs74qwtaau4";
    const KAT_DESCRIPTOR: &str = "tr(c95112743e4ef9a9c8b99194e77fddf3a1d766fec37b1001d84c7326080d6ac0,pk(a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c))#z9gyp6zs";
    const KAT_DISPLAY: &str = "0001-0203-0405-0607-0809-0a0b-0c0d-0e0f-6ba9";
    const KAT_SECRET: &str = "cde4e861b7e30acc24015e0b4ccc491b337e95fe94f2b457e2fb5355abb2da29";
    const KAT_U: &str = "025f4d6e326a3b3fca954bcfab9fb6eb53b994bcb200d4b59462e9722441c0777b";
}
