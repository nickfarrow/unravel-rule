//! The proof of work a page does before the server stores a new hop address. Checking it
//! costs the server one hash, so filling the server's memory with hop addresses costs CPU.
//!
//! The work covers the server's salt, which it changes regularly so work can't be stockpiled
//! for long, and the request's own `x`, `user_pk` and any `exchange`, so one solution registers
//! one hop address.

use sha2::{Digest, Sha256};

const TAG: &[u8] = b"unravel/pow/v1";

// An absent exchange adds nothing to the hash, so a page that never sends one still matches
// the server.
fn prefix(salt: &[u8; 32], x: &str, user_pk: &str, exchange: Option<&str>) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(TAG);
    hash.update(salt);
    for field in [x, user_pk].into_iter().chain(exchange) {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash
}

fn zero_bits(hash: &[u8]) -> u32 {
    let mut bits = 0;
    for byte in hash {
        bits += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    bits
}

fn meets(prefix: &Sha256, nonce: u32, bits: u32) -> bool {
    let mut hash = prefix.clone();
    hash.update(nonce.to_be_bytes());
    zero_bits(&hash.finalize()) >= bits
}

pub fn check(
    salt: &[u8; 32],
    x: &str,
    user_pk: &str,
    exchange: Option<&str>,
    nonce: u32,
    bits: u32,
) -> bool {
    meets(&prefix(salt, x, user_pk, exchange), nonce, bits)
}

/// The first nonce in `from..from + count` whose hash starts with `bits` zero bits. The page
/// searches a slice at a time so it stays responsive.
pub fn search(
    salt: &[u8; 32],
    x: &str,
    user_pk: &str,
    exchange: Option<&str>,
    bits: u32,
    from: u32,
    count: u32,
) -> Option<u32> {
    let prefix = prefix(salt, x, user_pk, exchange);
    (from..from.saturating_add(count)).find(|&nonce| meets(&prefix, nonce, bits))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn counts_leading_zero_bits() {
        assert_eq!(zero_bits(&[0xff]), 0);
        assert_eq!(zero_bits(&[0x01, 0xff]), 7);
        assert_eq!(zero_bits(&[0x00, 0x20]), 10);
        assert_eq!(zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn a_solution_registers_only_its_own_request() {
        let salt = [7; 32];
        let nonce = search(&salt, "bc1p-x", "02aa", None, 12, 0, u32::MAX).unwrap();
        assert!(check(&salt, "bc1p-x", "02aa", None, nonce, 12));
        assert!(!check(&[8; 32], "bc1p-x", "02aa", None, nonce, 12));
        // The length prefixes keep a field's end from moving into the next one.
        assert!(!check(&salt, "bc1p-x0", "2aa", None, nonce, 12));
        assert!(!check(&salt, "bc1p-x", "02ab", None, nonce, 12));
        // Each nonce before the one found falls short.
        assert!((0..nonce).all(|n| !check(&salt, "bc1p-x", "02aa", None, n, 12)));

        // With an exchange, the work covers it too.
        let nonce = search(&salt, "bc1p-x", "02aa", Some("bc1q-e"), 12, 0, u32::MAX).unwrap();
        assert!(check(&salt, "bc1p-x", "02aa", Some("bc1q-e"), nonce, 12));
        assert!(!check(&salt, "bc1p-x", "02aa", Some("bc1q-f"), nonce, 12));
        assert!(!check(&salt, "bc1p-x", "02aa", None, nonce, 12));
    }
}
