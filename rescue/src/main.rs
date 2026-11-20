//! `unravel-rescue <kit file> <hop address> [exchange deposit address...]`
//!
//! Prints the Bitcoin Core commands that spend a hop address through its safety net, for when
//! the browser and the server are gone. It reads the emergency kit, then the seed words of the
//! wallet that holds the destination. It finds the destination among that wallet's BIP-86
//! addresses and prints the hop address's descriptor with the destination's tweaked private
//! key, for Bitcoin Core to import and spend. No wallet signs the safety net's script from a
//! seed, but Bitcoin Core does from a descriptor. It runs offline: it reads the kit and the
//! terminal, nothing else.

use std::{
    io::{self, BufRead, IsTerminal, Write},
    iter,
    process::{Command, ExitCode},
    str::FromStr,
};

use bitcoin::{
    Address, Network, NetworkKind,
    bip32::{ChildNumber, DerivationPath, Xpriv},
    secp256k1::Secp256k1,
};
use secp256kfun::Point;
use unravel::{Deposit, RescueKey, deposit::parse_exchange, safety_net};

/// How far into each account's receive and change addresses to look. Most wallets use one
/// account and far fewer addresses; the search is cheap enough to cover the unusual ones.
const DEPTH: u32 = 1000;
const ACCOUNTS: u32 = 3;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [kit, hop, exchanges @ ..] = &args[..] else {
        return Err(
            "usage: just rescue <kit file> <hop address> [exchange deposit address...]".into(),
        );
    };
    let text = std::fs::read_to_string(kit).map_err(|e| format!("can't read {kit}: {e}"))?;
    let mut kit = Kit::parse(&text)?;
    let network = kit.network;
    for exchange in exchanges {
        parse_exchange(exchange, network)
            .map_err(|_| format!("{exchange} isn't an exchange deposit address on {network}"))?;
        kit.exchanges.push(exchange.clone());
    }
    let hop = Address::from_str(hop)
        .ok()
        .and_then(|a| a.require_network(network).ok())
        .ok_or_else(|| format!("{hop} isn't an address on {network}"))?;

    let master = read_master(network)?;
    eprintln!(
        "searching your wallet's first {DEPTH} receive and change addresses in accounts 0 to {}…",
        ACCOUNTS - 1
    );
    let (path, deposit, descriptor) = find(&kit, &master, &hop, DEPTH)?;

    let x = deposit.x();
    let via = deposit
        .exchange()
        .map(|e| format!(", with the exchange's deposit address {e}"))
        .unwrap_or_default();
    let cli = match network {
        Network::Bitcoin => "bitcoin-cli".to_string(),
        Network::Testnet => "bitcoin-cli -testnet".to_string(),
        other => format!("bitcoin-cli -{other}"),
    };
    println!(
        r#"found it: {hop} was made with your address {x} (m/{path}){via}.

to spend it with Bitcoin Core, run these in order. they make a new blank wallet, import the
hop address's spending rules with your key, and send everything back to {x}:

  {cli} createwallet unravel-rescue false true
  {cli} -rpcclienttimeout=0 -rpcwallet=unravel-rescue importdescriptors '[{{"desc":"{descriptor}","timestamp":0}}]'
  {cli} -named -rpcwallet=unravel-rescue sendall recipients='["{x}"]' fee_rate=1

the descriptor in the second command holds your address's tweaked private key, so anyone who
sees it can take the coins at that address. use it on this machine only, and delete the
unravel-rescue wallet when you're done.

"timestamp":0 rescans the whole chain, which takes hours on a node that doesn't have the
blocks indexed; -rpcclienttimeout=0 makes bitcoin-cli wait for it instead of reporting a
timeout while the wallet is still scanning. a unix time from before the first deposit is
quicker. a pruned node can only rescan the blocks it still has.

fee_rate is in sats per vbyte. 1 is cheap and can wait a long time when blocks are full; a
higher number confirms sooner. choose it now: sendall leaves this wallet empty, so it can't
raise the fee later. if it does get stuck, the wallet at {x} can speed it up by spending
the incoming coins on to itself with a high fee. it's set because a node without recent fee
data refuses to guess.

for a second hop address to the same destination, skip the first command and import into the
same wallet, after `{cli} loadwallet unravel-rescue` if bitcoind has restarted since; one
sendall takes everything in it. for a different destination, use a different wallet name."#
    );
    Ok(())
}

struct Kit {
    network: Network,
    rescue: RescueKey,
    server: Point,
    exchanges: Vec<String>,
}

impl Kit {
    fn parse(text: &str) -> Result<Self, String> {
        if !text.contains("UNRAVEL RULE EMERGENCY KIT") {
            return Err("that file isn't an emergency kit".into());
        }
        let field = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(name))
                .map(str::trim)
        };
        if field("format:") != Some("1") {
            return Err("this reads kits of format 1 only".into());
        }
        // Each value sits indented on the lines under its heading.
        let section = |heading: &str| -> Vec<&str> {
            text.lines()
                .skip_while(|l| l.trim() != heading)
                .skip(1)
                .take_while(|l| !l.trim().is_empty())
                .map(str::trim)
                .collect()
        };
        Ok(Self {
            network: field("network:")
                .and_then(|n| n.parse().ok())
                .ok_or("no network in the kit")?,
            rescue: section("rescue key:")
                .first()
                .and_then(|k| k.parse().ok())
                .ok_or("no rescue key in the kit, or it fails its checksum")?,
            server: section("server key:")
                .first()
                .and_then(|k| k.parse().ok())
                .ok_or("no server key in the kit")?,
            exchanges: section("exchange deposit addresses used so far:")
                .into_iter()
                .map(String::from)
                .collect(),
        })
    }
}

/// The wallet's master key, from seed words and a passphrase, or an xprv, read from the terminal.
fn read_master(network: Network) -> Result<Xpriv, String> {
    let secret = read_secret("seed words, or an xprv: ")?;
    if let Ok(xprv) = Xpriv::from_str(secret.trim()) {
        if xprv.network != NetworkKind::from(network) {
            return Err(format!("that xprv isn't for {network}"));
        }
        return Ok(xprv);
    }
    let words = secret.split_whitespace().collect::<Vec<_>>().join(" ");
    let mnemonic = bip39::Mnemonic::parse_normalized(&words)
        .map_err(|e| format!("those aren't valid seed words, or an xprv: {e}"))?;
    let passphrase = read_secret("passphrase, or enter for none: ")?;
    Xpriv::new_master(network, &mnemonic.to_seed_normalized(&passphrase)).map_err(|e| e.to_string())
}

/// One line from stdin, without the newline. A passphrase keeps its spaces. On a terminal the
/// typing isn't shown, so the seed doesn't end up in its scrollback.
fn read_secret(prompt: &str) -> Result<String, String> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    let hide = io::stdin().is_terminal() && stty("-echo");
    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line);
    if hide {
        stty("echo");
        eprintln!();
    }
    read.map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn stty(arg: &str) -> bool {
    Command::new("stty")
        .arg(arg)
        .status()
        .is_ok_and(|s| s.success())
}

/// Finds which of the wallet's BIP-86 addresses, alone or with one of the exchange addresses,
/// made `hop`, looking `depth` addresses deep. Low indexes are tried in every account before
/// higher ones, since most wallets have used only a few.
fn find(
    kit: &Kit,
    master: &Xpriv,
    hop: &Address,
    depth: u32,
) -> Result<(DerivationPath, Deposit, String), String> {
    let secp = Secp256k1::new();
    let musig = unravel::musig();
    let coin = u32::from(kit.network != Network::Bitcoin);
    let hardened = |i| ChildNumber::from_hardened_idx(i).expect("small index");
    let normal = |i| ChildNumber::from_normal_idx(i).expect("small index");
    let mut chains = vec![];
    for account in 0..ACCOUNTS {
        for chain in 0..2 {
            let path = DerivationPath::from(vec![
                hardened(86),
                hardened(coin),
                hardened(account),
                normal(chain),
            ]);
            let key = master
                .derive_priv(&secp, &path)
                .map_err(|e| e.to_string())?;
            chains.push((path, key));
        }
    }
    let exchanges: Vec<Option<&str>> = iter::once(None)
        .chain(kit.exchanges.iter().map(|e| Some(e.as_str())))
        .collect();
    for index in 0..depth {
        for (path, chain) in &chains {
            let key = chain
                .derive_priv(&secp, &[normal(index)])
                .map_err(|e| e.to_string())?;
            let x = Address::p2tr(
                &secp,
                key.private_key.x_only_public_key(&secp).0,
                None,
                kit.network,
            );
            let user = musig.new_keypair(kit.rescue.tab_secret(&x)).public_key();
            for &exchange in &exchanges {
                let Ok(deposit) = Deposit::with_exchange(
                    &musig,
                    &x.to_string(),
                    exchange,
                    kit.network,
                    user,
                    kit.server,
                ) else {
                    continue;
                };
                if deposit.address() == *hop {
                    let descriptor = safety_net::private_descriptor(&deposit, key.private_key)
                        .expect("the key behind x");
                    return Ok((path.child(normal(index)), deposit, descriptor));
                }
            }
        }
    }
    Err(format!(
        "none of your wallet's first {depth} receive or change addresses, in accounts 0 to {}, made \
         that hop address with this kit. check the seed words, passphrase and kit. if the hop \
         address was for depositing to an exchange the kit doesn't list, add the exchange's \
         deposit address after the hop address.",
        ACCOUNTS - 1
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const XPRV: &str = "tprv8ZgxMBicQKsPf2aindJc8ieRYzcqjgTsHjPo5wmLZhrVhJKVTGoqkdhHYM5LrQx1kitfpsBvSewwwxwU2xNDwGLZoCbLP6XBPQPPQUf4BRX";
    const SERVER: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const EXCHANGE: &str = "bcrt1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk";

    /// A kit as the page writes it.
    fn kit_text(rescue: RescueKey, exchanges: &[&str]) -> String {
        let exchanges = match exchanges {
            [] => String::new(),
            list => format!(
                "exchange deposit addresses used so far:\n  {}\n\n",
                list.join("\n  ")
            ),
        };
        format!(
            "UNRAVEL RULE EMERGENCY KIT\n\nformat:   1\ncreated:  2026-11-16\nnetwork:  regtest\n\
             server:   http://127.0.0.1:8322\n\nrescue key:\n  {rescue}\n\nserver key:\n  {SERVER}\n\n\
             {exchanges}Keep this private.\n"
        )
    }

    #[test]
    fn reads_a_kit() {
        let rescue = RescueKey::generate();
        let text = kit_text(rescue, &[EXCHANGE]);
        let kit = Kit::parse(&text).unwrap();
        assert_eq!(kit.network, Network::Regtest);
        assert!(kit.rescue == rescue);
        assert_eq!(kit.server.to_string(), SERVER);
        assert_eq!(kit.exchanges, [EXCHANGE]);
        assert!(
            Kit::parse(&kit_text(rescue, &[]))
                .unwrap()
                .exchanges
                .is_empty()
        );
        assert!(Kit::parse(&text.replace("format:   1", "format:   2")).is_err());
        assert!(Kit::parse("hello").is_err());
    }

    #[test]
    fn finds_the_address_that_made_a_hop_address() {
        let master = Xpriv::from_str(XPRV).unwrap();
        let rescue = RescueKey::generate();
        let kit = Kit::parse(&kit_text(rescue, &[EXCHANGE])).unwrap();
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str("m/86h/1h/1h/1/3").unwrap();
        let key = master.derive_priv(&secp, &path).unwrap();
        let x = Address::p2tr(
            &secp,
            key.private_key.x_only_public_key(&secp).0,
            None,
            Network::Regtest,
        );
        let hop = |rescue: RescueKey, exchange| {
            let user = unravel::musig()
                .new_keypair(rescue.tab_secret(&x))
                .public_key();
            Deposit::with_exchange(
                &unravel::musig(),
                &x.to_string(),
                exchange,
                Network::Regtest,
                user,
                kit.server,
            )
            .unwrap()
            .address()
        };
        for exchange in [None, Some(EXCHANGE)] {
            let (found, deposit, descriptor) =
                find(&kit, &master, &hop(rescue, exchange), 5).unwrap();
            assert_eq!(found, path);
            assert_eq!(
                deposit.exchange().map(|e| e.to_string()).as_deref(),
                exchange
            );
            assert!(descriptor.starts_with("tr("));
        }
        // Another browser's hop address for the same address isn't found with this kit.
        assert!(find(&kit, &master, &hop(RescueKey::generate(), None), 5).is_err());
    }
}
