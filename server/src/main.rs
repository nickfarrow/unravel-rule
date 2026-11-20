//! The service: holds the server key S and serves the page.
//!
//! By default it runs its own regtest node, which also plays the exchange, so the page has
//! buttons to withdraw and mine. With UNRAVEL_NETWORK=bitcoin (or signet, testnet4) it reads
//! the chain from an Electrum server: a public one unless UNRAVEL_ELECTRUM names another.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs::OpenOptions,
    io::{Cursor, ErrorKind, Read, Write},
    os::unix::fs::OpenOptionsExt,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bdk_bitcoind_rpc::Emitter;
use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid,
    hashes::{Hash, sha256},
    hex::{DisplayHex, FromHex},
};
use bitcoind::bitcoincore_rpc::{RpcApi, json::AddressType};
use electrum_client::ElectrumApi;
use miniscript::{
    ForEachKey,
    descriptor::{Descriptor, DescriptorPublicKey, Wildcard, checksum::desc_checksum},
};
use qrcode::{QrCode, render::unicode::Dense1x2};
use schnorr_fun::fun::{Point, Scalar};
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server};
use unravel::{
    Deposit,
    protocol::{FeePolicy, Service, SignResponse, Task},
    watch::{DepositUtxo, Watcher},
};

/// Any mainnet taproot address, for sizing forwards and for tests.
const TAPROOT_ADDRESS: &str = "bc1pah6cqjfnsf6fxy8q48ckpm25u78l6jfqr2qa6ylxmfv20hmrexfs4r9mw6";
/// The on-chain fee output is off: it costs users block space and links every user
/// through the service's fee coins. The page refuses any forward with a fee output, so
/// turning this on also needs a page that agrees.
const SERVICE_FEE: Option<Amount> = None;
/// 2 sat/vB, for the regtest node: it has no fee market to read.
const FORWARD_FEE_RATE: FeeRate = FeeRate::from_sat_per_kwu(500);
/// On a real network the forward pays the going rate within these bounds. At the top, a
/// 111 vB forward costs 1,110 sats, well inside the page's 2,000-sat limit, so the page always
/// signs. When the market is higher the forward still goes out, and the page warns that it
/// will be slow.
const MIN_FORWARD_SAT_PER_VB: f64 = 1.0;
const MAX_FORWARD_SAT_PER_VB: f64 = 10.0;

type Reply = Response<Cursor<Vec<u8>>>;

/// The hop addresses the server knows, so it can look up and forward their deposits.
#[derive(Default)]
struct Deposits {
    records: BTreeMap<String, Record>,
    /// Oldest first.
    order: VecDeque<String>,
}

impl Deposits {
    /// Keeps a record for `y` unless there is one. Past `MAX_DEPOSITS` the oldest is
    /// forgotten, which is safe: its page registers it again when the server doesn't know it.
    fn insert(&mut self, y: String, record: Record) {
        if self.records.contains_key(&y) {
            return;
        }
        self.order.push_back(y.clone());
        self.records.insert(y, record);
        while self.order.len() > MAX_DEPOSITS {
            let oldest = self.order.pop_front().expect("longer than the cap");
            self.records.remove(&oldest);
        }
    }
}

struct Record {
    deposit: Deposit,
    /// Only the regtest node syncs blocks itself; Electrum answers per address.
    watcher: Option<Watcher>,
    /// Each forward broadcast once, in order.
    forwards: Vec<Forward>,
    /// How many confirmations each deposit had when its forward was built, kept until the
    /// forward is broadcast and counted in the stats.
    ages: HashMap<OutPoint, u32>,
}

struct Forward {
    txid: Txid,
    spends: OutPoint,
    at: Instant,
    /// What it paid, and whether to X rather than onward, so any page can say what went where.
    sent: Amount,
    to_x: bool,
}

/// How long a deposit just forwarded isn't offered for forwarding again. The Electrum server
/// may not have the forward in its mempool yet, and would still list the deposit as unspent.
const FORWARD_SETTLE: Duration = Duration::from_secs(60);
/// How long a fee estimate is reused. It's the same for every page, and every open page asks.
const FEE_CACHE: Duration = Duration::from_secs(60);

enum Chain {
    Node(bitcoind::BitcoinD),
    Electrum(Electrum),
}

/// Electrum servers such as electrs or Fulcrum, in order of preference.
///
/// Each connection serves one call at a time. electrum-client can share one between threads,
/// but if the server drops it mid-call, a waiting call can hang for good and block every
/// reconnect. Here a connection that fails is dropped, and the next call opens a new one, to
/// the next server in the list.
struct Electrum {
    urls: Vec<String>,
    network: Network,
    /// The server new connections go to, as an index into `urls` that only grows.
    current: AtomicUsize,
    /// One per worker, so a worker always finds one free. Each knows which server it's on.
    connections: Vec<Mutex<Option<(usize, electrum_client::Client)>>>,
    /// The last fee estimate, in sat/vB, and when it came.
    fee: Mutex<Option<(Instant, f64)>>,
}

/// Requests run in parallel so one slow Electrum call doesn't stall every page.
const WORKERS: usize = 8;
/// The most of a request body the server reads.
const MAX_BODY: u64 = 16 * 1024;
/// The longest exchange message the server will sign. Each waiting signature holds one.
const MAX_CHALLENGE: usize = 2048;
/// The API's version. Bump it on any change an older page would misread; the page refuses a
/// server whose version it doesn't know.
const PROTOCOL: u32 = 2;
/// A new hop address needs a proof of work with this many leading zero bits: about a million
/// hashes, a quarter of a second in a desktop browser. Known ones register again for free.
const POW_BITS: u32 = 20;
/// The salt the work covers changes this often, and the one before still counts, so work
/// can't be stockpiled for more than twice this.
const POW_SALT_LIFE: Duration = Duration::from_secs(600);
const POW_NEEDED: &str = "proof of work needed";
/// The most hop addresses kept in memory.
const MAX_DEPOSITS: usize = 100_000;

/// No lock is held across an Electrum call, and no request holds two at once, so a slow
/// chain lookup stalls only its own page. Stats and Donation hold theirs across a disk write.
struct App {
    network: Network,
    chain: Chain,
    service: Mutex<Service>,
    deposits: Mutex<Deposits>,
    /// Derives the proof-of-work salts. Made at each start, so a restart makes them all new.
    pow_secret: [u8; 32],
    root: PathBuf,
    stats: Stats,
    donation: Option<Donation>,
}

/// The mainnet donation wallet, used when UNRAVEL_DONATION isn't set. It's in the source so
/// anyone can see where donations go, which also makes every donation public.
const DONATION_DESCRIPTOR: Option<&str> = Some(
    "tr([fc739413/86h/0h/0h]xpub6BqAzFncdz3bYRdw2biQxUQYFJ3sd4j1ndJZqGXXuG95vCNahFu7SpjzUkjx2yJREtpwE679s6ELj545Q71MLsr9EQkTWgszeXPUdj33Thf/<0;1>/*)#8dyae2dl",
);

/// How many of the donation wallet's receive addresses are handed out. They go out in turn,
/// then again from the first, so however many a script asks for, a wallet with this gap
/// limit finds every donation. Two donors share an address only once this many have gone out.
const DONATION_ADDRESSES: u32 = 1000;

/// The most hop addresses the donations file lists. Each costs a proof of work and nothing
/// else, so without a cap a script could fill the disk. 100,000 lines is about 22 MB.
const MAX_DONATION_HOPS: usize = 100_000;

/// The donation wallet, from a descriptor such as `tr(xpub.../0/*)` in UNRAVEL_DONATION.
///
/// Each browser keeps the address it was given, so pressing donate again doesn't use up
/// another one. Its locks are held across a disk write, but only donation requests wait on them.
struct Donation {
    descriptor: Descriptor<DescriptorPublicKey>,
    network: Network,
    /// How many addresses have been handed out. The next is at index `next % DONATION_ADDRESSES`.
    next: Mutex<u64>,
    /// Holds `next`, so a restart carries on where it left off.
    index_file: PathBuf,
    /// Lists each hop address that pays the donation wallet, with its descriptor. Spending
    /// through the safety net needs the internal key, which the hop address doesn't reveal, so
    /// without this line a donation whose donor never comes back to forward would be lost.
    hops_file: PathBuf,
    /// The lines in `hops_file`, so recording one doesn't read the whole file.
    recorded: Mutex<HashSet<String>>,
    /// The index of each address that can go out, by its script. A hop address to any of them
    /// is a donation, however the donor got the address.
    addresses: HashMap<ScriptBuf, u32>,
}

impl Donation {
    fn new(
        descriptor: &str,
        network: Network,
        index_file: PathBuf,
        hops_file: PathBuf,
    ) -> Result<Self, String> {
        let next = match std::fs::read_to_string(&index_file) {
            Ok(text) => text
                .trim()
                .parse()
                .map_err(|e| format!("{} doesn't hold an index: {e}", index_file.display()))?,
            Err(e) if e.kind() == ErrorKind::NotFound => 0,
            Err(e) => return Err(format!("can't read {}: {e}", index_file.display())),
        };
        let recorded = match std::fs::read_to_string(&hops_file) {
            Ok(text) => {
                // A crash mid-append leaves a partial line. The next line must not join it.
                if !text.is_empty() && !text.ends_with('\n') {
                    OpenOptions::new()
                        .append(true)
                        .open(&hops_file)
                        .and_then(|mut file| file.write_all(b"\n"))
                        .map_err(|e| format!("can't repair {}: {e}", hops_file.display()))?;
                }
                text.lines().map(str::to_string).collect()
            }
            Err(e) if e.kind() == ErrorKind::NotFound => HashSet::new(),
            Err(e) => return Err(format!("can't read {}: {e}", hops_file.display())),
        };
        let descriptor = Self::parse(descriptor)?;
        let addresses = (0..DONATION_ADDRESSES)
            .map(|index| Ok((derive(&descriptor, index, network)?.script_pubkey(), index)))
            .collect::<Result<_, String>>()?;
        Ok(Self {
            descriptor,
            network,
            next: Mutex::new(next),
            index_file,
            hops_file,
            recorded: Mutex::new(recorded),
            addresses,
        })
    }

    fn parse(descriptor: &str) -> Result<Descriptor<DescriptorPublicKey>, String> {
        let descriptor = descriptor.trim();
        // A mistyped descriptor would send donations to a wallet nobody holds.
        let descriptor = match descriptor.split_once('#') {
            Some((body, checksum)) => {
                if desc_checksum(body).map_err(|e| e.to_string())? != checksum {
                    return Err("the descriptor's checksum doesn't match".into());
                }
                body
            }
            None => descriptor,
        };
        // Wallets export `<0;1>/*` for receive and change; donations use receive.
        let descriptor: Descriptor<DescriptorPublicKey> = descriptor
            .replace("<0;1>", "0")
            .parse()
            .map_err(|e| format!("{e}"))?;
        // The page's destination is a taproot address, so a donor couldn't use any other kind.
        if !matches!(descriptor, Descriptor::Tr(_)) {
            return Err("the donation wallet must be a taproot one, tr(...)".into());
        }
        if !descriptor.has_wildcard() {
            return Err("the descriptor needs a /* to derive addresses from".into());
        }
        if descriptor.is_multipath() {
            return Err("the descriptor needs one receive path, such as /0/* or /<0;1>/*".into());
        }
        // An xpub can't derive a hardened step, and miniscript panics trying.
        let hardened = descriptor.for_any_key(|key| {
            key.has_hardened_step()
                || matches!(key, DescriptorPublicKey::XPub(xpub) if xpub.wildcard == Wildcard::Hardened)
        });
        if hardened {
            return Err("the descriptor can't derive addresses: it has a hardened step".into());
        }
        // Anything else that stops it deriving shows up now, not at the first donation.
        descriptor
            .at_derivation_index(0)
            .map_err(|e| e.to_string())?
            .address(Network::Bitcoin)
            .map_err(|e| format!("the descriptor can't derive addresses: {e}"))?;
        Ok(descriptor)
    }

    /// Hands out the next receive address in turn, with its index.
    fn reserve(&self) -> Result<(u32, Address), String> {
        let mut next = lock(&self.next);
        let index = (*next % u64::from(DONATION_ADDRESSES)) as u32;
        let address = self.address(index)?;
        // Saved before the address leaves, so a crash can't hand it out again soon. Synced
        // before the rename, or a crash could leave an empty file in its place.
        let saved = self.index_file.with_extension("new");
        private_file(&saved)
            .and_then(|mut file| {
                file.write_all((*next + 1).to_string().as_bytes())?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&saved, &self.index_file))
            .map_err(|e| {
                eprintln!(
                    "can't save the donation index in {}: {e}",
                    self.index_file.display()
                );
                "The server can't hand out a donation address right now. Try again later."
            })?;
        *next += 1;
        Ok((index, address))
    }

    fn address(&self, index: u32) -> Result<Address, String> {
        derive(&self.descriptor, index, self.network)
    }

    /// Whether `x` is one of the addresses that can go out.
    fn covers(&self, x: &Address) -> bool {
        self.addresses.contains_key(&x.script_pubkey())
    }

    /// Whether `address` is the one handed out at `index`.
    fn issued(&self, address: &str, index: u32) -> bool {
        let handed_out = (*lock(&self.next)).min(u64::from(DONATION_ADDRESSES));
        u64::from(index) < handed_out
            && self
                .address(index)
                .is_ok_and(|issued| issued.to_string() == address)
    }

    /// Adds a hop address that pays the donation wallet to the hops file, once.
    fn record(&self, deposit: &Deposit) -> Result<(), String> {
        let line = format!("{} {}", deposit.address(), deposit.descriptor());
        // Held so that two pages registering the same hop address at once add it once.
        let mut recorded = lock(&self.recorded);
        if recorded.contains(&line) {
            return Ok(());
        }
        if recorded.len() >= MAX_DONATION_HOPS {
            eprintln!("{} is full", self.hops_file.display());
            return Err("The server can't record this donation right now. Try again later.".into());
        }
        OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.hops_file)
            .and_then(|mut file| {
                file.write_all(format!("{line}\n").as_bytes())?;
                file.sync_all()
            })
            .map_err(|e| {
                eprintln!(
                    "can't record a donation in {}: {e}",
                    self.hops_file.display()
                );
                "The server can't record this donation right now. Try again later.".to_string()
            })?;
        recorded.insert(line);
        Ok(())
    }
}

fn derive(
    descriptor: &Descriptor<DescriptorPublicKey>,
    index: u32,
    network: Network,
) -> Result<Address, String> {
    descriptor
        .at_derivation_index(index)
        .map_err(|e| e.to_string())?
        .address(network)
        .map_err(|e| e.to_string())
}

/// Running totals of what the service has done, in `<network>-stats` beside the service key.
/// Sums only, with no addresses, txids or times, so the file can't tie a forward to anyone.
/// Comparing two readings could, by matching a jump to a transaction on chain, so there is
/// no endpoint for it: read the file on the server. A file that doesn't parse stops the
/// server, since starting again from zero would quietly lose the totals. Like Donation's,
/// its lock is held across a disk write, but only stats updates wait on it.
struct Stats {
    file: PathBuf,
    counts: Mutex<Counts>,
}

#[derive(Default, Debug, PartialEq)]
struct Counts {
    /// Forwards broadcast, and the sats they carried, by where they went: a withdrawal's
    /// hop address to the destination X, a deposit's to the exchange's deposit address E,
    /// or a deposit's back to X.
    withdrawals: u64,
    withdrawn_sat: u64,
    deposits: u64,
    deposited_sat: u64,
    returns: u64,
    returned_sat: u64,
    /// BIP-322 proofs signed.
    proofs: u64,
    failed_broadcasts: u64,
    /// How many confirmations a deposit had when it was forwarded: within an hour, a day,
    /// a week, or later. A rough measure of how long people take to come back.
    forwarded_within_an_hour: u64,
    forwarded_within_a_day: u64,
    forwarded_within_a_week: u64,
    forwarded_later: u64,
}

impl Counts {
    /// Each counter with the name it has in the file.
    fn fields(&mut self) -> [(&'static str, &mut u64); 12] {
        [
            ("withdrawals", &mut self.withdrawals),
            ("withdrawn_sat", &mut self.withdrawn_sat),
            ("deposits", &mut self.deposits),
            ("deposited_sat", &mut self.deposited_sat),
            ("returns", &mut self.returns),
            ("returned_sat", &mut self.returned_sat),
            ("proofs", &mut self.proofs),
            ("failed_broadcasts", &mut self.failed_broadcasts),
            ("forwarded_within_an_hour", &mut self.forwarded_within_an_hour),
            ("forwarded_within_a_day", &mut self.forwarded_within_a_day),
            ("forwarded_within_a_week", &mut self.forwarded_within_a_week),
            ("forwarded_later", &mut self.forwarded_later),
        ]
    }

    fn text(&mut self) -> String {
        self.fields()
            .iter()
            .map(|(name, value)| format!("{name} {value}\n"))
            .collect()
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut counts = Self::default();
        for line in text.lines() {
            let (name, value) = line.split_once(' ').ok_or(format!("bad line {line:?}"))?;
            let value = value
                .trim()
                .parse()
                .map_err(|_| format!("bad count {line:?}"))?;
            let mut fields = counts.fields();
            let (_, slot) = fields
                .iter_mut()
                .find(|(n, _)| *n == name)
                .ok_or(format!("unknown counter {name:?}"))?;
            **slot = value;
        }
        Ok(counts)
    }

    /// One forward of `sat` from `deposit`'s hop address by `tx`, whose deposit had
    /// `confirmations` when the forward was built.
    fn forwarded(
        &mut self,
        deposit: &Deposit,
        tx: &Transaction,
        sat: u64,
        confirmations: Option<u32>,
    ) {
        let pays = |address: &Address| {
            tx.output
                .iter()
                .any(|o| o.script_pubkey == address.script_pubkey())
        };
        let (count, total) = match deposit.exchange() {
            None => (&mut self.withdrawals, &mut self.withdrawn_sat),
            Some(e) if pays(e) => (&mut self.deposits, &mut self.deposited_sat),
            Some(_) => (&mut self.returns, &mut self.returned_sat),
        };
        *count += 1;
        *total += sat;
        if let Some(confirmations) = confirmations {
            *match confirmations {
                0..=6 => &mut self.forwarded_within_an_hour,
                7..=144 => &mut self.forwarded_within_a_day,
                145..=1008 => &mut self.forwarded_within_a_week,
                _ => &mut self.forwarded_later,
            } += 1;
        }
    }
}

impl Stats {
    fn new(file: PathBuf) -> Result<Self, String> {
        let counts = match std::fs::read_to_string(&file) {
            Ok(text) => Counts::parse(&text).map_err(|e| format!("{}: {e}", file.display()))?,
            Err(e) if e.kind() == ErrorKind::NotFound => Counts::default(),
            Err(e) => return Err(format!("can't read {}: {e}", file.display())),
        };
        Ok(Self {
            file,
            counts: Mutex::new(counts),
        })
    }

    /// Applies `update` and saves. A save that fails is reported, and the count stays in
    /// memory for the next one.
    fn bump(&self, update: impl FnOnce(&mut Counts)) {
        let mut counts = lock(&self.counts);
        update(&mut counts);
        // Written whole, synced and renamed into place, so a crash leaves the last full file.
        let saved = self.file.with_extension("new");
        let result = private_file(&saved)
            .and_then(|mut file| {
                file.write_all(counts.text().as_bytes())?;
                file.sync_all()
            })
            .and_then(|()| std::fs::rename(&saved, &self.file));
        if let Err(e) = result {
            eprintln!("can't save the stats in {}: {e}", self.file.display());
        }
    }
}

/// Creates or truncates `path` readable by the server's user alone, like the key file, rather
/// than at whatever the umask allows.
fn private_file(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

fn main() {
    // The folder holding web/, and target/ for the regtest node. Defaults to the source tree.
    let root = std::env::var("UNRAVEL_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."));
    let network: Network = std::env::var("UNRAVEL_NETWORK")
        .map(|n| {
            n.parse()
                .expect("UNRAVEL_NETWORK: bitcoin, signet, testnet4 or regtest")
        })
        .unwrap_or(Network::Regtest);
    // Outside target/ for real networks: `cargo clean` must not take the key with it.
    let key_file = std::env::var("UNRAVEL_KEY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| match network {
            Network::Regtest => root.join("target/service.key"),
            _ => {
                let home = std::env::var("HOME").expect("HOME or UNRAVEL_KEY_FILE");
                let dir = Path::new(&home).join(".config/unravel-rule");
                std::fs::create_dir_all(&dir).unwrap();
                dir.join(format!("{network}.key"))
            }
        });
    // The regtest demo's key is disposable; a real network's is created only on request.
    // Read before connecting anywhere, so a missing key stops the start at once.
    let create_key =
        network == Network::Regtest || std::env::var("UNRAVEL_CREATE_KEY").is_ok_and(|v| v == "1");
    let secret = service_secret(&key_file, create_key);
    let chain = match network {
        Network::Regtest => {
            let datadir = root.join("target/demo-node");
            std::fs::create_dir_all(&datadir).unwrap();
            let mut conf = bitcoind::Conf::default();
            conf.tmpdir = Some(datadir);
            let node = bitcoind::BitcoinD::with_conf(bitcoind::exe_path().unwrap(), &conf).unwrap();
            let mine_to = new_address(&node);
            node.client.generate_to_address(101, &mine_to).unwrap();
            Chain::Node(node)
        }
        _ => {
            let url = std::env::var("UNRAVEL_ELECTRUM").unwrap_or_else(|_| {
                match network {
                    // Blockstream's current name, then its older one, then another operator,
                    // each used only while those before it fail.
                    Network::Bitcoin => {
                        "ssl://bitcoin-mainnet.blockstream.info:50002,ssl://electrum.blockstream.info:50002,ssl://fulcrum.grey.pw:50002"
                    }
                    Network::Signet => "ssl://mempool.space:60602",
                    Network::Testnet4 => "ssl://mempool.space:40002",
                    _ => panic!("no default Electrum server for {network}; set UNRAVEL_ELECTRUM"),
                }
                .into()
            });
            Chain::Electrum(Electrum::connect(&url, network))
        }
    };

    let fee_policy = SERVICE_FEE.map(|fee| FeePolicy {
        fee_spk: new_address(
            chain
                .node()
                .expect("the service fee address comes from the node"),
        )
        .script_pubkey(),
        fee,
    });
    let service = Service::new(unravel::musig(), secret, fee_policy);
    println!("{network}, service key {}", key_file.display());
    let file = |name: &str| key_file.with_file_name(format!("{network}-{name}"));
    let app = Arc::new(App {
        network,
        chain,
        service: Mutex::new(service),
        deposits: Mutex::default(),
        pow_secret: rand::random(),
        root,
        stats: Stats::new(file("stats")).unwrap_or_else(|e| panic!("stats: {e}")),
        // The built-in wallet is a mainnet one, so test networks have none unless set.
        donation: std::env::var("UNRAVEL_DONATION")
            .ok()
            .or_else(|| {
                DONATION_DESCRIPTOR
                    .filter(|_| network == Network::Bitcoin)
                    .map(str::to_string)
            })
            .map(|d| {
                Donation::new(&d, network, file("donation-index"), file("donations.txt"))
                    .unwrap_or_else(|e| panic!("donation wallet: {e}"))
            }),
    });

    let addr = std::env::var("UNRAVEL_ADDR").unwrap_or_else(|_| "127.0.0.1:8322".into());
    let server = Arc::new(Server::http(&addr).unwrap());
    println!("open http://{addr}");
    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let (app, server) = (app.clone(), server.clone());
            std::thread::spawn(move || {
                for mut request in server.incoming_requests() {
                    // A panic answers 500 instead of silently losing a worker.
                    let reply =
                        std::panic::catch_unwind(AssertUnwindSafe(|| app.handle(&mut request)))
                            .unwrap_or_else(|_| {
                                json_reply(500, &json!({ "error": "internal error" }))
                            });
                    let _ = request.respond(reply);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}

/// A panic elsewhere mustn't take the server down with it: every update under these locks
/// is a single insert, push or increment, so the data is whole even if a holder panicked.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// S, read from `path`, or created there from the OS's RNG on first boot. A new S would
/// orphan every hop address made with the old one, so the file is never overwritten, and on a
/// real network it is only created when `create` says so: a missing key is more likely a lost
/// state directory or a mistyped path than a first boot, and serving with a new key would look
/// healthy while every outstanding hop address fell through to its safety net.
fn service_secret(path: &Path, create: bool) -> Scalar {
    match std::fs::read_to_string(path) {
        Ok(hex) => hex
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{} doesn't hold a valid key", path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound && !create => panic!(
            "no service key at {}. if this really is the first start, set UNRAVEL_CREATE_KEY=1 \
             for this start only; otherwise restore the key from backup",
            path.display()
        ),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let secret = Scalar::random(&mut rand::rngs::OsRng);
            // create_new fails rather than clobber a key that appeared since the read.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap_or_else(|e| panic!("can't create {}: {e}", path.display()));
            file.write_all(secret.to_bytes().to_lower_hex_string().as_bytes())
                .and_then(|()| file.sync_all())
                .unwrap_or_else(|e| panic!("can't write {}: {e}", path.display()));
            println!("created service key {}", path.display());
            secret
        }
        Err(e) => panic!("can't read {}: {e}", path.display()),
    }
}

fn new_address(node: &bitcoind::BitcoinD) -> Address {
    node.client
        .get_new_address(None, Some(AddressType::Bech32m))
        .unwrap()
        .assume_checked()
}

impl App {
    fn handle(&self, request: &mut Request) -> Reply {
        let path = request.url().split('?').next().unwrap_or("").to_string();
        if *request.method() == Method::Get {
            return self.static_file(&path);
        }
        let mut body = String::new();
        // Every API body is well under MAX_BODY, so a bigger one is cut short and fails to parse.
        let _ = request
            .as_reader()
            .take(MAX_BODY)
            .read_to_string(&mut body);
        let body: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        match self.api(&path, &body) {
            Ok(value) => json_reply(200, &value),
            Err(error) => json_reply(400, &json!({ "error": error })),
        }
    }

    fn static_file(&self, path: &str) -> Reply {
        let Some(file) = static_path(&self.root, path) else {
            return Response::from_data(b"not found".to_vec()).with_status_code(404);
        };
        let content_type = match file.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("css") => "text/css",
            Some("js") => "text/javascript",
            Some("wasm") => "application/wasm",
            Some("png") => "image/png",
            _ => "application/octet-stream",
        };
        match std::fs::read(&file) {
            Ok(bytes) => page_reply(bytes, content_type),
            _ => Response::from_data(b"not found".to_vec()).with_status_code(404),
        }
    }

    fn api(&self, path: &str, body: &Value) -> Result<Value, String> {
        let field = |name: &str| -> Result<String, String> {
            body[name]
                .as_str()
                .map(str::to_string)
                .ok_or(format!("missing {name}"))
        };
        match path {
            "/api/info" => {
                Ok(json!({
                    "protocol": PROTOCOL,
                    "network": self.network.to_string(),
                    // The page's withdraw and mine buttons need our own regtest node.
                    "helpers": matches!(self.chain, Chain::Node(_)),
                    "service_pk": lock(&self.service).public_key().to_string(),
                    "donate": self.donation.is_some(),
                }))
            }
            "/api/donate" => {
                let donation = self.donation.as_ref().ok_or("donations aren't set up here")?;
                // A page asks again for the address it was given, and keeps it while it's
                // still this wallet's. Otherwise it gets a new one.
                let kept = body["index"]
                    .as_u64()
                    .and_then(|index| u32::try_from(index).ok())
                    .filter(|&index| {
                        body["address"]
                            .as_str()
                            .is_some_and(|address| donation.issued(address, index))
                    });
                let (index, address) = match kept {
                    Some(index) => (index, donation.address(index)?),
                    None => donation.reserve()?,
                };
                // Upper case fits QR's denser alphanumeric mode, and BIP-21 allows it.
                let qr = QrCode::new(format!("bitcoin:{address}").to_uppercase())
                    .map_err(|e| e.to_string())?
                    .render::<Dense1x2>()
                    // Light text on the dark page: draw the light modules, leave dark ones blank.
                    .dark_color(Dense1x2::Light)
                    .light_color(Dense1x2::Dark)
                    .build();
                Ok(json!({ "address": address.to_string(), "index": index, "qr": qr }))
            }
            "/api/pow" => Ok(json!({
                "salt": pow_salt(&self.pow_secret, pow_epoch()).to_lower_hex_string(),
                "bits": POW_BITS,
            })),
            "/api/deposit" => {
                let (x, user_pk) = (field("x")?, field("user_pk")?);
                // Only a hop address that deposits to an exchange has one.
                let exchange = match &body["exchange"] {
                    Value::Null => None,
                    Value::String(e) => Some(e.as_str()).filter(|e| !e.is_empty()),
                    _ => return Err("bad exchange address".into()),
                };
                let user: Point = user_pk.parse().map_err(|_| "bad user key")?;
                let deposit = Deposit::with_exchange(
                    &unravel::musig(),
                    &x,
                    exchange,
                    self.network,
                    user,
                    lock(&self.service).public_key(),
                )
                .map_err(|e| e.to_string())?;
                let y = deposit.address().to_string();
                if lock(&self.deposits).records.contains_key(&y) {
                    return Ok(json!({ "y": y }));
                }
                let pow = &body["pow"];
                if pow.is_null() {
                    return Err(POW_NEEDED.into());
                }
                let salt = pow["salt"]
                    .as_str()
                    .and_then(|s| <[u8; 32]>::from_hex(s).ok())
                    .ok_or("bad proof of work")?;
                let nonce = pow["nonce"]
                    .as_u64()
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or("bad proof of work")?;
                if !pow_salt_current(&self.pow_secret, &salt, pow_epoch()) {
                    return Err("That proof of work has expired. Try again.".into());
                }
                if !unravel::pow::check(&salt, &x, &user_pk, exchange, nonce, POW_BITS) {
                    return Err("bad proof of work".into());
                }
                if let Some(donation) = &self.donation
                    && donation.covers(deposit.x())
                {
                    donation.record(&deposit)?;
                }
                let watcher = match &self.chain {
                    Chain::Node(node) => {
                        let genesis = node.client.get_block_hash(0).map_err(rpc)?;
                        Some(Watcher::new(genesis, deposit.script_pubkey()))
                    }
                    Chain::Electrum(_) => None,
                };
                // `insert` checks again under the lock: a page reloading twice at once must
                // not replace a record whose forwards are already listed.
                lock(&self.deposits).insert(
                    y.clone(),
                    Record {
                        deposit,
                        watcher,
                        forwards: vec![],
                        ages: HashMap::new(),
                    },
                );
                Ok(json!({ "y": y }))
            }
            "/api/challenge" => {
                let deposit = self.deposit(&field("y")?)?;
                let challenge = field("challenge")?;
                if challenge.len() > MAX_CHALLENGE {
                    return Err("that message is too long".into());
                }
                let request = lock(&self.service)
                    .request(&deposit, Task::Challenge(challenge))
                    .map_err(|e| e.to_string())?;
                Ok(json!(request))
            }
            "/api/status" => {
                let y = field("y")?;
                let utxos = self.utxos(&y)?;
                let y_spk = self.deposit(&y)?.script_pubkey();
                let (forwards, sent): (Vec<Txid>, Vec<(Amount, bool)>) = lock(&self.deposits)
                    .records
                    .get(&y)
                    .ok_or(UNKNOWN)?
                    .forwards
                    .iter()
                    .map(|forward| (forward.txid, (forward.sent, forward.to_x)))
                    .unzip();
                let confirmed = self.chain.confirmed(&forwards, &y_spk);
                let spent = self.spent(&y, !forwards.is_empty(), &utxos)?;
                let deposits: Vec<Value> = utxos
                    .iter()
                    .map(|d| json!({ "outpoint": d.outpoint.to_string(), "sat": d.txout.value.to_sat(), "confirmations": d.confirmations }))
                    .collect();
                let forwards: Vec<Value> = forwards
                    .iter()
                    .zip(confirmed)
                    .zip(sent)
                    .map(|((txid, confirmed), (sent, to_x))| json!({ "txid": txid.to_string(), "confirmed": confirmed, "sat": sent.to_sat(), "to_x": to_x }))
                    .collect();
                // No lookup of X: on a public server it would pair X with the hop address
                // before any forward puts that link on chain.
                Ok(json!({ "deposits": deposits, "forwards": forwards, "spent": spent }))
            }
            "/api/fee" => {
                let market_rate = self.chain.market_rate();
                let Some(fee_rate) = self.chain.fee_rate(market_rate) else {
                    return Ok(json!({ "forward_fee_sat": null }));
                };
                let service_fee = lock(&self.service)
                    .policy()
                    .map(|p| (p.fee_spk.clone(), p.fee));
                let fee_sat = service_fee.as_ref().map_or(0, |(_, fee)| fee.to_sat());
                // `parse_exchange` accepts no output bigger than a taproot one, so this is the most it costs.
                let x = Address::from_str(TAPROOT_ADDRESS)
                    .expect("valid address")
                    .assume_checked()
                    .script_pubkey();
                let forward_fee = forward_fee(x.clone(), service_fee, fee_rate);
                // The forward's one output to X must not be dust.
                let min_deposit = forward_fee
                    .map(|miner| miner.to_sat() + fee_sat + x.minimal_non_dust().to_sat());
                let one_decimal = |sat_per_vb: f64| (sat_per_vb * 10.0).round() / 10.0;
                Ok(json!({
                    "forward_fee_sat": forward_fee.map(Amount::to_sat),
                    "min_deposit_sat": min_deposit,
                    // One decimal: rounding up would show 2.004 sat/vB as 3.
                    "fee_rate": one_decimal(fee_rate.to_sat_per_kwu() as f64 / 250.0),
                    "market_rate": market_rate.map(one_decimal),
                    "max_rate": MAX_FORWARD_SAT_PER_VB,
                }))
            }
            "/api/forward" => {
                let y = field("y")?;
                let deposit = self.deposit(&y)?;
                // A hop address that deposits to an exchange forwards there, unless the
                // user sends the coins back to X, such as a deposit the exchange returned.
                let to = match &body["to_x"] {
                    Value::Bool(true) => deposit.x(),
                    Value::Bool(false) | Value::Null => deposit.onward(),
                    _ => return Err("to_x must be true or false".into()),
                };
                // The page names the deposit when it matters which one goes where.
                let only = match &body["outpoint"] {
                    Value::Null => None,
                    Value::String(outpoint) => {
                        Some(OutPoint::from_str(outpoint).map_err(|_| "that isn't an outpoint")?)
                    }
                    _ => return Err("outpoint must be a string".into()),
                };
                let utxos = self.utxos(&y)?;
                let settling: Vec<OutPoint> = lock(&self.deposits)
                    .records
                    .get(&y)
                    .ok_or(UNKNOWN)?
                    .forwards
                    .iter()
                    .filter(|forward| forward.at.elapsed() < FORWARD_SETTLE)
                    .map(|forward| forward.spends)
                    .collect();
                let confirmed: Vec<_> = utxos
                    .into_iter()
                    .filter(|d| {
                        ready_to_forward(&deposit, d.confirmations)
                            && !settling.contains(&d.outpoint)
                            && only.is_none_or(|only| only == d.outpoint)
                    })
                    .collect();
                if confirmed.is_empty() {
                    return Ok(json!({ "request": null }));
                }
                // Paying 1 sat/vB by default could leave the forward stuck, so it waits.
                let fee_rate = self
                    .chain
                    .fee_rate(self.chain.market_rate())
                    .ok_or("No fee estimate right now. The forward waits until there is one.")?;
                let service_fee = lock(&self.service)
                    .policy()
                    .map(|p| (p.fee_spk.clone(), p.fee));
                // A deposit too small to forward mustn't hold up the ones after it, or
                // anyone could block a hop address by sending it dust.
                let (utxo, tx) = confirmed
                    .into_iter()
                    .find_map(|utxo| {
                        let tx = unravel::forward::build(
                            utxo.outpoint,
                            &utxo.txout,
                            to.script_pubkey(),
                            service_fee.clone(),
                            fee_rate,
                        )?;
                        Some((utxo, tx))
                    })
                    .ok_or("deposit too small to forward")?;
                if let Some(record) = lock(&self.deposits).records.get_mut(&y) {
                    record.ages.insert(utxo.outpoint, utxo.confirmations);
                }
                let request = lock(&self.service)
                    .request(
                        &deposit,
                        Task::Forward {
                            tx,
                            prevout: utxo.txout,
                        },
                    )
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "request": request }))
            }
            "/api/complete" => {
                let y = field("y")?;
                let deposit = self.deposit(&y)?;
                let response: SignResponse =
                    serde_json::from_value(body["response"].clone()).map_err(|e| e.to_string())?;
                let (task, signature) = lock(&self.service)
                    .complete(&deposit, response)
                    .map_err(|e| e.to_string())?;
                match task {
                    Task::Challenge(_) => {
                        self.stats.bump(|c| c.proofs += 1);
                        Ok(json!({ "proof": unravel::bip322::encode(&task.witness(signature)) }))
                    }
                    Task::Forward { mut tx, prevout } => {
                        unravel::forward::finalize(&mut tx, signature);
                        let txid = self
                            .chain
                            .broadcast(&tx)
                            .inspect_err(|_| self.stats.bump(|c| c.failed_broadcasts += 1))?;
                        let spends = tx.input[0].previous_output;
                        let x = deposit.x().script_pubkey();
                        let to_x = tx.output.iter().any(|output| output.script_pubkey == x);
                        let to = if to_x {
                            x
                        } else {
                            deposit.onward().script_pubkey()
                        };
                        let sent = tx
                            .output
                            .iter()
                            .find(|output| output.script_pubkey == to)
                            .map_or(Amount::ZERO, |output| output.value);
                        // Broadcasting the same forward again succeeds, but it's one forward.
                        let first = {
                            let mut deposits = lock(&self.deposits);
                            let Some(record) = deposits.records.get_mut(&y) else {
                                // Evicted since the request, but the forward is out all the same.
                                return Ok(json!({ "txid": txid.to_string() }));
                            };
                            if record.forwards.iter().any(|forward| forward.txid == txid) {
                                None
                            } else {
                                record.forwards.push(Forward {
                                    txid,
                                    spends,
                                    at: Instant::now(),
                                    sent,
                                    to_x,
                                });
                                Some(record.ages.remove(&spends))
                            }
                        };
                        if let Some(confirmations) = first {
                            let sat = prevout.value.to_sat();
                            self.stats
                                .bump(|c| c.forwarded(&deposit, &tx, sat, confirmations));
                        }
                        Ok(json!({ "txid": txid.to_string() }))
                    }
                }
            }
            "/api/demo/x" => Ok(json!({ "x": new_address(self.chain.node()?).to_string() })),
            "/api/demo/withdraw" => {
                let y = self.deposit(&field("y")?)?.address();
                let amount = Amount::from_sat(body["sat"].as_u64().unwrap_or(100_000));
                // Like an exchange: deduct the network fee from the amount, and signal RBF.
                let txid = self
                    .chain
                    .node()?
                    .client
                    .send_to_address(&y, amount, None, None, Some(true), Some(true), None, None)
                    .map_err(rpc)?;
                Ok(json!({ "txid": txid.to_string() }))
            }
            "/api/demo/mine" => {
                let node = self.chain.node()?;
                node.client
                    .generate_to_address(1, &new_address(node))
                    .map_err(rpc)?;
                Ok(json!({ "height": node.client.get_block_count().map_err(rpc)? }))
            }
            _ => Err("no such endpoint".into()),
        }
    }

    fn deposit(&self, y: &str) -> Result<Deposit, String> {
        lock(&self.deposits)
            .records
            .get(y)
            .map(|record| record.deposit.clone())
            .ok_or_else(|| UNKNOWN.into())
    }

    /// Whether the hop address `y` has ever spent, read from the chain so a restart, which
    /// forgets the forwards, doesn't forget this. The page sends a deposit to the exchange
    /// unasked only before then. `None` while there are no deposits to decide about, which
    /// saves the lookup.
    fn spent(
        &self,
        y: &str,
        forwarded: bool,
        utxos: &[DepositUtxo],
    ) -> Result<Option<bool>, String> {
        if forwarded {
            return Ok(Some(true));
        }
        if utxos.is_empty() {
            return Ok(None);
        }
        match &self.chain {
            Chain::Node(_) => {
                let deposits = lock(&self.deposits);
                let record = deposits.records.get(y).ok_or(UNKNOWN)?;
                let watcher = record
                    .watcher
                    .as_ref()
                    .expect("node records have a watcher");
                Ok(Some(watcher.has_spent()))
            }
            Chain::Electrum(electrum) => electrum.has_spent(&self.deposit(y)?, utxos).map(Some),
        }
    }

    /// Unspent outputs at the hop address `y`, including unconfirmed ones that haven't been
    /// replaced.
    fn utxos(&self, y: &str) -> Result<Vec<DepositUtxo>, String> {
        match &self.chain {
            // The regtest node is local and quick, so its watchers sync under the lock.
            Chain::Node(node) => {
                let mut deposits = lock(&self.deposits);
                let record = deposits.records.get_mut(y).ok_or(UNKNOWN)?;
                let watcher = record
                    .watcher
                    .as_mut()
                    .expect("node records have a watcher");
                sync(node, watcher)
            }
            Chain::Electrum(electrum) => electrum.utxos(&self.deposit(y)?),
        }
    }
}

fn sync(node: &bitcoind::BitcoinD, watcher: &mut Watcher) -> Result<Vec<DepositUtxo>, String> {
    let client = &node.client;
    let mut emitter = Emitter::new(client, watcher.tip(), 0, watcher.unconfirmed_txs());
    while let Some(event) = emitter.next_block().map_err(rpc)? {
        let (height, connected_to) = (event.block_height(), event.connected_to());
        watcher.apply_block(&event.block, height, connected_to);
    }
    let mempool = emitter.mempool().map_err(rpc)?;
    watcher.apply_mempool(mempool.update, mempool.evicted);
    Ok(watcher.deposits())
}

const UNKNOWN: &str = "unknown deposit address";

fn pow_epoch() -> u64 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    now.as_secs() / POW_SALT_LIFE.as_secs()
}

/// The salt for one `POW_SALT_LIFE`. Derived rather than stored, so nothing needs rotating.
fn pow_salt(secret: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut data = secret.to_vec();
    data.extend(epoch.to_be_bytes());
    sha256::Hash::hash(&data).to_byte_array()
}

fn pow_salt_current(secret: &[u8; 32], salt: &[u8; 32], epoch: u64) -> bool {
    [epoch, epoch.saturating_sub(1)]
        .into_iter()
        .any(|e| pow_salt(secret, e) == *salt)
}

impl Chain {
    fn node(&self) -> Result<&bitcoind::BitcoinD, String> {
        match self {
            Chain::Node(node) => Ok(node),
            Chain::Electrum(_) => Err("only the regtest demo has a node".into()),
        }
    }

    /// Whether each of `txids`, forwards from the hop address `y`, has confirmed.
    fn confirmed(&self, txids: &[Txid], y: &Script) -> Vec<bool> {
        match self {
            Chain::Node(node) => txids
                .iter()
                .map(|txid| node.client.get_mempool_entry(txid).is_err())
                .collect(),
            // Electrum can't look up a transaction's status by txid alone, only an address's.
            Chain::Electrum(electrum) => {
                let history = match txids {
                    [] => vec![],
                    _ => electrum
                        .call(|client| client.script_get_history(y))
                        .unwrap_or_default(),
                };
                txids
                    .iter()
                    .map(|txid| history.iter().any(|h| h.tx_hash == *txid && h.height > 0))
                    .collect()
            }
        }
    }

    fn broadcast(&self, tx: &Transaction) -> Result<Txid, String> {
        match self {
            Chain::Node(node) => node.client.send_raw_transaction(tx).map_err(rpc),
            Chain::Electrum(electrum) => electrum
                .call(|client| client.transaction_broadcast(tx))
                .map_err(|e| format!("broadcast failed: {e}")),
        }
    }

    /// The going rate for the next block, in sat/vB.
    fn market_rate(&self) -> Option<f64> {
        match self {
            Chain::Node(_) => None,
            Chain::Electrum(electrum) => electrum.market_rate(),
        }
    }

    /// The forward's rate: `market_rate` plus 5%, so the forward isn't left at its margin,
    /// within the bounds, or `None` without one.
    fn fee_rate(&self, market_rate: Option<f64>) -> Option<FeeRate> {
        if let Chain::Node(_) = self {
            return Some(FORWARD_FEE_RATE);
        }
        Some(clamp_fee_rate(market_rate? * 1.05))
    }
}

const BACKEND_DOWN: &str = "The chain backend isn't answering. Try again soon.";

impl Electrum {
    /// Connects to the first of a comma-separated list of servers that answers, and refuses
    /// any on another network: its answers would look valid.
    fn connect(urls: &str, network: Network) -> Electrum {
        let urls: Vec<String> = urls
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(String::from)
            .collect();
        assert!(!urls.is_empty(), "no Electrum server given");
        let electrum = Electrum {
            network,
            current: AtomicUsize::new(0),
            connections: (0..WORKERS).map(|_| Mutex::new(None)).collect(),
            fee: Mutex::new(None),
            urls,
        };
        // Each failure moves on to the next server, so this tries each one once.
        for _ in 0..electrum.urls.len() {
            if electrum.call(|client| client.block_header(0)).is_ok() {
                return electrum;
            }
        }
        panic!("no {network} Electrum server answered: {}", electrum.urls.join(", "));
    }

    /// A new connection, checked to be on this network.
    fn open(&self, url: &str) -> Result<electrum_client::Client, String> {
        // One retry, on a fresh connection, for one the server dropped while it sat idle.
        let config = electrum_client::ConfigBuilder::new()
            .timeout(Some(20))
            .retry(1)
            .build();
        let client = electrum_client::Client::from_config(url, config).map_err(|e| failure(&e))?;
        let genesis = client.block_header(0).map_err(|e| failure(&e))?;
        if genesis.block_hash() != bitcoin::constants::genesis_block(self.network).block_hash() {
            return Err(format!("it isn't a {} server", self.network));
        }
        Ok(client)
    }

    fn call<T>(
        &self,
        call: impl FnOnce(&electrum_client::Client) -> Result<T, electrum_client::Error>,
    ) -> Result<T, String> {
        let mut slot = self
            .connections
            .iter()
            .find_map(|connection| connection.try_lock().ok())
            .unwrap_or_else(|| lock(&self.connections[0]));
        let (server, client) = match &mut *slot {
            Some((server, client)) => (*server, client),
            None => {
                let server = self.current.load(Ordering::Relaxed);
                match self.open(&self.urls[server % self.urls.len()]) {
                    Ok(client) => {
                        let (_, client) = slot.insert((server, client));
                        (server, client)
                    }
                    Err(e) => return Err(self.failed(server, &e)),
                }
            }
        };
        match call(client) {
            Ok(value) => Ok(value),
            // A refusal, such as a rejected transaction, comes over a working connection, and
            // goes to the page.
            Err(electrum_client::Error::Protocol(reason)) => Err(match reason["message"].as_str() {
                Some(message) => message.to_string(),
                None => reason.to_string(),
            }),
            Err(e) => {
                *slot = None;
                Err(self.failed(server, &failure(&e)))
            }
        }
    }

    /// The going rate for the next block, asked at most once per `FEE_CACHE`. A failure isn't
    /// kept, so the next request asks again.
    fn market_rate(&self) -> Option<f64> {
        if let Some((at, rate)) = *lock(&self.fee)
            && at.elapsed() < FEE_CACHE
        {
            return Some(rate);
        }
        // In BTC per kvB, and -1 when the server has no estimate yet.
        let rate = self
            .call(|client| client.estimate_fee(1))
            .ok()
            .filter(|&btc_per_kvb| btc_per_kvb > 0.0)?
            * 100_000.0;
        *lock(&self.fee) = Some((Instant::now(), rate));
        Some(rate)
    }

    /// Logs a failed connection, and sends new connections to the next server. Only the first
    /// worker to see a server fail moves on, so several failing at once skip just one.
    fn failed(&self, server: usize, e: &str) -> String {
        let urls = &self.urls;
        eprintln!("chain backend: {}: {e}", urls[server % urls.len()]);
        let moved =
            self.current
                .compare_exchange(server, server + 1, Ordering::Relaxed, Ordering::Relaxed);
        if urls.len() > 1 && moved.is_ok() {
            eprintln!("chain backend: now using {}", urls[(server + 1) % urls.len()]);
        }
        BACKEND_DOWN.into()
    }

    /// Whether the hop address has spent anything, given its unspent outputs: only spending
    /// puts a transaction in its history that none of them came from.
    fn has_spent(&self, deposit: &Deposit, utxos: &[DepositUtxo]) -> Result<bool, String> {
        let history = self.call(|client| client.script_get_history(&deposit.script_pubkey()))?;
        Ok(history
            .iter()
            .any(|h| !utxos.iter().any(|u| u.outpoint.txid == h.tx_hash)))
    }

    fn utxos(&self, deposit: &Deposit) -> Result<Vec<DepositUtxo>, String> {
        let tip = self.call(|client| {
            let tip = client.block_headers_subscribe()?;
            // Subscribing also queues a notification per new block. Nothing reads them.
            while let Ok(Some(_)) = client.block_headers_pop() {}
            Ok(tip.height)
        })?;
        let spk = deposit.script_pubkey();
        let utxos = self.call(|client| client.script_list_unspent(&spk))?;
        Ok(utxos
            .into_iter()
            .map(|u| DepositUtxo {
                outpoint: OutPoint::new(u.tx_hash, u.tx_pos as u32),
                txout: TxOut {
                    value: Amount::from_sat(u.value),
                    script_pubkey: spk.clone(),
                },
                // Height 0 is the mempool.
                confirmations: match u.height {
                    0 => 0,
                    height => (tip + 1).saturating_sub(height) as u32,
                },
            })
            .collect())
    }
}

/// What went wrong, for the log. electrum-client gives up after its last retry without saying
/// why, so the first attempt's error is what's left.
fn failure(e: &electrum_client::Error) -> String {
    match e {
        electrum_client::Error::AllAttemptsErrored(errors) if !errors.is_empty() => errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; "),
        electrum_client::Error::AllAttemptsErrored(_) => "no answer, and no reason given".into(),
        e => e.to_string(),
    }
}

fn rpc(e: bitcoind::bitcoincore_rpc::Error) -> String {
    e.to_string()
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}

/// The file a GET for `path` serves, or `None` if it may not. Every segment must be a plain
/// name: an empty one (`//etc/passwd`) would make the rest an absolute path that `join`
/// follows out of the web folder, and one starting with a dot could be `..`.
fn static_path(root: &Path, path: &str) -> Option<PathBuf> {
    let file = match path {
        "/" => "static/index.html",
        "/about" => "static/about.html",
        "/recover" => "pkg/recover.html",
        _ => {
            let rest = path.strip_prefix('/')?;
            let plain = |segment: &str| {
                !segment.is_empty()
                    && !segment.starts_with('.')
                    && segment
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
            };
            if !rest.split('/').all(plain) {
                return None;
            }
            return Some(match rest.strip_prefix("pkg/") {
                Some(_) => root.join("web").join(rest),
                None => root.join("web/static").join(rest),
            });
        }
    };
    Some(root.join("web").join(file))
}

/// The going rate in sat/vB, held within the bounds, as a fee rate rounded up.
fn clamp_fee_rate(sat_per_vb: f64) -> FeeRate {
    let sat_per_vb = sat_per_vb.clamp(MIN_FORWARD_SAT_PER_VB, MAX_FORWARD_SAT_PER_VB);
    FeeRate::from_sat_per_kwu((sat_per_vb * 250.0).ceil() as u64)
}

/// Whether a deposit with `confirmations` can be forwarded yet. Exchanges often fee-bump a
/// withdrawal, which drops a forward that spent the original, and the user may have closed the
/// page by then. So a withdrawal waits for a confirmation. Coins sent to a hop address that
/// deposits to an exchange come from the user's own wallet, and the page stays open for them
/// to choose where the coins go, so those go on at once.
fn ready_to_forward(deposit: &Deposit, confirmations: u32) -> bool {
    confirmations >= 1 || deposit.exchange().is_some()
}

/// What a forward to `x` would pay the miners at `fee_rate`. It builds one the same
/// way `/api/forward` does, so the estimate the page shows is what it is later asked to sign.
fn forward_fee(
    x: ScriptBuf,
    service_fee: Option<(ScriptBuf, Amount)>,
    fee_rate: FeeRate,
) -> Option<Amount> {
    // The size doesn't depend on what the deposit's output script is.
    let prevout = TxOut {
        value: Amount::ONE_BTC,
        script_pubkey: x.clone(),
    };
    let tx = unravel::forward::build(OutPoint::null(), &prevout, x, service_fee, fee_rate)?;
    Some(prevout.value - tx.output.iter().map(|o| o.value).sum::<Amount>())
}

/// A page holds the rescue key and signs, so no other site may frame it and steer its clicks.
fn page_reply(bytes: Vec<u8>, content_type: &str) -> Reply {
    Response::from_data(bytes)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Content-Security-Policy", "frame-ancestors 'none'"))
        .with_header(header("Referrer-Policy", "no-referrer"))
        .with_header(header("X-Frame-Options", "DENY"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
}

fn json_reply(status: u16, value: &Value) -> Reply {
    Response::from_data(value.to_string().into_bytes())
        .with_status_code(status)
        .with_header(header("Content-Type", "application/json"))
        // A page served from anywhere, such as a copy the user checked and hosts themselves,
        // may use this server. The page sends plain-text bodies, so there's no preflight.
        .with_header(header("Access-Control-Allow-Origin", "*"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn service_key_is_created_once_then_reused() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/test-service-key");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.key", rand::random::<u64>()));
        let created = service_secret(&path, true);
        assert_eq!(service_secret(&path, false), created);
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&path).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_service_key_is_not_replaced_unasked() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/test-service-key");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{}.key", rand::random::<u64>()));
        let panic = std::panic::catch_unwind(|| service_secret(&path, false)).unwrap_err();
        let message = panic.downcast_ref::<String>().expect("a formatted panic");
        assert!(message.contains("UNRAVEL_CREATE_KEY=1"), "{message}");
        assert!(!path.exists());
    }

    #[test]
    fn api_replies_can_be_read_by_a_page_from_another_site() {
        let reply = json_reply(200, &json!({}));
        assert!(reply
            .headers()
            .iter()
            .any(|h| h.field.equiv("Access-Control-Allow-Origin") && h.value == "*"));
    }

    #[test]
    fn pages_cant_be_framed_by_another_site() {
        let reply = page_reply(vec![], "text/html; charset=utf-8");
        let has = |name: &'static str, value: &str| {
            reply
                .headers()
                .iter()
                .any(|h| h.field.equiv(name) && h.value == value)
        };
        assert!(has("Content-Security-Policy", "frame-ancestors 'none'"));
        assert!(has("X-Frame-Options", "DENY"));
        assert!(has("X-Content-Type-Options", "nosniff"));
    }

    #[test]
    fn forward_fee_estimate_matches_a_one_in_one_out_forward() {
        let x = Address::from_str(TAPROOT_ADDRESS)
            .unwrap()
            .assume_checked()
            .script_pubkey();
        // A signed key-path forward to a taproot address is 111 vB.
        assert_eq!(
            forward_fee(x, None, FORWARD_FEE_RATE),
            Some(Amount::from_sat(222))
        );
    }

    #[test]
    fn static_files_stay_inside_the_web_folder() {
        let root = Path::new("/srv/unravel");
        assert_eq!(
            static_path(root, "/"),
            Some(root.join("web/static/index.html"))
        );
        assert_eq!(
            static_path(root, "/app.js"),
            Some(root.join("web/static/app.js"))
        );
        assert_eq!(
            static_path(root, "/pkg/unravel_web_bg.wasm"),
            Some(root.join("web/pkg/unravel_web_bg.wasm"))
        );
        for bad in [
            "//etc/passwd",
            "/pkg//etc/passwd",
            "/../server.key",
            "/pkg/../../server.key",
            "/.hidden",
            "/a%2f..%2fb",
            "*",
            "http://host/app.js",
            "",
        ] {
            assert_eq!(static_path(root, bad), None, "{bad}");
        }
    }

    #[test]
    fn the_most_a_forward_pays_is_within_the_pages_limit() {
        let x = Address::from_str(TAPROOT_ADDRESS)
            .unwrap()
            .assume_checked()
            .script_pubkey();
        let rate = clamp_fee_rate(1_000.0);
        assert_eq!(rate, clamp_fee_rate(MAX_FORWARD_SAT_PER_VB));
        // The page's MAX_MINER_FEE_SAT in web/static/app.js.
        assert!(forward_fee(x, None, rate).unwrap() <= Amount::from_sat(2_000));
        assert_eq!(clamp_fee_rate(0.0), FeeRate::from_sat_per_vb_u32(1));
        assert_eq!(clamp_fee_rate(2.01), FeeRate::from_sat_per_kwu(503));
    }

    #[test]
    fn proof_of_work_salts_last_two_lifetimes() {
        let secret = [1; 32];
        let salt = pow_salt(&secret, 100);
        assert!(pow_salt_current(&secret, &salt, 100));
        assert!(pow_salt_current(&secret, &salt, 101));
        assert!(!pow_salt_current(&secret, &salt, 102));
        assert!(!pow_salt_current(&[2; 32], &salt, 100));
    }

    #[test]
    fn the_oldest_hop_address_is_forgotten_when_full() {
        let deposit = Deposit::new(
            &unravel::musig(),
            TAPROOT_ADDRESS,
            Network::Bitcoin,
            Point::random(&mut rand::thread_rng()),
            Point::random(&mut rand::thread_rng()),
        )
        .unwrap();
        let record = || Record {
            deposit: deposit.clone(),
            watcher: None,
            forwards: vec![],
            ages: HashMap::new(),
        };
        let mut deposits = Deposits::default();
        for i in 0..MAX_DEPOSITS {
            deposits.insert(i.to_string(), record());
        }
        // Registering again doesn't add a second entry.
        deposits.insert("0".into(), record());
        assert_eq!(deposits.order.len(), MAX_DEPOSITS);
        deposits.insert("new".into(), record());
        assert_eq!(deposits.records.len(), MAX_DEPOSITS);
        assert!(!deposits.records.contains_key("0"));
        assert!(deposits.records.contains_key("1") && deposits.records.contains_key("new"));
    }

    /// Answers Electrum requests over TCP with canned replies, as a mainnet server at height
    /// 850000 would.
    fn fake_electrum(deposit_txid: Txid, forward_txid: Txid) -> String {
        use std::io::{BufRead, BufReader};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let lines = BufReader::new(stream.try_clone().unwrap()).lines();
                for line in lines.map_while(Result::ok) {
                    let request: Value = serde_json::from_str(&line).unwrap();
                    let genesis = bitcoin::constants::genesis_block(Network::Bitcoin).header;
                    let header = bitcoin::consensus::encode::serialize_hex(&genesis);
                    let reply = match request["method"].as_str().unwrap() {
                        "blockchain.block.header" => json!({ "result": header }),
                        "blockchain.headers.subscribe" => {
                            json!({ "result": { "height": 850_000, "hex": header } })
                        }
                        "blockchain.scripthash.listunspent" => json!({ "result": [
                            { "height": 849_999, "tx_hash": deposit_txid, "tx_pos": 1, "value": 50_000 },
                            { "height": 0, "tx_hash": forward_txid, "tx_pos": 0, "value": 600 },
                        ] }),
                        "blockchain.scripthash.get_history" => json!({ "result": [
                            { "height": 849_999, "tx_hash": deposit_txid },
                            { "height": 0, "tx_hash": forward_txid },
                        ] }),
                        "blockchain.estimatefee" => json!({ "result": 0.0001 }),
                        "blockchain.transaction.broadcast" => json!({ "error": {
                            "code": 1, "message": "min relay fee not met"
                        } }),
                        method => panic!("unexpected {method}"),
                    };
                    let mut reply = reply;
                    reply["id"] = request["id"].clone();
                    reply["jsonrpc"] = "2.0".into();
                    writeln!(stream, "{reply}").unwrap();
                }
            }
        });
        url
    }

    #[test]
    fn electrum_reads_deposits_fees_and_refusals() {
        let deposit = Deposit::new(
            &unravel::musig(),
            TAPROOT_ADDRESS,
            Network::Bitcoin,
            Point::random(&mut rand::thread_rng()),
            Point::random(&mut rand::thread_rng()),
        )
        .unwrap();
        let (deposit_txid, forward_txid) = (
            Txid::from_byte_array([1; 32]),
            Txid::from_byte_array([2; 32]),
        );
        let url = fake_electrum(deposit_txid, forward_txid);
        // A mainnet server is refused for another network.
        let wrong = std::panic::catch_unwind(|| Electrum::connect(&url, Network::Testnet4));
        assert!(wrong.is_err());
        // A server that doesn't answer is passed over for the next in the list.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let fallback = Electrum::connect(&format!("tcp://{dead}, {url}"), Network::Bitcoin);
        assert_eq!(fallback.current.load(Ordering::Relaxed), 1);
        assert!(fallback.utxos(&deposit).is_ok());
        // The fake serves one connection at a time.
        drop(fallback);
        let chain = Chain::Electrum(Electrum::connect(&url, Network::Bitcoin));
        let Chain::Electrum(electrum) = &chain else {
            unreachable!()
        };

        let utxos = electrum.utxos(&deposit).unwrap();
        let utxo = |txid| utxos.iter().find(|u| u.outpoint.txid == txid).unwrap();
        assert_eq!(utxo(deposit_txid).outpoint.vout, 1);
        assert_eq!(utxo(deposit_txid).txout.value, Amount::from_sat(50_000));
        assert_eq!(utxo(deposit_txid).confirmations, 2);
        assert_eq!(utxo(forward_txid).confirmations, 0);
        // Every transaction in the history made an unspent output, so nothing was spent.
        assert!(!electrum.has_spent(&deposit, &utxos).unwrap());
        assert!(electrum.has_spent(&deposit, &utxos[..1]).unwrap());

        let y = deposit.script_pubkey();
        let unknown = Txid::from_byte_array([3; 32]);
        assert_eq!(
            chain.confirmed(&[deposit_txid, forward_txid, unknown], &y),
            [true, false, false]
        );
        // 0.0001 BTC per kvB is 10 sat/vB.
        assert_eq!(chain.market_rate(), Some(10.0));
        // Asked again within the minute, it doesn't ask the Electrum server.
        let asked_at = lock(&electrum.fee).unwrap().0;
        assert_eq!(chain.market_rate(), Some(10.0));
        assert_eq!(lock(&electrum.fee).unwrap().0, asked_at);

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        assert_eq!(
            chain.broadcast(&tx).unwrap_err(),
            "broadcast failed: min relay fee not met"
        );
    }

    /// A donation wallet whose files go under target/ and are removed afterwards.
    struct TestWallet(Donation);

    impl TestWallet {
        fn new(descriptor: &str) -> Self {
            let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/test-service-key");
            std::fs::create_dir_all(&dir).unwrap();
            let name = rand::random::<u64>();
            Self(
                Donation::new(
                    descriptor,
                    Network::Bitcoin,
                    dir.join(format!("{name}-donation-index")),
                    dir.join(format!("{name}-donations.txt")),
                )
                .unwrap(),
            )
        }

        /// The same wallet after a restart.
        fn restarted(&self) -> Donation {
            let d = &self.0;
            let descriptor = d.descriptor.to_string();
            Donation::new(
                &descriptor,
                d.network,
                d.index_file.clone(),
                d.hops_file.clone(),
            )
            .unwrap()
        }
    }

    impl Drop for TestWallet {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0.index_file);
            let _ = std::fs::remove_file(&self.0.hops_file);
        }
    }

    // BIP-86's test vector: account m/86'/0'/0'.
    const BIP86_DESCRIPTOR: &str = "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)";

    #[test]
    fn built_in_donation_descriptor_parses() {
        let TestWallet(donation) = &TestWallet::new(DONATION_DESCRIPTOR.unwrap());
        // The donation wallet's first receive address, as the wallet shows it.
        assert_eq!(
            donation.address(0).unwrap().to_string(),
            "bc1prj2f7cu2p95ctxqq8rexy2zefvq9u7q54wumf704yfmvrss6wnjq588msr"
        );
    }

    #[test]
    fn a_descriptor_with_a_wrong_checksum_is_refused() {
        let descriptor = DONATION_DESCRIPTOR.unwrap().replace("#8dyae2dl", "#8dyae2dm");
        assert!(Donation::parse(&descriptor).is_err());
    }

    #[test]
    fn a_descriptor_that_cant_derive_addresses_is_refused() {
        let hardened = BIP86_DESCRIPTOR.replace("<0;1>/*", "0/*h");
        let refused = Donation::parse(&hardened).unwrap_err();
        assert!(refused.contains("hardened step"), "{refused}");
        let three_paths = BIP86_DESCRIPTOR.replace("<0;1>", "<0;1;2>");
        assert!(Donation::parse(&three_paths).is_err());
    }

    #[test]
    fn donation_addresses_go_out_in_turn_and_then_again() {
        let wallet = TestWallet::new(BIP86_DESCRIPTOR);
        let (index, first) = wallet.0.reserve().unwrap();
        assert_eq!(index, 0);
        assert_eq!(
            first.to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        let (index, second) = wallet.0.reserve().unwrap();
        assert_eq!(index, 1);
        assert_eq!(
            second.to_string(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
        // A restart carries on from the saved index, and still knows what it handed out.
        let restarted = wallet.restarted();
        assert!(restarted.issued(&first.to_string(), 0));
        assert_eq!(restarted.reserve().unwrap().0, 2);
        // After the last one, the first again.
        *lock(&restarted.next) = u64::from(DONATION_ADDRESSES) - 1;
        assert_eq!(restarted.reserve().unwrap().0, DONATION_ADDRESSES - 1);
        assert_eq!(restarted.reserve().unwrap(), (0, first));
    }

    #[test]
    fn only_an_address_handed_out_at_its_index_counts_as_issued() {
        let TestWallet(donation) = &TestWallet::new(BIP86_DESCRIPTOR);
        let (_, first) = donation.reserve().unwrap();
        let (_, second) = donation.reserve().unwrap();
        assert!(donation.issued(&second.to_string(), 1));
        assert!(!donation.issued(&first.to_string(), 1));
        // A donation wallet address, but not handed out yet.
        assert!(!donation.issued(&donation.address(2).unwrap().to_string(), 2));
        assert!(!donation.issued(&first.to_string(), u32::MAX));
        assert!(!donation.issued("not an address", 0));
        // Once every address has gone out, each counts, and none past them.
        *lock(&donation.next) = u64::from(DONATION_ADDRESSES) * 3;
        let last = DONATION_ADDRESSES - 1;
        assert!(donation.issued(&donation.address(last).unwrap().to_string(), last));
        let past = DONATION_ADDRESSES;
        assert!(!donation.issued(&donation.address(past).unwrap().to_string(), past));
    }

    #[test]
    fn donation_hop_addresses_are_recorded_once() {
        let wallet = TestWallet::new(BIP86_DESCRIPTOR);
        let donation = &wallet.0;
        let (_, address) = donation.reserve().unwrap();
        let deposit = Deposit::new(
            &unravel::musig(),
            &address.to_string(),
            Network::Bitcoin,
            Point::random(&mut rand::thread_rng()),
            Point::random(&mut rand::thread_rng()),
        )
        .unwrap();
        donation.record(&deposit).unwrap();
        donation.record(&deposit).unwrap();
        let line = format!("{} {}\n", deposit.address(), deposit.descriptor());
        assert_eq!(std::fs::read_to_string(&donation.hops_file).unwrap(), line);
        // A restart still knows it, and a partial line left by a crash doesn't join the next.
        let restarted = TestWallet(wallet.restarted());
        restarted.0.record(&deposit).unwrap();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&donation.hops_file)
            .unwrap();
        file.write_all(b"partial").unwrap();
        let other = Deposit::new(
            &unravel::musig(),
            &address.to_string(),
            Network::Bitcoin,
            Point::random(&mut rand::thread_rng()),
            Point::random(&mut rand::thread_rng()),
        )
        .unwrap();
        restarted.restarted().record(&other).unwrap();
        let other_line = format!("{} {}\n", other.address(), other.descriptor());
        assert_eq!(
            std::fs::read_to_string(&donation.hops_file).unwrap(),
            format!("{line}partial\n{other_line}")
        );
    }

    #[test]
    fn a_donation_is_any_address_that_can_go_out() {
        let TestWallet(donation) = &TestWallet::new(BIP86_DESCRIPTOR);
        // Not handed out yet: a donor may have derived it from the public descriptor.
        let last = donation.address(DONATION_ADDRESSES - 1).unwrap();
        assert!(donation.covers(&last));
        assert!(!donation.covers(&donation.address(DONATION_ADDRESSES).unwrap()));
        // The same wallet's first change address, from BIP-86's test vectors.
        let change =
            Address::from_str("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7")
                .unwrap()
                .assume_checked();
        assert!(!donation.covers(&change));
    }

    #[test]
    fn a_donation_wallet_must_be_taproot() {
        let wpkh = BIP86_DESCRIPTOR.replace("tr(", "wpkh(");
        let wpkh = wpkh.split('#').next().unwrap();
        assert!(Donation::parse(wpkh).unwrap_err().contains("taproot"));
    }

    #[test]
    fn only_a_deposit_to_an_exchange_forwards_unconfirmed() {
        let deposit = |exchange: Option<&str>| {
            Deposit::with_exchange(
                &unravel::musig(),
                TAPROOT_ADDRESS,
                exchange,
                Network::Bitcoin,
                Point::random(&mut rand::thread_rng()),
                Point::random(&mut rand::thread_rng()),
            )
            .unwrap()
        };
        let withdrawal = deposit(None);
        let to_exchange =
            deposit(Some("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"));
        assert!(!ready_to_forward(&withdrawal, 0));
        assert!(ready_to_forward(&withdrawal, 1));
        assert!(ready_to_forward(&to_exchange, 0));
    }

    #[test]
    fn stats_count_forwards_by_direction_and_age() {
        let exchange = "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7";
        let deposit = |exchange: Option<&str>| {
            Deposit::with_exchange(
                &unravel::musig(),
                TAPROOT_ADDRESS,
                exchange,
                Network::Bitcoin,
                Point::random(&mut rand::thread_rng()),
                Point::random(&mut rand::thread_rng()),
            )
            .unwrap()
        };
        let pays = |address: &str| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: Address::from_str(address)
                    .unwrap()
                    .assume_checked()
                    .script_pubkey(),
            }],
        };
        let mut counts = Counts::default();
        counts.forwarded(&deposit(None), &pays(TAPROOT_ADDRESS), 100, Some(1));
        counts.forwarded(&deposit(Some(exchange)), &pays(exchange), 20, Some(144));
        counts.forwarded(&deposit(Some(exchange)), &pays(TAPROOT_ADDRESS), 3, None);
        assert_eq!(
            counts,
            Counts {
                withdrawals: 1,
                withdrawn_sat: 100,
                deposits: 1,
                deposited_sat: 20,
                returns: 1,
                returned_sat: 3,
                forwarded_within_an_hour: 1,
                forwarded_within_a_day: 1,
                ..Counts::default()
            }
        );
    }

    #[test]
    fn stats_survive_a_restart_and_refuse_a_bad_file() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/test-service-key");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{}-stats", rand::random::<u64>()));
        let stats = Stats::new(file.clone()).unwrap();
        stats.bump(|c| {
            c.proofs += 2;
            c.withdrawn_sat += 300;
        });
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("proofs 2\n") && text.contains("withdrawn_sat 300\n"), "{text}");
        let restarted = Stats::new(file.clone()).unwrap();
        assert_eq!(*lock(&restarted.counts), *lock(&stats.counts));
        std::fs::write(&file, "proofs two\n").unwrap();
        assert!(Stats::new(file.clone()).is_err());
        std::fs::write(&file, "fees 1\n").unwrap();
        assert!(Stats::new(file.clone()).is_err());
        let _ = std::fs::remove_file(&file);
    }
}
