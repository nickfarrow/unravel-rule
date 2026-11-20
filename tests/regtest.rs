//! End-to-end on a regtest bitcoind (downloaded by the `bitcoind` crate).

use std::str::FromStr;

use bdk_bitcoind_rpc::Emitter;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use bitcoin::{
    Address, Amount, FeeRate, Network, Transaction, Txid,
    bip32::{DerivationPath, Xpriv},
    secp256k1::Secp256k1,
};
use bitcoind::bitcoincore_rpc::{Client, RpcApi, jsonrpc::serde_json};
use schnorr_fun::fun::Scalar;
use unravel::{
    Deposit, RescueKey,
    protocol::{FeePolicy, Service, Task, User, UserPolicy},
    safety_net,
    watch::Watcher,
};

const NETWORK: Network = Network::Regtest;
const CHALLENGE: &str = "SHAZAM-10698-1793874675547-43a174838f5e6f5e8b4a2ec6e6e13959";
const SERVICE_FEE: Amount = Amount::from_sat(1_000);

struct Env {
    node: bitcoind::BitcoinD,
    /// The user's cold wallet. The destination X is its first receive address.
    cold: Wallet,
    cold_xprv: Xpriv,
    /// The service's own wallet. It receives the fee output and can CPFP with it.
    fee_wallet: Wallet,
    fee_xprv: Xpriv,
    /// The user's one backup. The browser key U is derived from it and X.
    rescue: RescueKey,
    user: User,
    service: Service,
    deposit: Deposit,
    watcher: Watcher,
}

fn wallet(seed: u8) -> (Wallet, Xpriv) {
    let xprv = Xpriv::new_master(NETWORK, &[seed; 32]).unwrap();
    let wallet = Wallet::create(
        format!("tr({xprv}/86h/1h/0h/0/*)"),
        format!("tr({xprv}/86h/1h/0h/1/*)"),
    )
    .network(NETWORK)
    .create_wallet_no_persist()
    .unwrap();
    (wallet, xprv)
}

fn setup() -> Env {
    let mut conf = bitcoind::Conf::default();
    // Keep the node's datadir out of /tmp.
    conf.tmpdir = Some(env!("CARGO_TARGET_TMPDIR").into());
    let node = bitcoind::BitcoinD::with_conf(bitcoind::exe_path().unwrap(), &conf).unwrap();

    let (cold, cold_xprv) = wallet(1);
    let (fee_wallet, fee_xprv) = wallet(2);
    let x = cold.peek_address(KeychainKind::External, 0).address;
    let fee_policy = FeePolicy {
        fee_spk: fee_wallet
            .peek_address(KeychainKind::External, 0)
            .script_pubkey(),
        fee: SERVICE_FEE,
    };

    let mut rng = rand::thread_rng();
    let service = Service::new(
        unravel::musig(),
        Scalar::random(&mut rng),
        Some(fee_policy.clone()),
    );
    let rescue = RescueKey::generate();
    let user = User::new(
        unravel::musig(),
        rescue.tab_secret(&x),
        UserPolicy {
            service_fee: Some(fee_policy),
            max_miner_fee: Amount::from_sat(2_000),
        },
    );
    // The user pastes X and nothing else.
    let deposit = Deposit::new(
        &unravel::musig(),
        &x.to_string(),
        NETWORK,
        user.public_key(),
        service.public_key(),
    )
    .unwrap();
    let genesis = node.client.get_block_hash(0).unwrap();
    let watcher = Watcher::new(genesis, deposit.script_pubkey());

    // The exchange's hot wallet is bitcoind's own.
    let exchange_addr = node
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    node.client
        .generate_to_address(101, &exchange_addr)
        .unwrap();

    Env {
        node,
        cold,
        cold_xprv,
        fee_wallet,
        fee_xprv,
        rescue,
        user,
        service,
        deposit,
        watcher,
    }
}

impl Env {
    fn mine(&self, blocks: u64) {
        let addr = self
            .node
            .client
            .get_new_address(None, None)
            .unwrap()
            .assume_checked();
        self.node.client.generate_to_address(blocks, &addr).unwrap();
    }

    fn sync(&mut self) {
        let client = &self.node.client;
        sync_watcher(client, &mut self.watcher);
        sync_wallet(client, &mut self.cold);
        sync_wallet(client, &mut self.fee_wallet);
    }

    /// The exchange withdraws to Y. Like real exchanges, it deducts its fee from the
    /// amount and signals RBF.
    fn withdraw_to_y(&self, amount: Amount) -> Txid {
        self.node
            .client
            .send_to_address(
                &self.deposit.address(),
                amount,
                None,
                None,
                Some(true),
                Some(true),
                None,
                None,
            )
            .unwrap()
    }

    /// U and S run one signing round trip over the forward of `deposit`.
    fn forward(&mut self, fee_rate: FeeRate) -> Transaction {
        let utxo = self
            .watcher
            .deposits()
            .into_iter()
            .find(|d| d.confirmations >= 1)
            .unwrap();
        let task = Task::Forward {
            tx: unravel::forward::build(
                utxo.outpoint,
                &utxo.txout,
                self.deposit.x().script_pubkey(),
                self.service.policy().map(|p| (p.fee_spk.clone(), p.fee)),
                fee_rate,
            )
            .unwrap(),
            prevout: utxo.txout,
        };
        let request = self.service.request(&self.deposit, task).unwrap();
        let response = self.user.sign_forward(&self.deposit, &request).unwrap();
        let (task, signature) = self.service.complete(&self.deposit, response).unwrap();
        let Task::Forward { mut tx, .. } = task else {
            unreachable!()
        };
        unravel::forward::finalize(&mut tx, signature);
        tx
    }
}

fn sync_watcher(client: &Client, watcher: &mut Watcher) {
    let mut emitter = Emitter::new(client, watcher.tip(), 0, watcher.unconfirmed_txs());
    while let Some(event) = emitter.next_block().unwrap() {
        let (height, connected_to) = (event.block_height(), event.connected_to());
        watcher.apply_block(&event.block, height, connected_to);
    }
    let mempool = emitter.mempool().unwrap();
    watcher.apply_mempool(mempool.update, mempool.evicted);
}

fn sync_wallet(client: &Client, wallet: &mut Wallet) {
    let unconfirmed = wallet
        .transactions()
        .filter(|tx| !tx.chain_position.is_confirmed())
        .map(|tx| tx.tx_node.tx)
        .collect::<Vec<_>>();
    let mut emitter = Emitter::new(client, wallet.latest_checkpoint(), 0, unconfirmed);
    while let Some(event) = emitter.next_block().unwrap() {
        let (height, connected_to) = (event.block_height(), event.connected_to());
        wallet
            .apply_block_connected_to(&event.block, height, connected_to)
            .unwrap();
    }
    let mempool = emitter.mempool().unwrap();
    wallet.apply_unconfirmed_txs(mempool.update);
    wallet.apply_evicted_txs(mempool.evicted);
}

#[test]
fn challenge_withdraw_and_forward_through_an_rbf_bump() {
    let mut env = setup();

    // Verify: U and S sign the exchange's challenge for Y.
    let request = env
        .service
        .request(&env.deposit, Task::Challenge(CHALLENGE.into()))
        .unwrap();
    let response = env
        .user
        .sign_challenge(&env.deposit, &request, CHALLENGE)
        .unwrap();
    let (task, signature) = env.service.complete(&env.deposit, response).unwrap();
    let proof = unravel::bip322::encode(&task.witness(signature));
    println!("Y = {}\nproof = {proof}", env.deposit.address());
    assert!(matches!(
        bip322::verify_simple_encoded(&env.deposit.address().to_string(), CHALLENGE, &proof),
        Ok(bip322::Verification::Valid { .. })
    ));

    // Withdraw, then the exchange bumps the fee: the txid changes under us.
    let first = env.withdraw_to_y(Amount::from_sat(100_000));
    env.sync();
    assert_eq!(env.watcher.deposits()[0].outpoint.txid, first);
    let bumped: serde_json::Value = env
        .node
        .client
        .call("bumpfee", &[first.to_string().into()])
        .unwrap();
    let bumped = Txid::from_str(bumped["txid"].as_str().unwrap()).unwrap();
    assert_ne!(bumped, first);
    env.sync();
    let pending = env.watcher.deposits();
    assert_eq!(pending.len(), 1, "the replaced withdrawal drops out");
    assert_eq!(pending[0].outpoint.txid, bumped);
    assert_eq!(pending[0].confirmations, 0);
    let arrived = pending[0].txout.value;
    assert!(
        arrived < Amount::from_sat(100_000),
        "exchange deducted its fee"
    );

    env.mine(1);
    env.sync();
    assert_eq!(env.watcher.deposits()[0].confirmations, 1);
    assert!(!env.watcher.has_spent());

    // Forward to X.
    let forward = env.forward(FeeRate::from_sat_per_vb_u32(2));
    env.node.client.send_raw_transaction(&forward).unwrap();
    env.mine(1);
    env.sync();
    assert!(env.watcher.has_spent());

    let to_x = env.cold.balance().confirmed;
    let miner_fee = arrived - to_x - SERVICE_FEE;
    println!("arrived {arrived}, to X {to_x}, service fee {SERVICE_FEE}, miner fee {miner_fee}");
    assert_eq!(env.fee_wallet.balance().confirmed, SERVICE_FEE);
    assert_eq!(
        miner_fee,
        FeeRate::from_sat_per_vb_u32(2)
            .fee_vb(forward.vsize() as u64)
            .unwrap()
    );
    assert!(env.watcher.deposits().is_empty(), "Y is empty");
}

#[test]
fn service_bumps_a_stuck_forward_through_its_fee_output() {
    let mut env = setup();
    // The service needs funds of its own: the fee output alone is too small to pay for a
    // useful bump and still leave a non-dust change output.
    let fee_wallet_addr = env
        .fee_wallet
        .peek_address(KeychainKind::External, 1)
        .address;
    env.node
        .client
        .send_to_address(
            &fee_wallet_addr,
            Amount::from_sat(50_000),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    env.withdraw_to_y(Amount::from_sat(100_000));
    env.mine(1);
    env.sync();

    let forward = env.forward(FeeRate::from_sat_per_vb_u32(1));
    let forward_txid = env.node.client.send_raw_transaction(&forward).unwrap();
    env.sync();

    let fee_outpoint = env
        .fee_wallet
        .list_unspent()
        .find(|utxo| utxo.outpoint.txid == forward_txid)
        .unwrap()
        .outpoint;
    let mut builder = env.fee_wallet.build_tx();
    builder
        .add_utxo(fee_outpoint)
        .unwrap()
        .drain_wallet()
        .drain_to(fee_wallet_addr.script_pubkey())
        .fee_rate(FeeRate::from_sat_per_vb_u32(20));
    let mut psbt = builder.finish().unwrap();
    psbt.sign(&env.fee_xprv, env.fee_wallet.secp_ctx()).unwrap();
    assert!(
        env.fee_wallet
            .finalize_psbt(&mut psbt, SignOptions::default())
            .unwrap()
    );
    let child = psbt.extract_tx().unwrap();
    env.node.client.send_raw_transaction(&child).unwrap();

    let entry = env.node.client.get_mempool_entry(&forward_txid).unwrap();
    assert_eq!(
        entry.descendant_count, 2,
        "child is attached to the forward"
    );
    let package_rate = entry.fees.descendant.to_sat() as f64 / entry.descendant_size as f64;
    println!("forward alone 1 sat/vB, with child {package_rate:.1} sat/vB");
    assert!(
        package_rate >= 10.0,
        "the child should lift the package to about 11 sat/vB"
    );

    env.mine(1);
    env.sync();
    assert!(
        env.node.client.get_mempool_entry(&forward_txid).is_err(),
        "both confirmed"
    );
    assert!(env.watcher.deposits().is_empty());
}

#[test]
fn cold_wallet_sweeps_y_through_the_safety_net() {
    let mut env = setup();
    env.withdraw_to_y(Amount::from_sat(100_000));
    env.mine(1);
    env.sync();
    let utxo = env.watcher.deposits().pop().unwrap();

    // The browser and the service are gone. The user has X's seed and the rescue key, and
    // S's public key is published. That is enough to rebuild Y's internal key.
    let x = env.cold.peek_address(KeychainKind::External, 0).address;
    let u = unravel::musig()
        .new_keypair(env.rescue.tab_secret(&x))
        .public_key();
    let rebuilt = Deposit::new(
        &unravel::musig(),
        &x.to_string(),
        NETWORK,
        u,
        env.service.public_key(),
    )
    .unwrap();
    assert_eq!(rebuilt.address(), env.deposit.address());
    let derived = env
        .node
        .client
        .derive_addresses(rebuilt.descriptor(), None)
        .unwrap();
    assert_eq!(derived[0].clone().assume_checked(), rebuilt.address());
    let secp = Secp256k1::new();
    let x_secret = env
        .cold_xprv
        .derive_priv(&secp, &DerivationPath::from_str("m/86h/1h/0h/0/0").unwrap())
        .unwrap()
        .private_key;
    let sweep = safety_net::sweep(
        &rebuilt,
        utxo.outpoint,
        &utxo.txout,
        x.script_pubkey(),
        FeeRate::from_sat_per_vb_u32(2),
        x_secret,
    )
    .unwrap();
    env.node.client.send_raw_transaction(&sweep).unwrap();
    env.mine(1);
    env.sync();

    assert_eq!(env.cold.balance().confirmed, sweep.output[0].value);
    assert!(env.watcher.deposits().is_empty());
}

#[test]
fn bitcoin_core_sweeps_y_with_the_private_descriptor() {
    let mut env = setup();
    let x = env.cold.peek_address(KeychainKind::External, 0).address;
    let exchange = env.node.client.get_new_address(None, None).unwrap();
    let deposit = Deposit::with_exchange(
        &unravel::musig(),
        &x.to_string(),
        Some(&exchange.assume_checked().to_string()),
        NETWORK,
        env.user.public_key(),
        env.service.public_key(),
    )
    .unwrap();
    let amount = Amount::from_sat(100_000);
    env.withdraw_to_y(amount);
    env.node
        .client
        .send_to_address(
            &deposit.address(),
            amount,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    env.mine(1);

    // The browser and the service are gone, and no wallet signs the leaf from a seed. Bitcoin
    // Core does, given each Y's descriptor with X's tweaked key in it.
    let secp = Secp256k1::new();
    let derive = |xprv: &Xpriv| {
        xprv.derive_priv(&secp, &DerivationPath::from_str("m/86h/1h/0h/0/0").unwrap())
            .unwrap()
            .private_key
    };
    assert_eq!(
        safety_net::private_descriptor(&env.deposit, derive(&env.fee_xprv)),
        None,
        "another wallet's key is refused"
    );
    let descriptors: Vec<_> = [&env.deposit, &deposit]
        .iter()
        .map(|d| safety_net::private_descriptor(d, derive(&env.cold_xprv)).unwrap())
        .map(|desc| serde_json::json!({ "desc": desc, "timestamp": 0 }))
        .collect();
    let core = env.node.create_wallet("rescue").unwrap();
    let imported: serde_json::Value = core
        .call("importdescriptors", &[serde_json::json!(descriptors)])
        .unwrap();
    assert!(
        imported
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["success"] == true),
        "{imported}"
    );
    let sent: serde_json::Value = core
        .call("sendall", &[serde_json::json!([x.to_string()])])
        .unwrap();
    assert_eq!(sent["complete"], true, "{sent}");
    env.mine(1);
    env.sync();

    // Both Ys are empty, and X has both deposits less the exchange's and the sweep's fees.
    let left: serde_json::Value = env
        .node
        .client
        .call(
            "scantxoutset",
            &[
                "start".into(),
                serde_json::json!([
                    format!("addr({})", env.deposit.address()),
                    format!("addr({})", deposit.address())
                ]),
            ],
        )
        .unwrap();
    assert_eq!(left["unspents"], serde_json::json!([]), "{left}");
    let swept = env.cold.balance().confirmed;
    assert!(
        swept > amount * 2 - Amount::from_sat(10_000) && swept < amount * 2,
        "{swept}"
    );
}

#[test]
fn x_must_be_a_regtest_taproot_address() {
    let (cold, _) = wallet(3);
    let x = cold.peek_address(KeychainKind::External, 0).address;
    let p2wpkh = Address::p2wpkh(
        &bitcoin::CompressedPublicKey::from_slice(
            &bitcoin::secp256k1::PublicKey::from_secret_key(
                &Secp256k1::new(),
                &bitcoin::secp256k1::SecretKey::from_slice(&[7; 32]).unwrap(),
            )
            .serialize(),
        )
        .unwrap(),
        NETWORK,
    );
    let u = unravel::musig()
        .new_keypair(Scalar::random(&mut rand::thread_rng()))
        .public_key();
    assert!(Deposit::new(&unravel::musig(), &x.to_string(), NETWORK, u, u).is_ok());
    assert!(Deposit::new(&unravel::musig(), &p2wpkh.to_string(), NETWORK, u, u).is_err());
}
