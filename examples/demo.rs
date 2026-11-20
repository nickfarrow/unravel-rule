//! Runs the browser key U and the server key S in one process: prints the hop address Y and
//! the BIP-322 proof for a challenge.
//!
//! cargo run --example demo -- <regtest taproot X> <challenge>
//!
//! Regtest only: the keys are thrown away, so the address it prints can never be spent from.

use bitcoin::Network;
use schnorr_fun::fun::Scalar;
use unravel::{
    Deposit,
    protocol::{Service, Task, User, UserPolicy},
};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(x), Some(challenge)) = (args.next(), args.next()) else {
        eprintln!("usage: demo <regtest taproot X (bcrt1p…)> <challenge>");
        std::process::exit(1);
    };
    // Real networks are refused so the address it prints can't be used for a withdrawal.
    if !x.starts_with("bcrt1") {
        eprintln!("the demo only takes regtest addresses (bcrt1p…)");
        std::process::exit(1);
    }
    let network = Network::Regtest;

    let mut rng = rand::thread_rng();
    let mut service = Service::new(unravel::musig(), Scalar::random(&mut rng), None);
    let user = User::new(
        unravel::musig(),
        Scalar::random(&mut rng),
        UserPolicy {
            service_fee: None,
            max_miner_fee: bitcoin::Amount::from_sat(2_000),
        },
    );
    let deposit = Deposit::new(
        &unravel::musig(),
        &x,
        network,
        user.public_key(),
        service.public_key(),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    let request = service
        .request(&deposit, Task::Challenge(challenge.clone()))
        .unwrap();
    let response = user.sign_challenge(&deposit, &request, &challenge).unwrap();
    let (task, signature) = service.complete(&deposit, response).unwrap();
    println!("{}", deposit.address());
    println!("{}", unravel::bip322::encode(&task.witness(signature)));
}
