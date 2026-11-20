//! The signing round trip between the browser key U and the server key S.
//!
//! One round trip per signature:
//! 1. S checks the task against its policy, picks a fresh nonce and sends a [`SignRequest`].
//! 2. U checks the task against *its* policy, picks a fresh nonce, signs and returns a
//!    [`SignResponse`].
//! 3. S signs, checks U's partial signature and combines them.
//!
//! Each side computes the sighash itself from the task. Neither side ever signs a hash it
//! was handed, so a challenge can't be used to smuggle in a real spend.
//!
//! Nothing here depends on how the messages travel.

use std::collections::{HashMap, VecDeque};

use bitcoin::{
    Amount, ScriptBuf, TapSighash, Transaction, TxOut, Witness, absolute::LockTime, hashes::Hash,
};
use schnorr_fun::{
    Message,
    binonce::{Nonce, NonceKeyPair},
    fun::KeyPair,
    fun::{Point, Scalar, marker::*, s},
};

use crate::{
    Deposit, Error, MuSig,
    deposit::{SERVICE_INDEX, USER_INDEX},
};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Task {
    /// A BIP-322 simple signature for the hop address Y over the exchange's challenge.
    Challenge(String),
    /// The forward transaction, spending one deposit at Y.
    Forward { tx: Transaction, prevout: TxOut },
}

impl Task {
    fn sighash(&self, deposit: &Deposit) -> TapSighash {
        match self {
            Task::Challenge(message) => crate::bip322::sighash(&deposit.address(), message),
            Task::Forward { tx, prevout } => crate::forward::sighash(tx, prevout),
        }
    }

    /// The final witness for this task's signature.
    pub fn witness(&self, signature: [u8; 64]) -> Witness {
        match self {
            Task::Challenge(_) => crate::bip322::witness(signature),
            Task::Forward { tx, .. } => {
                let mut tx = tx.clone();
                crate::forward::finalize(&mut tx, signature);
                tx.input[0].witness.clone()
            }
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignRequest {
    pub session: u64,
    pub task: Task,
    pub service_nonce: Nonce,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignResponse {
    pub session: u64,
    pub user_nonce: Nonce,
    pub partial_signature: Scalar<Public, Zero>,
}

/// What the service charges for a forward: a fixed fee to a fixed script. With no policy
/// there is no fee output, and the forward has a single output.
#[derive(Clone, Debug)]
pub struct FeePolicy {
    pub fee_spk: ScriptBuf,
    pub fee: Amount,
}

/// The most signatures waiting for U at once. Past it the oldest is dropped, so a client that
/// asks for many and never answers can't grow the service's memory.
const MAX_PENDING: usize = 10_000;

pub struct Service {
    musig: MuSig,
    keypair: KeyPair,
    policy: Option<FeePolicy>,
    /// Secret nonces waiting for U's response. Each is removed when used, so it can only
    /// ever sign once. Session ids are random, so one client can't guess another's and
    /// cancel it.
    pending: HashMap<u64, (Deposit, Task, NonceKeyPair)>,
    /// Session ids, oldest first, for dropping the oldest when there are too many.
    order: VecDeque<u64>,
}

impl Service {
    pub fn new(musig: MuSig, secret: Scalar, policy: Option<FeePolicy>) -> Self {
        let keypair = musig.new_keypair(secret);
        Self {
            musig,
            keypair,
            policy,
            pending: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn public_key(&self) -> Point {
        self.keypair.public_key()
    }

    pub fn policy(&self) -> Option<&FeePolicy> {
        self.policy.as_ref()
    }

    /// The key S signs `deposit` with: its own, offset for a hop address with an exchange.
    fn keypair_for(&self, deposit: &Deposit) -> KeyPair {
        match deposit.service_tweak() {
            Some(t) => self.musig.new_keypair(
                s!(self.keypair.secret_key() + t)
                    .non_zero()
                    .expect("computationally unreachable: t is a hash"),
            ),
            None => self.keypair,
        }
    }

    pub fn request(&mut self, deposit: &Deposit, task: Task) -> Result<SignRequest, Error> {
        if let (Task::Forward { tx, .. }, Some(policy)) = (&task, &self.policy) {
            let pays_fee = tx
                .output
                .iter()
                .any(|out| out.script_pubkey == policy.fee_spk && out.value >= policy.fee);
            if !pays_fee {
                return Err(Error::Refused("forward doesn't pay the service fee"));
            }
        }
        // 53 bits: the page carries it as a JavaScript number, which holds no more exactly.
        let session = rand::random::<u64>() >> 11;

        let sighash = task.sighash(deposit);
        let mut nonce_rng: rand_chacha::ChaCha20Rng = self.musig.seed_nonce_rng(
            deposit.signing_key(),
            self.keypair_for(deposit).secret_key(),
            &session_id(sighash, session),
        );
        let nonce = self.musig.gen_nonce(&mut nonce_rng);
        let service_nonce = nonce.public();
        self.pending
            .insert(session, (deposit.clone(), task.clone(), nonce));
        self.order.push_back(session);
        while self.order.len() > MAX_PENDING {
            let oldest = self.order.pop_front().expect("not empty");
            self.pending.remove(&oldest);
        }
        Ok(SignRequest {
            session,
            task,
            service_nonce,
        })
    }

    /// Returns the final 64-byte BIP-340 signature. The session must be one for `deposit`.
    pub fn complete(
        &mut self,
        deposit: &Deposit,
        response: SignResponse,
    ) -> Result<(Task, [u8; 64]), Error> {
        let for_deposit = self
            .pending
            .get(&response.session)
            .is_some_and(|(d, ..)| d.script_pubkey() == deposit.script_pubkey());
        if !for_deposit {
            return Err(Error::UnknownSession);
        }
        let (deposit, task, nonce) = self
            .pending
            .remove(&response.session)
            .ok_or(Error::UnknownSession)?;
        let agg_key = deposit.signing_key();
        let sighash = task.sighash(&deposit);
        let session = self.musig.start_sign_session(
            agg_key,
            nonces(response.user_nonce, nonce.public()),
            Message::raw(&sighash.to_byte_array()),
        );
        if !self.musig.verify_partial_signature(
            agg_key,
            &session,
            USER_INDEX,
            response.partial_signature,
        ) {
            return Err(Error::BadPartialSignature);
        }
        let mine = self.musig.sign(
            agg_key,
            &session,
            SERVICE_INDEX,
            &self.keypair_for(&deposit),
            nonce,
        );
        let signature = self.musig.combine_partial_signatures(
            agg_key,
            &session,
            [response.partial_signature, mine],
        );
        assert!(self.musig.schnorr.verify(
            &agg_key.agg_public_key(),
            Message::raw(&sighash.to_byte_array()),
            &signature
        ));
        Ok((task, signature.to_bytes()))
    }
}

/// What the browser agrees to sign.
#[derive(Clone, Debug)]
pub struct UserPolicy {
    pub service_fee: Option<FeePolicy>,
    /// The most the forward may spend on mining fees.
    pub max_miner_fee: Amount,
}

pub struct User {
    musig: MuSig,
    keypair: KeyPair,
    policy: UserPolicy,
}

impl User {
    pub fn new(musig: MuSig, secret: Scalar, policy: UserPolicy) -> Self {
        let keypair = musig.new_keypair(secret);
        Self {
            musig,
            keypair,
            policy,
        }
    }

    pub fn public_key(&self) -> Point {
        self.keypair.public_key()
    }

    /// Signs the challenge the user pasted, and nothing else.
    pub fn sign_challenge(
        &self,
        deposit: &Deposit,
        request: &SignRequest,
        challenge: &str,
    ) -> Result<SignResponse, Error> {
        match &request.task {
            Task::Challenge(message) if message == challenge => self.sign(deposit, request),
            _ => Err(Error::Refused("not the challenge the user entered")),
        }
    }

    /// Signs a forward only if it pays everything except the agreed fees to the destination X
    /// or the exchange's deposit address.
    pub fn sign_forward(
        &self,
        deposit: &Deposit,
        request: &SignRequest,
    ) -> Result<SignResponse, Error> {
        let Task::Forward { tx, prevout } = &request.task else {
            return Err(Error::Refused("not a forward"));
        };
        self.check_forward(deposit, tx, prevout)?;
        self.sign(deposit, request)
    }

    // `prevout` comes from S and isn't trusted: the sighash commits to it, so if S lies
    // about the amount or script the signature is invalid on chain.
    fn check_forward(
        &self,
        deposit: &Deposit,
        tx: &Transaction,
        prevout: &TxOut,
    ) -> Result<(), Error> {
        let fee = self.policy.service_fee.as_ref();
        if tx.input.len() != 1 || prevout.script_pubkey != deposit.script_pubkey() {
            return Err(Error::Refused("the forward must spend exactly one deposit"));
        }
        // `to_x` may be the exchange's output: a hop address with one forwards there.
        let (to_x, to_service) = match (tx.output.as_slice(), fee) {
            ([to_x], None) => (to_x, None),
            ([a, b], Some(fee)) => {
                let (to_x, to_service) = if deposit.may_pay(&a.script_pubkey) {
                    (a, b)
                } else {
                    (b, a)
                };
                if to_service.script_pubkey != fee.fee_spk || to_service.value > fee.fee {
                    return Err(Error::Refused("service output isn't the agreed fee"));
                }
                (to_x, Some(to_service))
            }
            _ => return Err(Error::Refused("forward has the wrong number of outputs")),
        };
        if !deposit.may_pay(&to_x.script_pubkey) {
            return Err(Error::Refused("the forward must pay an address you gave"));
        }
        // Otherwise a forward could hand the whole deposit to the miners.
        if to_x.value < to_x.script_pubkey.minimal_non_dust() {
            return Err(Error::Refused(
                "the forward pays too little: below the dust limit",
            ));
        }
        // A time-locked forward couldn't be broadcast yet, and would hold up the deposit.
        if tx.lock_time != LockTime::ZERO || tx.input[0].sequence.is_relative_lock_time() {
            return Err(Error::Refused("the forward must be spendable now"));
        }
        // Both values come off the wire; plain addition would panic on overflow.
        let miner_fee = to_x
            .value
            .checked_add(to_service.map_or(Amount::ZERO, |out| out.value))
            .and_then(|spent| prevout.value.checked_sub(spent))
            .ok_or(Error::Refused("outputs exceed the deposit"))?;
        if miner_fee > self.policy.max_miner_fee {
            return Err(Error::Refused("miner fee too high"));
        }
        Ok(())
    }

    fn sign(&self, deposit: &Deposit, request: &SignRequest) -> Result<SignResponse, Error> {
        let agg_key = deposit.signing_key();
        let sighash = request.task.sighash(deposit);
        // A fresh nonce per request, mixed with randomness by the synthetic nonce generator.
        // It's used immediately and never stored. The service's nonce is in the seed too, so
        // even if the randomness failed, S replaying a task with a new nonce of its own would
        // get a new nonce here rather than a second signature that reveals U's key.
        let mut id = session_id(sighash, request.session);
        id.extend(request.service_nonce.to_bytes());
        let mut nonce_rng: rand_chacha::ChaCha20Rng =
            self.musig
                .seed_nonce_rng(agg_key, self.keypair.secret_key(), &id);
        let nonce = self.musig.gen_nonce(&mut nonce_rng);
        let user_nonce = nonce.public();
        let session = self.musig.start_sign_session(
            agg_key,
            nonces(user_nonce, request.service_nonce),
            Message::raw(&sighash.to_byte_array()),
        );
        let partial_signature =
            self.musig
                .sign(agg_key, &session, USER_INDEX, &self.keypair, nonce);
        Ok(SignResponse {
            session: request.session,
            user_nonce,
            partial_signature,
        })
    }
}

fn nonces(user: Nonce, service: Nonce) -> Vec<Nonce> {
    let mut nonces = vec![user; 2];
    nonces[SERVICE_INDEX] = service;
    nonces
}

fn session_id(sighash: TapSighash, session: u64) -> Vec<u8> {
    let mut id = sighash.to_byte_array().to_vec();
    id.extend(session.to_be_bytes());
    id
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_util::random_x;
    use bitcoin::{Address, FeeRate, Network, OutPoint, Txid};

    const CHALLENGE: &str = "SHAZAM-10698-1793874675547-43a174838f5e6f5e8b4a2ec6e6e13959";

    struct Setup {
        user: User,
        service: Service,
        deposit: Deposit,
    }

    fn setup() -> Setup {
        let fee_spk = Address::from_str(&random_x())
            .unwrap()
            .assume_checked()
            .script_pubkey();
        setup_with(Some(FeePolicy {
            fee_spk,
            fee: Amount::from_sat(1_000),
        }))
    }

    fn setup_with(service_fee: Option<FeePolicy>) -> Setup {
        let mut rng = rand::thread_rng();
        let service = Service::new(
            crate::musig(),
            Scalar::random(&mut rng),
            service_fee.clone(),
        );
        let user = User::new(
            crate::musig(),
            Scalar::random(&mut rng),
            UserPolicy {
                service_fee,
                max_miner_fee: Amount::from_sat(5_000),
            },
        );
        let deposit = Deposit::new(
            &crate::musig(),
            &random_x(),
            Network::Regtest,
            user.public_key(),
            service.public_key(),
        )
        .unwrap();
        Setup {
            user,
            service,
            deposit,
        }
    }

    use std::str::FromStr;

    fn forward_task(s: &Setup) -> Task {
        forward_task_to(s, s.deposit.onward().script_pubkey())
    }

    fn forward_task_to(s: &Setup, to: ScriptBuf) -> Task {
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: s.deposit.script_pubkey(),
        };
        let tx = crate::forward::build(
            OutPoint::new(Txid::all_zeros(), 0),
            &prevout,
            to,
            s.service.policy().map(|p| (p.fee_spk.clone(), p.fee)),
            FeeRate::from_sat_per_vb_u32(2),
        )
        .unwrap();
        Task::Forward { tx, prevout }
    }

    #[test]
    fn challenge_signature_verifies_as_ordinary_bip322() {
        let mut s = setup();
        let request = s
            .service
            .request(&s.deposit, Task::Challenge(CHALLENGE.into()))
            .unwrap();
        let response = s
            .user
            .sign_challenge(&s.deposit, &request, CHALLENGE)
            .unwrap();
        let (task, signature) = s.service.complete(&s.deposit, response).unwrap();
        let encoded = crate::bip322::encode(&task.witness(signature));
        let y = s.deposit.address().to_string();

        assert!(matches!(
            ::bip322::verify_simple_encoded(&y, CHALLENGE, &encoded),
            Ok(::bip322::Verification::Valid { .. })
        ));
        assert!(::bip322::verify_simple_encoded(&y, "something else", &encoded).is_err());
        // 1 item, 65 bytes: same shape as a single-key Sparrow signature.
        assert_eq!(encoded.len(), 92);
    }

    #[test]
    fn user_only_signs_the_challenge_they_entered() {
        let mut s = setup();
        let request = s
            .service
            .request(&s.deposit, Task::Challenge("send me your coins".into()))
            .unwrap();
        assert!(
            s.user
                .sign_challenge(&s.deposit, &request, CHALLENGE)
                .is_err()
        );
        assert!(s.user.sign_forward(&s.deposit, &request).is_err());
    }

    #[test]
    fn forward_signature_is_valid_for_y() {
        let mut s = setup();
        let task = forward_task(&s);
        let request = s.service.request(&s.deposit, task.clone()).unwrap();
        let response = s.user.sign_forward(&s.deposit, &request).unwrap();
        let (_, signature) = s.service.complete(&s.deposit, response).unwrap();
        assert_valid_for_y(&task, signature);
    }

    fn assert_valid_for_y(task: &Task, signature: [u8; 64]) {
        let Task::Forward { tx, prevout } = task else {
            unreachable!()
        };
        let sighash = crate::forward::sighash(tx, prevout);
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        let y_key =
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&prevout.script_pubkey.as_bytes()[2..])
                .unwrap();
        secp.verify_schnorr(
            &bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).unwrap(),
            &bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array()),
            &y_key,
        )
        .unwrap();
    }

    #[test]
    fn a_hop_address_with_an_exchange_signs_and_forwards_there_or_to_x() {
        let mut s = setup();
        s.deposit = Deposit::with_exchange(
            &crate::musig(),
            &s.deposit.x().to_string(),
            Some("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
            Network::Regtest,
            s.user.public_key(),
            s.service.public_key(),
        )
        .unwrap();
        // S signs with its key offset by the exchange's tweak, or the signature fails.
        for to in [s.deposit.onward(), s.deposit.x()] {
            let task = forward_task_to(&s, to.script_pubkey());
            let request = s.service.request(&s.deposit, task.clone()).unwrap();
            let response = s.user.sign_forward(&s.deposit, &request).unwrap();
            let (_, signature) = s.service.complete(&s.deposit, response).unwrap();
            assert_valid_for_y(&task, signature);
        }

        let request = s
            .service
            .request(&s.deposit, Task::Challenge(CHALLENGE.into()))
            .unwrap();
        let response = s
            .user
            .sign_challenge(&s.deposit, &request, CHALLENGE)
            .unwrap();
        let (task, signature) = s.service.complete(&s.deposit, response).unwrap();
        let encoded = crate::bip322::encode(&task.witness(signature));
        assert!(matches!(
            ::bip322::verify_simple_encoded(&s.deposit.address().to_string(), CHALLENGE, &encoded),
            Ok(::bip322::Verification::Valid { .. })
        ));

        let thief = Address::from_str(&random_x())
            .unwrap()
            .assume_checked()
            .script_pubkey();
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.output[0].script_pubkey = thief),
            Error::Refused(_)
        ));
    }

    /// The page's policy has no fee output, so this is the forward it signs.
    #[test]
    fn only_a_hop_address_with_an_exchange_forwards_to_it_alone() {
        let mut s = setup_with(None);
        let plain = s.deposit.clone();
        let exchange = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        s.deposit = Deposit::with_exchange(
            &crate::musig(),
            &plain.x().to_string(),
            Some(exchange),
            Network::Regtest,
            s.user.public_key(),
            s.service.public_key(),
        )
        .unwrap();
        let task = forward_task(&s);
        let request = s.service.request(&s.deposit, task.clone()).unwrap();
        let response = s.user.sign_forward(&s.deposit, &request).unwrap();
        let (_, signature) = s.service.complete(&s.deposit, response).unwrap();
        assert_valid_for_y(&task, signature);

        s.deposit = plain;
        let to_exchange = Address::from_str(exchange)
            .unwrap()
            .assume_checked()
            .script_pubkey();
        assert_eq!(
            user_refuses(&mut s, |tx, _| tx.output[0].script_pubkey = to_exchange),
            Error::Refused("the forward must pay an address you gave")
        );
    }

    /// The service builds a bad forward; the user must refuse before signing anything.
    fn user_refuses(s: &mut Setup, tamper: impl FnOnce(&mut Transaction, &mut TxOut)) -> Error {
        let Task::Forward {
            mut tx,
            mut prevout,
        } = forward_task(s)
        else {
            unreachable!()
        };
        tamper(&mut tx, &mut prevout);
        let request = SignRequest {
            session: 0,
            task: Task::Forward { tx, prevout },
            service_nonce: NonceKeyPair::random(&mut rand::thread_rng()).public(),
        };
        s.user.sign_forward(&s.deposit, &request).unwrap_err()
    }

    #[test]
    fn user_refuses_bad_forwards() {
        let mut s = setup();
        let thief = Address::from_str(&random_x())
            .unwrap()
            .assume_checked()
            .script_pubkey();
        let t = thief.clone();
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.output[0].script_pubkey = t),
            Error::Refused(_)
        ));
        assert!(matches!(
            user_refuses(&mut s, |tx, _| {
                tx.output[0].value -= Amount::from_sat(500);
                tx.output[1].value += Amount::from_sat(500);
            }),
            Error::Refused(_)
        ));
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.output[0].value -=
                Amount::from_sat(10_000)),
            Error::Refused(_)
        ));
        let t = thief.clone();
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.output.push(TxOut {
                value: Amount::from_sat(1),
                script_pubkey: t
            })),
            Error::Refused(_)
        ));
        assert!(matches!(
            user_refuses(&mut s, |_, prevout| prevout.script_pubkey = thief),
            Error::Refused(_)
        ));
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.input.push(tx.input[0].clone())),
            Error::Refused("the forward must spend exactly one deposit")
        ));
        assert!(matches!(
            user_refuses(&mut s, |tx, prevout| prevout.value =
                tx.output[0].value - Amount::from_sat(1)),
            Error::Refused("outputs exceed the deposit")
        ));
        // A value near the maximum must be refused, not overflow.
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.output[0].value = Amount::MAX),
            Error::Refused(_)
        ));
        // Nothing to X, with the miner fee unchanged.
        assert!(matches!(
            user_refuses(&mut s, |tx, prevout| {
                prevout.value -= tx.output[0].value;
                tx.output[0].value = Amount::ZERO;
            }),
            Error::Refused("the forward pays too little: below the dust limit")
        ));
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.lock_time =
                LockTime::from_consensus(499_999_999)),
            Error::Refused("the forward must be spendable now")
        ));
        assert!(matches!(
            user_refuses(&mut s, |tx, _| tx.input[0].sequence =
                bitcoin::Sequence::from_height(1_000)),
            Error::Refused("the forward must be spendable now")
        ));
    }

    #[test]
    fn service_refuses_forward_without_fee() {
        let mut s = setup();
        let Task::Forward { mut tx, prevout } = forward_task(&s) else {
            unreachable!()
        };
        tx.output.pop();
        assert!(
            s.service
                .request(&s.deposit, Task::Forward { tx, prevout })
                .is_err()
        );
    }

    #[test]
    fn service_nonce_is_used_once() {
        let mut s = setup();
        let request = s.service.request(&s.deposit, forward_task(&s)).unwrap();
        // The page holds the session id as a JavaScript number.
        assert!(request.session < 1 << 53);
        let response = s.user.sign_forward(&s.deposit, &request).unwrap();
        s.service.complete(&s.deposit, response.clone()).unwrap();
        assert_eq!(
            s.service.complete(&s.deposit, response).unwrap_err(),
            Error::UnknownSession
        );
    }

    #[test]
    fn service_only_completes_a_session_for_its_own_deposit() {
        let mut s = setup();
        let other = setup();
        let request = s.service.request(&s.deposit, forward_task(&s)).unwrap();
        let response = s.user.sign_forward(&s.deposit, &request).unwrap();
        assert_eq!(
            s.service
                .complete(&other.deposit, response.clone())
                .unwrap_err(),
            Error::UnknownSession
        );
        // The wrong deposit doesn't cancel the session.
        s.service.complete(&s.deposit, response).unwrap();
    }

    #[test]
    fn user_pays_the_miner_up_to_the_limit_and_no_more() {
        let mut s = setup_with(None);
        // forward_task pays 2 sat/vB; the limit is 5,000 sats.
        let Task::Forward { tx, prevout } = forward_task(&s) else {
            unreachable!()
        };
        let miner_fee = prevout.value - tx.output[0].value;
        let at_limit = Amount::from_sat(5_000) - miner_fee;
        user_refuses(&mut s, |tx, _| tx.output[0].value -= at_limit + Amount::from_sat(1));
        let mut tx = tx;
        tx.output[0].value -= at_limit;
        let request = SignRequest {
            session: 0,
            task: Task::Forward { tx, prevout },
            service_nonce: NonceKeyPair::random(&mut rand::thread_rng()).public(),
        };
        s.user.sign_forward(&s.deposit, &request).unwrap();
    }

    #[test]
    fn service_rejects_bad_partial_signature() {
        let mut s = setup();
        let request = s.service.request(&s.deposit, forward_task(&s)).unwrap();
        let mut response = s.user.sign_forward(&s.deposit, &request).unwrap();
        response.partial_signature = Scalar::random(&mut rand::thread_rng()).public().mark_zero();
        assert_eq!(
            s.service.complete(&s.deposit, response).unwrap_err(),
            Error::BadPartialSignature
        );
    }

    #[test]
    fn without_a_fee_the_forward_pays_x_alone() {
        let mut s = setup_with(None);
        let task = forward_task(&s);
        let Task::Forward { tx, .. } = &task else {
            unreachable!()
        };
        assert_eq!(tx.output.len(), 1);
        let request = s.service.request(&s.deposit, task.clone()).unwrap();
        let response = s.user.sign_forward(&s.deposit, &request).unwrap();
        s.service.complete(&s.deposit, response).unwrap();

        // A service that slips in a fee output anyway is refused.
        let thief = Address::from_str(&random_x())
            .unwrap()
            .assume_checked()
            .script_pubkey();
        let err = user_refuses(&mut s, |tx, _| {
            tx.output[0].value -= Amount::from_sat(1_000);
            tx.output.push(TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: thief,
            });
        });
        assert!(matches!(err, Error::Refused(_)));
    }
}
