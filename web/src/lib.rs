//! The browser's side, holding the browser key U, compiled to WASM. Strings in, strings out:
//! the page passes JSON.

use bitcoin::{hex::DisplayHex, Amount, Network};
use schnorr_fun::fun::{Point, Scalar};
use serde::{Deserialize, Serialize};
use unravel::{
    Deposit, RescueKey,
    protocol::{SignRequest, Task, User, UserPolicy},
};
use wasm_bindgen::prelude::*;

/// Everything the page stores about this hop address. U is derived from `rescue` and `x`.
#[derive(Deserialize)]
struct Context {
    x: String,
    /// The exchange's deposit address, for a hop address that deposits to an exchange.
    #[serde(default)]
    exchange: Option<String>,
    network: Network,
    rescue: String,
    service_pk: String,
    max_miner_fee_sat: u64,
}

impl Context {
    fn parse(json: &str) -> Result<(User, Deposit), JsError> {
        let ctx: Context = serde_json::from_str(json)?;
        let secret = ctx.tab_secret()?;
        let service: Point = ctx
            .service_pk
            .parse()
            .map_err(|_| JsError::new("bad service key"))?;
        let user = User::new(
            unravel::musig(),
            secret,
            UserPolicy {
                // Never a fee output. Fee terms taken from the server would let it name
                // its own script and amount, and take the deposit as its "fee".
                service_fee: None,
                max_miner_fee: Amount::from_sat(ctx.max_miner_fee_sat),
            },
        );
        let deposit = Deposit::with_exchange(
            &unravel::musig(),
            &ctx.x,
            ctx.exchange.as_deref(),
            ctx.network,
            user.public_key(),
            service,
        )?;
        Ok((user, deposit))
    }

    fn tab_secret(&self) -> Result<Scalar, JsError> {
        let rescue: RescueKey = self.rescue.parse()?;
        Ok(rescue.tab_secret(&unravel::deposit::parse_x(&self.x, self.network)?))
    }
}

#[wasm_bindgen]
pub fn new_rescue_key() -> String {
    RescueKey::generate().to_string()
}

/// The rescue key in its canonical form, or why it can't be one.
#[wasm_bindgen]
pub fn parse_rescue_key(s: &str) -> Result<String, JsError> {
    Ok(s.parse::<RescueKey>()?.to_string())
}

#[wasm_bindgen]
pub fn public_key(ctx: &str) -> Result<String, JsError> {
    let ctx: Context = serde_json::from_str(ctx)?;
    let keypair = unravel::musig().new_keypair(ctx.tab_secret()?);
    Ok(keypair.public_key().to_string())
}

/// The hop address Y, computed here so the server can't hand the page an address without
/// the safety net to X in it.
#[wasm_bindgen]
pub fn deposit_address(ctx: &str) -> Result<String, JsError> {
    Ok(Context::parse(ctx)?.1.address().to_string())
}

/// Y's spending conditions as a descriptor: the user's way to verify Y elsewhere and to
/// claim through the safety net without this page or the service.
#[wasm_bindgen]
pub fn descriptor(ctx: &str) -> Result<String, JsError> {
    Ok(Context::parse(ctx)?.1.descriptor().to_string())
}

#[wasm_bindgen]
pub fn sign_challenge(ctx: &str, request: &str, challenge: &str) -> Result<String, JsError> {
    let (user, deposit) = Context::parse(ctx)?;
    let request: SignRequest = serde_json::from_str(request)?;
    let response = user.sign_challenge(&deposit, &request, challenge)?;
    Ok(serde_json::to_string(&response)?)
}

#[derive(Serialize)]
struct ForwardSigned {
    response: unravel::protocol::SignResponse,
    sent_sat: u64,
    miner_fee_sat: u64,
}

/// Signs the forward only if it passes the user's policy and pays where the user chose: X
/// when `to_x`, or else where the hop address forwards (the exchange, or else X). Reports
/// what it pays.
#[wasm_bindgen]
pub fn sign_forward(ctx: &str, request: &str, to_x: bool) -> Result<String, JsError> {
    let (user, deposit) = Context::parse(ctx)?;
    let request: SignRequest = serde_json::from_str(request)?;
    let Task::Forward { tx, prevout } = &request.task else {
        return Err(JsError::new("refused to sign: not a forward"));
    };
    // The server picks the output. Without this, it could send a deposit the exchange
    // returned straight back to the exchange.
    let chosen = if to_x { deposit.x() } else { deposit.onward() }.script_pubkey();
    if tx.output.iter().any(|o| o.script_pubkey != chosen) {
        return Err(JsError::new(
            "refused to sign: the forward doesn't pay where you chose",
        ));
    }
    let response = user.sign_forward(&deposit, &request)?;
    // The policy allows one output.
    let sent: Amount = tx.output.iter().map(|o| o.value).sum();
    Ok(serde_json::to_string(&ForwardSigned {
        response,
        sent_sat: sent.to_sat(),
        miner_fee_sat: (prevout.value - sent).to_sat(),
    })?)
}

/// The smallest amount a forward may pay `address`, in sats, or `undefined` if it isn't an
/// address the page accepts. A u32 reaches JavaScript as a number; a u64 would be a BigInt.
#[wasm_bindgen]
pub fn dust_limit(address: &str, network: &str) -> Option<u32> {
    let network: Network = network.parse().ok()?;
    let address = unravel::deposit::parse_exchange(address, network).ok()?;
    u32::try_from(address.script_pubkey().minimal_non_dust().to_sat()).ok()
}

#[wasm_bindgen]
pub fn verify_proof(y: &str, message: &str, proof: &str) -> bool {
    matches!(
        bip322::verify_simple_encoded(y, message, proof),
        Ok(bip322::Verification::Valid { .. })
    )
}

/// A QR code of the address as text, built here rather than taken from the server, which
/// could hand back a code for an address of its own.
#[wasm_bindgen]
pub fn address_qr(address: &str) -> Result<String, JsError> {
    use qrcode::{QrCode, render::unicode::Dense1x2};
    // Upper case fits QR's denser alphanumeric mode, and BIP-21 allows it.
    Ok(QrCode::new(format!("bitcoin:{address}").to_uppercase())
        .map_err(|e| JsError::new(&e.to_string()))?
        .render::<Dense1x2>()
        // Light text on the dark page: draw the light modules, leave dark ones blank.
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build())
}

/// Whether `s` can be a destination on `network`: a taproot address with a valid key.
#[wasm_bindgen]
pub fn is_address(s: &str, network: &str) -> bool {
    network
        .parse::<Network>()
        .is_ok_and(|network| unravel::deposit::parse_x(s, network).is_ok())
}

/// The key inside a taproot address, in hex as a descriptor writes it, so the page can show
/// which key in the hop address's spending rules is the user's.
#[wasm_bindgen]
pub fn taproot_key(address: &str, network: &str) -> Option<String> {
    let x = unravel::deposit::parse_x(address, network.parse().ok()?).ok()?;
    Some(x.witness_program()?.program().as_bytes().to_lower_hex_string())
}

/// Whether `s` can be an exchange's deposit address on `network`: any address type.
#[wasm_bindgen]
pub fn is_exchange_address(s: &str, network: &str) -> bool {
    network
        .parse::<Network>()
        .is_ok_and(|network| unravel::deposit::parse_exchange(s, network).is_ok())
}

/// Searches nonces `from..from + count` for a registration's proof of work.
#[wasm_bindgen]
pub fn pow_search(
    salt: &str,
    x: &str,
    user_pk: &str,
    exchange: Option<String>,
    bits: u32,
    from: u32,
    count: u32,
) -> Result<Option<u32>, JsError> {
    use bitcoin::hex::FromHex;
    let salt = <[u8; 32]>::from_hex(salt).map_err(|_| JsError::new("bad proof-of-work salt"))?;
    Ok(unravel::pow::search(
        &salt,
        x,
        user_pk,
        exchange.as_deref(),
        bits,
        from,
        count,
    ))
}
