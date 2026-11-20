import init, * as u from "./pkg/unravel_web.js";

// The most the forward may spend on mining fees. The user's device refuses anything more.
const MAX_MINER_FEE_SAT = 2000;
// Written into the kit. A kit of another format derives different keys, so restore refuses it.
const KIT_FORMAT = 1;
// The server API version this page speaks. It refuses a server that speaks another.
const PROTOCOL = 2;
// The public server, which a copy of this page opened from disk uses by default.
const HOME_SERVER = "https://unravelrule.xyz/";
// This site's own server, or the public one for a copy opened from disk. Used unless the
// user picks another at the top right.
const SITE_SERVER = location.protocol.startsWith("http") ? new URL(".", location.href).href : HOME_SERVER;
const server = localStorage.getItem("unravel-server") || SITE_SERVER;
const $ = (id) => document.getElementById(id);

let info;
let state = JSON.parse(localStorage.getItem("unravel") || "null");
// Pages from before every forward was listed kept only the last.
if (state?.lastForward) {
  state.forwards ??= [state.lastForward];
  delete state.lastForward;
}
// Kept apart from "unravel" so starting over never deletes the one backup that covers
// every hop address this browser makes.
let rescue = JSON.parse(localStorage.getItem("unravel-rescue") || "null");
let forwarding = false;
// The deposits waiting for the user to choose where they go, by where they're big enough to go.
let choices = { exchange: [], x: [] };
// The latest /api/fee answer: what a forward would pay right now.
let fee = null;
// Which finished card the user reopened. `null` means the current step's card.
let reopened = null;
// Whether a deposit's fee, forward and closing note are shown. Withdrawing always shows them.
let details = false;
// The kit step has two cards: saving it, then checking it. `restoring` checks a kit from
// before instead of the one just saved.
let checking = false;
let restoring = false;
// Before this browser's first hop address, the user accepts the risks, once.
let agreeing = false;
// The direction chosen on the first card, before there's a hop address. After that, the hop address's own.
let mode = "withdraw";
// The card shown before there's a hop address: "mode", "exchange" or "x".
let entry = "mode";
// Whether this server offers a test address for withdrawing.
let testHidden = false;
// Whether the server offers the regtest demo's send and mine buttons.
let demo = false;
// The card last shown, so a change of card can move focus to it.
let lastShown = null;
// Depositing to an exchange: the hop address forwards to the exchange's deposit address.
const depositing = () => (state ? Boolean(state.exchange) : mode === "deposit");

async function post(base, path, body = {}) {
  let res;
  try {
    res = await fetch(new URL(path, base), { method: "POST", body: JSON.stringify(body) });
  } catch {
    throw Object.assign(new Error(`can't reach the server at ${base}`), { unreachable: true });
  }
  const json = await res.json().catch(() => null);
  // A proxy answers with an error page while the server restarts: that's not the wrong server.
  if (!json && !res.ok) throw new Error(`The server isn't answering right now (${res.status}). Try again in a minute.`);
  if (!json) throw new Error(`${base} isn't an unravel rule server`);
  if (!res.ok) throw new Error(json.error);
  return json;
}

async function api(path, body) {
  try {
    const json = await post(server, path, body);
    setConn(true);
    return json;
  } catch (e) {
    setConn(!e.unreachable);
    throw e;
  }
}

function setConn(up) {
  $("conn").classList.toggle("up", up);
  $("conn-label").textContent = !up ? "not connected"
    : server === SITE_SERVER ? "connected" : `connected to ${new URL(server).host}`;
}

function checkProtocol(i) {
  if (i.protocol !== PROTOCOL) throw new Error(`that server speaks protocol ${i.protocol ?? 0}, and this page speaks ${PROTOCOL}.`);
}

// A hop address belongs to one server key, so a server with another key means new hop
// addresses. The rescue key carries over, but the kit names the server key, so it's saved again.
async function switchServer(input) {
  $("conn-err").textContent = "";
  try {
    let url;
    try {
      url = new URL(/^https?:\/\//.test(input) ? input : `https://${input}`);
    } catch {
      throw new Error("that isn't a server address, such as https://example.com");
    }
    if (!url.pathname.endsWith("/")) url.pathname += "/";
    url = url.href;
    const next = await post(url, "api/info");
    checkProtocol(next);
    if (next.service_pk !== info?.service_pk) {
      if (state?.y && !confirm("Switch server? You'll get a new hop address. Anything sent to the old one is forwarded only if you switch back, or claimed with your emergency kit.")) return;
      localStorage.removeItem("unravel");
    }
    if (url === SITE_SERVER) localStorage.removeItem("unravel-server");
    else localStorage.setItem("unravel-server", url);
    location.reload();
  } catch (e) {
    $("conn-err").textContent = e.message;
  }
}

function ctx() {
  return JSON.stringify({
    x: state.x,
    exchange: state.exchange,
    network: info.network,
    rescue: rescueKey(),
    service_pk: info.service_pk,
    max_miner_fee_sat: MAX_MINER_FEE_SAT,
  });
}

// Set while the page starts over, so a registration still in flight can't save the old hop
// address back.
let leaving = false;

function save() {
  if (!leaving) localStorage.setItem("unravel", JSON.stringify(state));
}

function rescueKey() {
  // Another tab may have made the key since this one loaded. Making a second would replace it.
  rescue ??= JSON.parse(localStorage.getItem("unravel-rescue") || "null");
  if (!rescue) {
    rescue = { key: u.new_rescue_key(), saved: false, created: Date.now() };
    localStorage.setItem("unravel-rescue", JSON.stringify(rescue));
  }
  return rescue.key;
}

// en-CA writes YYYY-MM-DD, in local time, which reads the same everywhere on paper.
const day = (ms) => new Date(ms).toLocaleDateString("en-CA");

function cliFlag(network) {
  return { bitcoin: "", testnet: "-testnet ", testnet4: "-testnet4 " }[network] ?? `-${network} `;
}

function busy(link, on) {
  link.classList.toggle("busy", on);
}

function onClick(id, fn) {
  $(id).addEventListener("click", async (e) => {
    e.preventDefault();
    // The link itself, not a span inside it.
    const link = e.currentTarget;
    busy(link, true);
    try {
      await fn();
    } catch (err) {
      // Handlers report their own expected errors; this catches the rest, such as a
      // clipboard the browser won't let us write to, so a click never fails silently.
      const shown = link.closest(".body")?.querySelector(".err");
      if (shown) shown.textContent = err.message ?? String(err);
    } finally {
      busy(link, false);
    }
  });
}

// The server stores a new hop address only with a proof of work, so filling its memory
// costs CPU. One it already knows registers again for free.
// While a registration runs, the addresses can't change underneath it.
let registering = false;

async function register() {
  if (!state.y && !localStorage.getItem("unravel-agreed")) {
    agreeing = true;
    return render();
  }
  registering = true;
  try {
    const body = { x: state.x, exchange: state.exchange, user_pk: u.public_key(ctx()) };
    let reply = await api("api/deposit", body).catch((e) => {
      if (e.message !== "proof of work needed") throw e;
    });
    if (!reply) {
      body.pow = await proofOfWork(body);
      reply = await api("api/deposit", body);
    }
    const { y } = reply;
    // Y is rebuilt here from the addresses, B and S. A server that left out the safety net would fail this.
    if (u.deposit_address(ctx()) !== y) {
      throw new Error("The server's hop address doesn't match the one built here. Don't use it.");
    }
    state.y = y;
    state.step = Math.max(state.step ?? 3, 3);
    agreeing = false;
    save();
    $("page-err").textContent = "";
    render();
  } finally {
    registering = false;
  }
}

// Whether the kit must be saved before making the hop address. Recovering a deposit's hop
// address needs the exchange's address, so a kit saved before that address was used is saved
// again. The rescue key is the same, so it isn't checked again.
function kitMissing() {
  return !rescue?.checked || Boolean(state?.exchange && !rescue.inKit?.includes(state.exchange));
}

// Every exchange deposit address this browser has used, kept with the rescue key, which
// nothing deletes: recovering a hop address that deposits to an exchange needs it.
function rememberExchange(exchange) {
  rescueKey();
  rescue.exchanges = [...new Set([...(rescue.exchanges ?? []), exchange])];
  localStorage.setItem("unravel-rescue", JSON.stringify(rescue));
}

async function proofOfWork({ x, user_pk, exchange }) {
  const { salt, bits } = await api("api/pow");
  // A slice is a few tens of milliseconds, and the page handles clicks between slices.
  const slice = 100000;
  for (let from = 0; ; from += slice) {
    const nonce = u.pow_search(salt, x, user_pk, exchange, bits, from, slice);
    if (nonce !== undefined) return { salt, nonce };
    await new Promise((resolve) => setTimeout(resolve));
  }
}

// The cards after the addresses are chosen, by `state.step`.
const STEP_CARDS = { 2: "kit", 3: "hop", 4: "sign", 5: "wait" };
const short = (a) => (a.length > 20 ? `${a.slice(0, 10)}…${a.slice(-6)}` : a);
// The start of a taproot address on each network.
const taprootPrefix = (network) => ({ bitcoin: "bc1p", regtest: "bcrt1p" })[network] ?? "tb1p";

// An address as typed, or scanned from a bitcoin: link. Bech32 ones are kept in lower case, so
// the same address always compares equal, in the kit too.
function cleanAddress(text) {
  const address = text.trim().replace(/^bitcoin:/i, "").replace(/\?.*$/, "");
  return /^(bc|tb|bcrt)1/i.test(address) ? address.toLowerCase() : address;
}

// A message from elsewhere, as the first of several sentences.
const capital = (text) => text.charAt(0).toUpperCase() + text.slice(1);

// Copies an element's text, and dims it for a moment to show it did.
async function copyText(el) {
  await navigator.clipboard.writeText(el.value ?? el.textContent);
  el.classList.add("copied");
  setTimeout(() => el.classList.remove("copied"), 400);
}

function render() {
  // One card at a time: before there's a hop address, the one choosing it; after, the hop
  // address's current step, or an earlier one the user went back to. Depositing, the exchange
  // asks for the signature once the coins arrive, so signing sits under the hop address's
  // status rather than being a step of its own.
  const view = state ? reopened ?? state.step : null;
  const shown = !state ? entry : agreeing ? "agree" : view === 2 && checking ? "check" : STEP_CARDS[view];
  const deposit = depositing();
  const open = (id) => id === `c-${shown}` || (deposit && shown === "wait" && id === "c-sign");
  for (const card of document.querySelectorAll(".card")) card.classList.toggle("open", open(card.id));
  // A screen reader hears nothing when a card swaps, so focus goes to its heading. Before there's
  // a hop address, `show` focuses the card's field instead.
  if (state && lastShown && shown !== lastShown) $(`c-${shown}`)?.querySelector("h2")?.focus({ preventScroll: true });
  lastShown = shown;
  for (const el of document.querySelectorAll("[data-mode]")) el.hidden = el.dataset.mode !== (deposit ? "deposit" : "withdraw");
  $("x-title").textContent = deposit ? "Your wallet's address" : "Where should the coins end up?";
  $("wait-title").textContent = deposit ? "Hop address" : "Withdraw to your hop address";
  // Depositing, the hop address card waits for the coins, and the poll moves on when they come.
  const waiting = deposit && state?.step < 5;
  $("hop-wait").hidden = $("sign-first").hidden = !waiting;
  $("next-3").hidden = waiting;
  $("wait-more").hidden = deposit && !details;
  $("wait-details").textContent = details ? "hide details" : "details";
  // Off mainnet a test address stands in for a real one.
  $("test-x").hidden = testHidden;
  $("test-exchange").hidden = info?.network === "bitcoin" || !info?.helpers;
  $("demo").hidden = !demo || !state?.y;
  // What's been chosen so far, above the card.
  const trail = [];
  if (state || entry !== "mode") trail.push(deposit ? "depositing" : "withdrawing");
  const exchange = state ? state.exchange : entry === "x" && deposit ? cleanAddress($("exchange").value) : "";
  if (exchange) trail.push(["exchange ", exchange, true]);
  if (state) trail.push([deposit ? "wallet " : "to ", state.x, false]);
  // A narrow screen breaks the line between parts, never inside one.
  $("trail-text").replaceChildren(...trail.flatMap((part, i) => [...(i ? [" · "] : []), trailPart(part)]));
  $("trail").hidden = !trail.length;
  // Back goes to the previous card, but never before the hop address once there is one:
  // changing the addresses then means starting over.
  $("back").hidden = shown !== "check" && (state ? Boolean(state.y) && view <= 3 : entry === "mode");
  // Each card has its own next. The kit's only matters once there's a hop address to go back to.
  $("kit-next-row").hidden = !state?.y;
  // On the kit card before the hop address, with a checked kit that doesn't list this exchange
  // address: save it again.
  const again = Boolean(state && !state.y && rescue?.checked && kitMissing());
  $("kit-again").hidden = !again;
  if (again) withAddresses($("kit-again"), ["Add this exchange to your kit: save it again so it lists ", state.exchange, ". You do this once for each exchange deposit address."]);
  // A browser with its own kit can only reuse that one, so there's nothing to offer.
  $("kit-restore").hidden = again || Boolean(rescue?.savedAt);
  $("kit-check").hidden = again || !rescue?.saved || rescue.checked;
  $("proof-row").hidden = proofRowHidden(state?.proof);
  // From the proof shown, which a failed new signature clears, so copy never copies nothing.
  $("copy").hidden = !$("proof").value;
  $("sign-again").textContent = state?.proof ? "sign another message" : "sign the exchange's message";
  $("kit-open").hidden = !state?.y || view === 2;
  // Only once there is one: before that, back undoes a mistake.
  $("forget-row").hidden = !state?.y || !$("forget-confirm").hidden;
  // Shown from what's saved, so a reload with the server unreachable still shows the address.
  // It was checked against the one built here when it was saved.
  if (state?.y && info) {
    $("y").textContent = state.y;
    // Split evenly on a narrow screen, as addressSpan does.
    for (const id of ["y", "wait-y"]) $(id).style.setProperty("--half", Math.ceil(state.y.length / 2));
    $("y-qr").textContent = u.address_qr(state.y);
    $("y-ok").textContent = `checked in this browser: ${deposit ? "your wallet" : "the destination"} can always claim from it`;
    // Text and addresses in turn, each address in its holder's colour.
    const parts = deposit
      ? ["forwards to:", state.exchange, "or recovered by:", state.x]
      : ["forwards to:", state.x];
    withAddresses($("hop-addrs"), parts);
    $("wait-y").textContent = state.y;
    // The wallet's key is read out of its address here rather than taken from the descriptor,
    // so a descriptor without it shows no cyan.
    const desc = u.descriptor(ctx());
    const keys = { [u.taproot_key(state.x, info.network)]: "wallet", [desc.match(/^tr\(([0-9a-f]{64}),/)?.[1]]: "shared" };
    withKeys($("desc"), desc, keys);
    withKeys($("desc-cmd"), `bitcoin-cli ${cliFlag(info.network)}deriveaddresses "${desc}"`, keys);
    withAddresses($("key-cmd"), [`bitcoin-cli ${cliFlag(info.network)}validateaddress `, state.x]);
    withAddresses($("desc-key"), ["The cyan key is the one inside ", state.x, ", so that address can always claim the funds alone. The striped key combines this browser's key and the server's, so spending with it takes both."]);
  }
  const saved = !rescue?.saved ? "" : rescue.checked ? `saved ${day(rescue.savedAt)}, checked` : `saved ${day(rescue.savedAt)}, not checked yet`;
  // Saying it's saved while asking to save it again reads as done.
  $("kit-ok").textContent = again ? "" : saved;
  $("check-title").textContent = restoring ? "Reuse your kit" : "Check your kit";
  $("check-hint").textContent = restoring
    ? "choose your kit file, or paste its rescue key."
    : "choose the file you just saved, so we know it's really there.";
}

// A part of the trail: a word, or a label and an address, shortened. Hovering shows the whole
// address, and a tap shows it in place, for screens without hover.
function trailPart(part) {
  const [label, address, theirs] = typeof part === "string" ? [part] : part;
  const span = Object.assign(document.createElement("span"), { textContent: label });
  if (address) {
    const a = addressSpan(address, short(address), theirs);
    Object.assign(a, { title: address });
    a.classList.add("short");
    a.addEventListener("click", () => {
      a.classList.toggle("short");
      a.textContent = a.classList.contains("short") ? short(address) : address;
    });
    span.append(a);
  }
  return span;
}

// Fills `el` with text and addresses in turn.
function withAddresses(el, parts) {
  el.replaceChildren(...parts.map((part, i) => (i % 2 ? addressSpan(part) : part)));
}

// An address in its holder's colour: the user's own in cyan, an exchange's in yellow. Whose
// it is can be given, for an exchange address not saved yet.
function addressSpan(address, text = address, theirs = address === state?.exchange || rescue?.exchanges?.includes(address)) {
  const span = Object.assign(document.createElement("span"), { className: theirs ? "addr theirs" : "addr", textContent: text });
  // Where an address gets a line of its own, a narrow screen splits it into two even halves.
  span.style.setProperty("--half", Math.ceil(text.length / 2));
  return span;
}

// The browser's and server's colours, alternating, for what takes both of them to spend. In
// pairs of characters: alternating every character, the two blur into one colour.
function striped(text) {
  const span = document.createElement("span");
  const pairs = text.match(/.{1,2}/g) ?? [];
  span.append(...pairs.map((pair, i) => Object.assign(document.createElement("span"), { className: i % 2 ? "k-s" : "k-b", textContent: pair })));
  return span;
}

// Fills `el` with `text`, colouring each key by who holds it: the wallet's in cyan, and the
// browser's and server's combined key in both their colours, alternating, since it takes both.
function withKeys(el, text, keys) {
  const found = Object.keys(keys).filter((key) => /^[0-9a-f]{64}$/.test(key));
  const parts = found.length ? text.split(new RegExp(`(${found.join("|")})`)) : [text];
  el.replaceChildren(...parts.map((part, i) => {
    if (i % 2 === 0) return part;
    if (keys[part] !== "wallet") return striped(part);
    return Object.assign(document.createElement("span"), { className: "k-d", textContent: part });
  }));
}

function showProof(proof) {
  $("proof").value = proof ?? "";
  for (const id of ["proof", "copy", "proof-hint"]) $(id).hidden = !proof;
  $("proof-row").hidden = proofRowHidden(proof);
  $("proof-ok").textContent = proof ? "valid signature for your hop address" : "";
}

// Next stays once signed before, so a failed new signature doesn't strand the user. Depositing
// has no next: the status is on the same page.
function proofRowHidden(proof) {
  return !proof && !(state?.step > 4 && !depositing());
}

// Going forward to a step already done shows it again rather than skipping past it.
function goTo(step) {
  state.step = Math.max(state.step, step);
  reopened = step < state.step ? step : null;
  save();
  render();
}

function show(card) {
  entry = card;
  render();
  $(card)?.focus();
}

onClick("back", async () => {
  if (registering) return;
  if (checking) {
    checking = restoring = false;
    return render();
  }
  if (!state) return show(entry === "x" && depositing() ? "exchange" : "mode");
  if (state.y) {
    const order = depositing() ? [2, 3, 5] : [2, 3, 4, 5];
    return goTo(order[order.indexOf(reopened ?? state.step) - 1]);
  }
  // Only the kit is left to do, so the addresses can still change.
  agreeing = false;
  mode = state.exchange ? "deposit" : "withdraw";
  $("x").value = state.x;
  $("exchange").value = state.exchange ?? "";
  state = null;
  localStorage.removeItem("unravel");
  show("x");
});
onClick("kit-next", async () => goTo(3));
onClick("agree", async () => {
  $("agree-err").textContent = "";
  localStorage.setItem("unravel-agreed", "1");
  await register().catch((e) => { $("agree-err").textContent = e.message; });
});
onClick("sign-again", async () => goTo(4));
onClick("sign-first", async () => goTo(5));
// The intro's screenshot of an exchange asking for the proof, shown in place.
onClick("travelrule-open", async () => {
  const shot = $("travelrule");
  shot.hidden = !shot.hidden;
  $("travelrule-open").setAttribute("aria-expanded", String(!shot.hidden));
});
onClick("wait-details", async () => {
  details = !details;
  render();
});
// The kit stays reachable after the hop address exists: to save it again, or to restore one.
onClick("kit-open", async () => {
  reopened = 2;
  checking = restoring = false;
  render();
});
onClick("kit-check", async () => {
  checking = true;
  restoring = false;
  $("kit-err").textContent = "";
  render();
});
onClick("kit-restore", async () => {
  checking = restoring = true;
  $("kit-err").textContent = "";
  render();
});
onClick("kit-paste", async () => {
  $("kit-paste-row").hidden = true;
  $("kit-paste-box").hidden = false;
  $("kit-typed").focus();
});

for (const m of ["withdraw", "deposit"]) {
  onClick(`mode-${m}`, async () => {
    mode = m;
    show(m === "deposit" ? "exchange" : "x");
  });
}

onClick("exchange-next", async () => {
  $("exchange-err").textContent = "";
  if (!u.is_exchange_address(cleanAddress($("exchange").value), info.network)) {
    $("exchange-err").textContent = `that isn't a bitcoin address on ${info.network}.`;
    return;
  }
  show("x");
});

onClick("test-exchange", async () => {
  $("exchange").value = (await api("api/demo/x")).x;
  $("exchange-next").click();
});

onClick("test-x", async () => {
  $("x").value = (await api("api/demo/x")).x;
  $("make").click();
});

// The actions are links styled as buttons, so they're announced as buttons and Space presses
// them too, as it does a button.
for (const a of document.querySelectorAll('a[href="#"]')) a.setAttribute("role", "button");
document.addEventListener("keydown", (e) => {
  if (e.key !== " " || !e.target.matches?.('a[role="button"]')) return;
  e.preventDefault();
  e.target.click();
});

// Enter in an address field continues, as the card's button does.
for (const [field, next] of [["exchange", "exchange-next"], ["x", "make"]]) {
  $(field).addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !$(next).classList.contains("busy")) $(next).click();
  });
}

onClick("make", async () => {
  $("x-err").textContent = "";
  const x = cleanAddress($("x").value);
  if (!u.is_address(x, info.network)) {
    const prefix = taprootPrefix(info.network);
    const other = ["bitcoin", "testnet", "regtest"].find((n) => n !== info.network && u.is_exchange_address(x, n));
    $("x-err").textContent = u.is_exchange_address(x, info.network)
      ? depositing()
        ? `That isn't a taproot address. Your own wallet's goes here, not the exchange's: one starting ${prefix}, from a taproot account.`
        : `That isn't a taproot address. Use one from a taproot account in your wallet: it starts ${prefix}.`
      : other
        ? `that's a ${other} address, and this server is on ${info.network}.`
        : `That isn't a taproot address on ${info.network}. It starts ${prefix}.`;
    return;
  }
  const exchange = depositing() ? cleanAddress($("exchange").value) : undefined;
  if (exchange !== undefined) {
    // The same address twice would make an ordinary hop address that forwards to the wallet.
    if (exchange.toLowerCase() === x.toLowerCase()) {
      $("x-err").textContent = "That's the same address twice. The exchange's deposit address goes first, your wallet's second.";
      return;
    }
  }
  if (exchange) rememberExchange(exchange);
  state = { x, exchange, step: 2 };
  if (kitMissing()) {
    checking = rescue?.saved === true && !rescue.checked;
    return goTo(2);
  }
  try {
    await register();
  } catch (e) {
    state = null;
    $("x-err").textContent = e.message;
  }
});

onClick("sign", async () => {
  $("sign-err").textContent = "";
  showProof(null);
  // A copied message often brings a newline with it, which the exchange's check wouldn't expect.
  const challenge = $("challenge").value.trim();
  if (!challenge) {
    $("sign-err").textContent = "paste the exchange's challenge message first.";
    return;
  }
  // The server's limit. A much longer one wouldn't even reach it whole.
  if (new TextEncoder().encode(challenge).length > 2048) {
    $("sign-err").textContent = "that message is too long";
    return;
  }
  try {
    const request = await api("api/challenge", { y: state.y, challenge });
    const response = JSON.parse(u.sign_challenge(ctx(), JSON.stringify(request), challenge));
    const { proof } = await api("api/complete", { y: state.y, response });
    if (u.verify_proof(state.y, challenge, proof)) {
      Object.assign(state, { challenge, proof });
      save();
      showProof(proof);
    } else {
      $("sign-err").textContent = "The signature didn't check out. Don't use it.";
    }
  } catch (e) {
    $("sign-err").textContent = e.message;
  }
});

onClick("copy-y", async () => copyText($("y")));
onClick("copy-wait-y", async () => copyText($("wait-y")));

// Clicking an address, the signature, the spending rules or a command copies it, and it dims
// for a moment to show it did. A command copies whole, even where the click is on an address in
// it. The trail's shortened addresses show in full on a click instead.
document.addEventListener("click", async (e) => {
  const el = e.target.closest("#desc, #desc-cmd, #key-cmd") ?? e.target.closest(".big, .addr, #proof");
  if (!el || el.closest("#trail-text")) return;
  await copyText(el);
});

onClick("verify-y", async () => {
  $("verify").hidden = !$("verify").hidden;
});
onClick("copy-desc", async () => copyText($("desc")));

onClick("next-3", async () => goTo(depositing() ? 5 : 4));
onClick("next-4", async () => goTo(5));

function kitText() {
  const key = rescueKey();
  return `UNRAVEL RULE EMERGENCY KIT

format:   ${KIT_FORMAT}
created:  ${day(rescue.created ?? Date.now())}
network:  ${info.network}
server:   ${server}

rescue key:
  ${key}

server key:
  ${info.service_pk}

${exchangesText()}Keep this private. With it and your bc1p address, someone can
find your hop addresses and rebuild the browser's half of their
key. That can't move funds without the server's half.

It covers every hop address made with the server above in the
browser that made this kit. The rescue key never changes, but a
new kit is needed if that browser switches server. A hop address
made for depositing to an exchange also needs that exchange's
deposit address. This kit lists the ones used so far, and the
page asks you to save it again when you use a new one.


HOW TO RECOVER

Your bc1p address is the one you gave the page: the destination
when withdrawing, or your wallet's address when depositing. If
that browser or the server is gone, whoever holds its key can
still claim anything sent to a hop address.

1. Open ${new URL("recover", server).href}
   or your saved copy of it (unravelrule-recover.html), which
   works offline.
2. Enter the rescue key and your bc1p address. For a hop address
   made for depositing to an exchange, also enter the exchange's
   deposit address. It gives you the hop address and its
   spending rules (a descriptor).
3. Check them without trusting the page. This should print your
   hop address:
   bitcoin-cli ${cliFlag(info.network)}deriveaddresses "<descriptor>"
4. Claim with your bc1p address's key through the hidden script,
   <D> OP_CHECKSIG, signing with that address's tweaked private
   key (BIP-86). Bitcoin Core can do this if you give it that key.
   The source code at https://github.com/nickfarrow/unravel-rule
   has a command for it, \`just rescue\`: give it this kit and
   your seed words, offline, and it prints the Bitcoin Core
   commands.


HOW IT'S BUILT, SO ANYONE CAN REBUILD IT

X = your bc1p address
E = the exchange's deposit address, only when depositing
R = the rescue key's first 16 bytes (the last 2 are a checksum)
b = TaggedHash("unravel/browser-key/v1", R || scriptPubKey of X)
    mod n, with TaggedHash as in BIP-340
B = b*G, the browser key
S = the server key above, 33 bytes compressed
D = the key inside X
K = MuSig2(B, S) when withdrawing, or MuSig2(B, S + t*G) when
    depositing, where t = TaggedHash("unravel/exchange/v1",
    S || scriptPubKey of E) mod n
hop address = tr(K, pk(D)), where MuSig2 is BIP-327 key
    aggregation of the two keys in that order, not sorted
`;
}

// The exchange deposit addresses a kit lists, read back from its text.
function kitExchanges(text) {
  return text.match(/exchange deposit addresses used so far:\r?\n((?:[ \t]+\S+\r?\n?)+)/)?.[1].trim().split(/\s+/) ?? [];
}

// The exchange deposit addresses this browser has used so far, for the kit.
function exchangesText() {
  const exchanges = rescue?.exchanges ?? [];
  if (!exchanges.length) return "";
  return `exchange deposit addresses used so far:
${exchanges.map((e) => `  ${e}`).join("\n")}

`;
}

onClick("kit-get", async () => {
  const a = document.createElement("a");
  // A data: URL rather than a blob: one, which wallet apps' built-in browsers often drop.
  a.href = `data:text/plain;charset=utf-8,${encodeURIComponent(kitText())}`;
  a.download = `unravelrule-emergency-kit-${Math.floor(Date.now() / 1000)}.txt`;
  a.click();
  await kitSaved(false);
});

// Wallet browsers on phones often drop downloads, so the text can go to the clipboard instead.
onClick("kit-copy", async () => {
  await navigator.clipboard.writeText(kitText());
  await kitSaved(false);
});

// `checked` means the user showed they hold the kit, not just that a download started.
// Phone wallets' built-in browsers can drop a download silently, so no hop address is made
// until the kit is checked. `listed` is the exchange addresses in the kit they showed.
async function kitSaved(checked, listed) {
  // Saving the same kit again doesn't undo an earlier check, unless it now lists a new
  // exchange address: that kit is checked again, for the address.
  const newExchange = Boolean(state?.exchange && !rescue.inKit?.includes(state.exchange));
  rescue.checked = checked || (rescue.checked === true && savedForThisServer() && !newExchange);
  rescue.saved = true;
  rescue.savedAt = Date.now();
  rescue.servicePk = info.service_pk;
  // The exchange addresses in the kit the user holds: what they showed, or what was just saved.
  rescue.inKit = listed ?? rescue.exchanges ?? [];
  localStorage.setItem("unravel-rescue", JSON.stringify(rescue));
  $("kit-save-err").textContent = "";
  // Asks the browser not to clear this site's storage, rescue key included, when it's idle.
  navigator.storage?.persist?.().catch(() => {});
  if (!rescue.checked) {
    checking = true;
    restoring = false;
    render();
    return;
  }
  // Off the check card, or back would first return to it.
  checking = restoring = false;
  // A kit from before this exchange address was used: the kit card asks to save it again.
  if (state && !state.y && kitMissing()) return render();
  try {
    await register();
  } catch (e) {
    $("kit-err").textContent = e.message;
  }
}

// Restoring brings back hop addresses made in another browser, or before this one's storage
// was cleared. It replaces this browser's key only while that key has never backed a hop
// address: one saved for another server still does.
// The kit's exchange addresses join this browser's, so the next kit it saves still lists them.
function adopt(key, listed) {
  if (rescue?.savedAt && rescue.key !== key) {
    throw new Error(restoring
      ? "This browser already has its own kit. Restore in another browser or a private window."
      : "That isn't the kit you just saved. Use that one.");
  }
  rescue = { ...(rescue?.key === key ? rescue : { key }), exchanges: [...new Set([...(rescue?.exchanges ?? []), ...listed])] };
  localStorage.setItem("unravel-rescue", JSON.stringify(rescue));
}

// A typed key doesn't say which server the user's kit names, and recovery needs that, so it
// only counts as this server's kit if this browser already saved one for this server.
function savedForThisServer() {
  return rescue?.servicePk === info.service_pk;
}

// Pasting proves the user holds the kit as well as uploading does: the copy might never have
// reached their notes, but the rescue key in what they paste back did.
onClick("kit-verify", async () => {
  $("kit-err").textContent = "";
  const found = $("kit-typed").value.match(/[0-9a-f]{4}(?:[\s-]*[0-9a-f]{4}){8}/i);
  if (!found) {
    $("kit-err").textContent = "No rescue key in that. Paste the whole kit, or its nine groups of four letters and numbers.";
    return;
  }
  let key;
  try {
    key = u.parse_rescue_key(found[0]);
  } catch (e) {
    $("kit-err").textContent = `${capital(e.message ?? String(e))}. Check it and try again.`;
    return;
  }
  const text = $("kit-typed").value;
  try {
    adopt(key, kitExchanges(text));
  } catch (e) {
    $("kit-err").textContent = e.message;
    return;
  }
  // The rescue key is in every kit, so only the whole kit shows it lists the new exchange address.
  if (!restoring && state?.exchange && !state.y && !text.includes(state.exchange)) {
    withAddresses($("kit-err"), ["paste the whole kit you just saved: it lists ", state.exchange, "."]);
    return;
  }
  // A rescue key alone doesn't say, so it counts as the kit just saved.
  if (savedForThisServer()) return kitSaved(true, text.includes("UNRAVEL RULE EMERGENCY KIT") ? kitExchanges(text) : undefined);
  checking = restoring = false;
  render();
  $("kit-save-err").textContent = "Rescue key restored. Now download or copy the kit: a pasted key doesn't say which server your old kit names.";
});

onClick("kit-upload", async () => $("kit-file").click());

$("kit-file").addEventListener("change", async () => {
  $("kit-err").textContent = "";
  const file = $("kit-file").files[0];
  $("kit-file").value = "";
  if (!file) return;
  const text = await file.text();
  const found = text.match(/[0-9a-f]{4}(?:-[0-9a-f]{4}){8}/i);
  if (!text.includes("UNRAVEL RULE EMERGENCY KIT")) {
    $("kit-err").textContent = "that file isn't an emergency kit.";
    return;
  }
  const format = text.match(/^format:\s*(\d+)/m)?.[1];
  if (format !== String(KIT_FORMAT)) {
    $("kit-err").textContent = format
      ? `that kit is format ${format}, and this page reads format ${KIT_FORMAT}.`
      : "that kit is from before kits had a format, and this page can't read it.";
    return;
  }
  let key;
  try {
    if (!found) throw new Error("no rescue key in that file");
    key = u.parse_rescue_key(found[0]);
  } catch (e) {
    $("kit-err").textContent = `${capital(e.message ?? String(e))}. Try again, or paste the rescue key instead.`;
    return;
  }
  if (!text.includes(info.service_pk)) {
    const other = text.match(/^server:\s*(\S+)/m)?.[1];
    $("kit-err").textContent = other && other !== server
      ? `That kit is for the server at ${other}. Connect to it at the top right, then try again.`
      : "That kit is for a different server key. Download a new one and try again.";
    return;
  }
  try {
    adopt(key, kitExchanges(text));
  } catch (e) {
    $("kit-err").textContent = e.message;
    return;
  }
  if (!restoring && state?.exchange && !state.y && !text.includes(state.exchange)) {
    withAddresses($("kit-err"), ["That kit doesn't list ", state.exchange, ". Choose the one you just saved."]);
    return;
  }
  await kitSaved(true, kitExchanges(text));
});

onClick("copy", async () => copyText($("proof")));

// Every deposit waiting for the choice goes where the user chose.
async function sendChosen(toX) {
  for (const outpoint of choices[toX ? "x" : "exchange"]) await forward(toX, outpoint);
  await poll();
}
onClick("send-exchange", async () => sendChosen(false));
onClick("send-x", async () => sendChosen(true));

onClick("withdraw", async () => {
  await api("api/demo/withdraw", { y: state.y, sat: 100000 });
  await poll();
});

onClick("mine", async () => {
  await api("api/demo/mine");
  await poll();
});

function startOver() {
  leaving = true;
  localStorage.removeItem("unravel");
  location.reload();
}
// Asks in the page first. Entering the same addresses again brings the hop address back, but
// what matters now is not sending more to it.
onClick("forget", async () => {
  if (!state?.y) return startOver();
  $("forget-what").replaceChildren("this page will stop watching ", Object.assign(document.createElement("span"), { className: "hop", textContent: short(state.y) }), ", so don't send any more to it.");
  $("forget-row").hidden = true;
  $("forget-confirm").hidden = false;
});
onClick("forget-yes", async () => startOver());
onClick("forget-no", async () => {
  $("forget-confirm").hidden = true;
  $("forget-row").hidden = false;
});

// `toX` sends a deposit to the wallet instead of the exchange, such as one the exchange returned.
// `outpoint` names the deposit, where it matters which one goes where.
async function forward(toX = false, outpoint = undefined) {
  if (forwarding) return;
  forwarding = true;
  try {
    const { request } = await api("api/forward", { y: state.y, to_x: toX, outpoint });
    if (!request) {
      $("fwd-err").textContent = "";
      return;
    }
    // The wasm refuses unless the forward pays where the user chose, everything except the
    // network fee.
    const signed = JSON.parse(u.sign_forward(ctx(), JSON.stringify(request), toX));
    const { txid } = await api("api/complete", { y: state.y, response: signed.response });
    // Kept so the status can say how much went where, which the server doesn't say.
    const sent = { txid, sat: signed.sent_sat, to: toX ? state.x : state.exchange ?? state.x };
    state.forwards = [...(state.forwards ?? []).filter((f) => f.txid !== txid), sent];
    save();
    $("fwd-err").textContent = "";
  } catch (e) {
    $("fwd-err").textContent = e.message;
  } finally {
    forwarding = false;
  }
}

async function pollFee() {
  try {
    fee = await api("api/fee");
  } catch {
    return;
  }
  const market = fee.market_rate;
  const high = market > fee.max_rate;
  $("fee").textContent = `network fee: ~${fee.forward_fee_sat} sats`;
  $("fee").dataset.rate = `${fee.fee_rate} sat/vB${high ? `, capped: the market is at ${market}` : ""}`;
  $("fee").classList.toggle("high", high);
  $("fee").hidden = fee.forward_fee_sat == null;
  $("fee-warn").textContent = high
    ? `Fees are high right now (${market} sat/vB). The forward pays at most ${fee.max_rate} sat/vB, so it may take hours or days to confirm, and nothing here can speed it up. Only ${depositing() ? "the exchange or your wallet" : "the destination"} can receive the coins meanwhile.`
    : "";
}

const sats = (n) => `${n.toLocaleString("en")} sats`;

// Regtest has no public explorer, so its transaction ids aren't links.
const EXPLORER = {
  bitcoin: "https://mempool.space/",
  testnet: "https://mempool.space/testnet/",
  testnet4: "https://mempool.space/testnet4/",
  signet: "https://mempool.space/signet/",
};

// A transaction id, linking to its page on mempool.space. Nothing is
// fetched from there unless the user clicks.
function txidLink(txid) {
  const base = EXPLORER[info.network];
  const el = document.createElement(base ? "a" : "span");
  el.className = "txid";
  el.textContent = txid;
  if (base) Object.assign(el, { href: `${base}tx/${txid}`, target: "_blank", rel: "noopener noreferrer" });
  return el;
}

// One line that says where things stand: `kind` is "waiting", "done" or "warn".
function setStatus(kind, parts) {
  // Rewritten only when it changes: it's a live region, and each rewrite is read out again.
  if ($("status-main").className === `status ${kind}` && $("status-main").textContent === parts.join("")) return;
  $("status-main").className = `status ${kind}`;
  withAddresses($("status-main"), parts);
}

// What a forward sent, and where. An older server doesn't say, for one this page didn't make.
function forwardWhat(f) {
  const amount = f.sat ? sats(f.sat) : "the coins";
  if (!depositing()) return `sent ${amount}`;
  return f.to ? `hopped ${amount} to ${f.to === state.exchange ? "the exchange" : "your wallet"}` : `hopped ${amount} on`;
}

// The status line for the latest forward. `confirmed` is unknown for one a restarted server forgot.
function forwardStatus(f) {
  const what = forwardWhat(f);
  if (depositing()) {
    const said = f.confirmed === true ? `done: ${what}` : f.confirmed === false ? `${what}, awaiting confirmation` : what;
    return f.to ? [said, f.to] : [said];
  }
  if (f.confirmed === true) return [`done: ${what} to`, state.x];
  return [f.confirmed === false ? `${what}, waiting for it to confirm, to` : `${what} to`, state.x];
}

async function poll() {
  if (!state?.y) return;
  try {
    const s = await api("api/status", { y: state.y });
    // A deposit means the exchange step is done, whatever card the user is on.
    if ((s.deposits.length || s.forwards.length) && state.step < 5) goTo(5);
    // The server's minimum is for a taproot output. A forward to an older type of exchange
    // address has a higher dust limit.
    const minFor = (address) => fee?.min_deposit_sat == null ? null
      : fee.min_deposit_sat - u.dust_limit(state.x, info.network) + u.dust_limit(address, info.network);
    const min = minFor(state.exchange ?? state.x);
    // Only a deposit the forward's fee leaves something of. Asking about one too small would
    // cost the server an Electrum lookup every poll, only to be refused.
    // Without a fee estimate the server refuses to forward anyway.
    // A withdrawal waits for a confirmation, since exchanges fee-bump them. Coins from the
    // user's own wallet, sent to a hop address that deposits to an exchange, go on at once.
    const ready = (d) => depositing() || d.confirmations >= 1;
    const forwardable = (to) => {
      const least = minFor(to);
      return least != null && s.deposits.some((d) => ready(d) && d.sat >= least);
    };
    const total = (deposits) => sats(deposits.reduce((sum, d) => sum + d.sat, 0));
    const enough = (to) => (d) => minFor(to) != null && d.sat >= minFor(to);
    const confirmed = s.deposits.filter(ready);
    const arriving = s.deposits.filter((d) => !ready(d));

    // Every forward, oldest first: the ones this page made that the server has forgotten since
    // it restarted, which can't say whether they've confirmed, then the ones the server lists.
    const own = state.forwards ?? [];
    const fromServer = (f) => ({
      ...own.find((o) => o.txid === f.txid),
      ...f,
      ...(f.to_x != null && { to: f.to_x ? state.x : state.exchange ?? state.x }),
    });
    const forwards = [
      ...own.filter((o) => !s.forwards.some((f) => f.txid === o.txid)),
      ...s.forwards.map(fromServer),
    ];
    const latest = forwards.at(-1);

    // Depositing, every deposit that arrives before the hop address first spends is the user's
    // own, and goes to the exchange. One that arrives after may be a deposit the exchange
    // returned, so the user chooses where it goes, rather than the page sending it straight
    // back. The server reads from the chain whether the hop address has spent, so a restart
    // doesn't forget. An older server only knows the forwards it made since it started.
    let auto = [];
    if (depositing()) {
      const spent = s.spent ?? (s.forwards.length > 0 || own.length > 0);
      const fresh = spent ? [] : s.deposits.map((d) => d.outpoint).filter((o) => !state.auto?.includes(o));
      if (fresh.length) {
        state.auto = [...(state.auto ?? []), ...fresh];
        save();
      }
      auto = confirmed.filter((d) => state.auto?.includes(d.outpoint));
      const asked = confirmed.filter((d) => !state.auto?.includes(d.outpoint));
      choices = {
        exchange: asked.filter(enough(state.exchange)).map((d) => d.outpoint),
        x: asked.filter(enough(state.x)).map((d) => d.outpoint),
      };
      $("send-exchange").hidden = !choices.exchange.length;
      $("send-x").hidden = !choices.x.length;
      $("send-choice").hidden = $("send-exchange").hidden && $("send-x").hidden;
    }
    // Whether the status line is the latest forward, so the list under it leaves that one out.
    let showsLatest = false;
    const going = auto.filter(enough(state.exchange));
    // Keeping the page open only matters while there are coins to send on. One too small
    // to send never will be.
    $("close-note").hidden = depositing()
      ? !going.length && $("send-choice").hidden
      : Boolean(latest) && !arriving.length && !forwardable(state.x);
    if (!$("send-choice").hidden) {
      const asked = confirmed.filter((d) => !auto.includes(d));
      setStatus("waiting", [`${total(asked)} arrived. Where should ${asked.length > 1 ? "they" : "it"} go?`]);
    } else if (!depositing() && forwardable(state.x)) {
      setStatus("waiting", [`sending ${total(confirmed.filter((d) => d.sat >= min))} on to`, state.x]);
      await forward();
    } else if (going.length) {
      setStatus("waiting", [`hopping ${total(going)} to the exchange`, state.exchange]);
      await forward(false, going[0].outpoint);
    } else if (arriving.length) {
      setStatus("waiting", [`${total(arriving)} on the way. Waiting for a confirmation`]);
    } else if (confirmed.length && min == null) {
      setStatus("waiting", [`${total(confirmed)} arrived. Waiting for a fee estimate`]);
    } else if (latest) {
      setStatus("done", forwardStatus(latest));
      showsLatest = true;
    } else if (confirmed.length) {
      setStatus("warn", [`${total(confirmed)} arrived, but that's too small to send on at today's fees`]);
    } else {
      setStatus("waiting", [depositing() ? "waiting for your deposit" : "waiting for your withdrawal"]);
    }

    // Each forward gets a line of its own, newest first, so none of them seems to go missing.
    const earlier = (showsLatest ? forwards.slice(0, -1) : [...forwards]).reverse();
    const suffix = (f) => (f.confirmed === true ? ", confirmed" : f.confirmed === false ? ", awaiting confirmation" : "");
    $("status-earlier").replaceChildren(...earlier.flatMap((f, i) => [...(i ? [document.createElement("br")] : []), forwardWhat(f) + suffix(f)]));
    $("status-earlier").hidden = !earlier.length;

    const detail = [];
    if (min != null) detail.push(`network fee about ${sats(fee.forward_fee_sat)} · send at least ${sats(min)}`);
    if (latest) detail.push(...(detail.length ? [document.createElement("br")] : []), "last forward ", txidLink(latest.txid));
    // What a forward left behind, too small to send: said here, so it doesn't hide the forward.
    if (latest && confirmed.length && min != null && $("send-choice").hidden) {
      detail.push(document.createElement("br"), `${total(confirmed)} also arrived, too small to send on at today's fees. Your emergency kit can claim it.`);
    }
    $("status-detail").replaceChildren(...detail);
    // Depositing, the minimum matters before sending, while the hop address card waits.
    $("hop-wait").textContent = min == null ? "waiting for your deposit" : `waiting for your deposit of at least ${sats(min)}`;
  } catch (e) {
    setStatus("warn", [e.message]);
    // The server forgets hop addresses when it restarts. Registering again brings this one back.
    // If that fails too, say why: after a server key change the mismatch is the news.
    if (e.message === "unknown deposit address") await register().catch((err) => setStatus("warn", [err.message]));
  }
}

onClick("conn-set", async () => switchServer($("conn-new").value.trim()));
onClick("conn-reset", async () => switchServer(SITE_SERVER));
$("conn-url").textContent = server;
$("conn-reset").hidden = !SITE_SERVER || server === SITE_SERVER;
// A copy opened from disk has no about or recovery page beside it, so these go to the server's.
if (server) {
  for (const a of document.querySelectorAll('a[href="about"], a[href="recover"]')) {
    a.href = new URL(a.getAttribute("href"), server).href;
  }
}

try {
  await init();
} catch (e) {
  $("page-err").textContent = "this page needs WebAssembly, which this browser has turned off.";
  document.querySelector(".steps").hidden = true;
  throw e;
}
try {
  if (!server) throw new Error("This copy has no server set. Enter one below.");
  info = await api("api/info");
  checkProtocol(info);
} catch (e) {
  setConn(false);
  $("conn-err").textContent = e.message;
  $("conn").open = true;
  document.querySelector(".steps").hidden = true;
  // Nothing below works without a server this page can speak to.
  throw e;
}
$("conn-net").textContent = info.network;
$("conn-key").textContent = info.service_pk;
$("conn-proto").textContent = info.protocol;
$("net").textContent = `${info.network} · no service fee`;
testHidden = info.network === "bitcoin" || !info.helpers;
demo = info.helpers && info.network !== "bitcoin";
// A kit names the server key, and recovery needs the right one, so a kit saved for another
// server (another network, or a regtest demo on this same origin) doesn't count.
if (rescue?.saved && rescue.servicePk !== info.service_pk) {
  rescue.saved = false;
  rescue.checked = false;
  localStorage.setItem("unravel-rescue", JSON.stringify(rescue));
}
// A hop address belongs to one server key. This server has another, so it can't forward.
if (state?.y && !rescue?.saved) {
  const hop = Object.assign(document.createElement("span"), { className: "hop", textContent: state.y });
  $("mode-err").replaceChildren(
    "This server's key has changed since your hop address ", hop, " was made, so it can't forward from it. Anything sent there can be claimed on the recovery page with the emergency kit you saved for it",
    ...(state.exchange ? [" and the exchange's deposit address ", addressSpan(state.exchange), ", which this browser keeps with its kit"] : []),
    ". Start again for a new hop address.",
  );
  localStorage.removeItem("unravel");
  state = null;
}
// A kit saved but not yet checked: back to checking it.
checking = Boolean(state && !state.y && rescue?.saved && !rescue.checked);
render();
if (state?.y) {
  if (state.proof) {
    $("challenge").value = state.challenge;
    showProof(state.proof);
  }
  // A failure here is most likely the server restarting, and polling registers again, so the
  // hop address is kept.
  await register().catch((e) => { $("page-err").textContent = e.message; });
} else if (state && !kitMissing()) {
  // The kit was checked but making the hop address failed then. Try again.
  await register().catch((e) => { $("kit-err").textContent = e.message; });
}
// Every tab shows this browser's one hop address. When another tab starts over, picks another
// destination or switches server, this one reloads to match, rather than later saving over
// what that tab saved. Smaller changes, such as a step done or a kit checked, are taken as is.
addEventListener("storage", (e) => {
  if (e.key === "unravel-rescue") {
    rescue = JSON.parse(e.newValue || "null");
    render();
  } else if (e.key === "unravel") {
    const next = JSON.parse(e.newValue || "null");
    if (next?.x !== state?.x || next?.y !== state?.y) return location.reload();
    state = next;
    render();
  } else if (e.key === "unravel-server" || e.key === null) {
    location.reload();
  }
});
// Fee estimates move slowly, and each check costs the server a lookup.
(async function feeLoop() {
  await pollFee();
  setTimeout(feeLoop, 15000);
})();
// Each poll waits for the last: a slow chain backend would otherwise pile requests up.
(async function loop() {
  await poll();
  setTimeout(loop, 2000);
})();
