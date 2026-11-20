import init, * as u from "./pkg/unravel_web.js";

const $ = (id) => document.getElementById(id);
// The kit format this page reads. A kit of another format derives different keys.
const KIT_FORMAT = 1;

function cliFlag(network) {
  return { bitcoin: "", testnet: "-testnet ", testnet4: "-testnet4 " }[network] ?? `-${network} `;
}

// Copies an element's text, and dims it for a moment to show it did.
async function copyText(el) {
  await navigator.clipboard.writeText(el.value ?? el.textContent);
  el.classList.add("copied");
  setTimeout(() => el.classList.remove("copied"), 400);
}

function onCopy(id, target) {
  $(id).addEventListener("click", async (e) => {
    e.preventDefault();
    await copyText($(target));
  });
}

// Clicking an address, the spending rules or the command copies it, as on the main page.
document.addEventListener("click", async (e) => {
  const el = e.target.closest(".big, .addr, #desc, #cmd");
  if (el) await copyText(el);
});

$("go").addEventListener("click", (e) => {
  e.preventDefault();
  $("err").textContent = "";
  $("out").hidden = true;
  const network = $("net").value;
  const xs = $("x").value.split(/[\s,]+/).filter(Boolean);
  // Addresses compare in lower case: a QR code often gives the upper-case form.
  const hop = $("hop").value.trim().toLowerCase();
  const exchanges = $("exchange").value.split(/[\s,]+/).filter(Boolean);
  try {
    const rescue = u.parse_rescue_key($("rescue").value.trim());
    $("rescue").value = rescue;
    if (!xs.length) throw new Error("enter your bc1p address");
    const bad = xs.find((x) => !u.is_address(x, network));
    if (bad) throw new Error(`${bad} isn't a taproot address on ${network}`);
    const badExchange = exchanges.find((e) => !u.is_exchange_address(e, network));
    if (badExchange) throw new Error(`${badExchange} isn't an exchange deposit address this page accepts on ${network}`);
    // Listing a hop address per candidate would send people to look each one up on a block
    // explorer, which ties them all together. Matching against the known one stays offline.
    // An exchange address is there even for a withdrawal's hop address when the kit filled it in,
    // so only the hop address tells which one, if any, it was made with.
    if (exchanges.length && !hop) throw new Error("With an exchange deposit address, enter the hop address too, so this page can tell whether it was made for depositing. For a withdrawal's hop address, clear the exchange addresses.");
    if (xs.length > 1 && !hop) throw new Error("with several addresses, enter the hop address too, so this page can find the ones that match");
    // Rebuilding the address needs no fee limit. That only matters when signing a forward.
    const ctxFor = ({ x, exchange }) => JSON.stringify({
      x, exchange, network, rescue,
      service_pk: $("spk").value.trim(),
      max_miner_fee_sat: 0,
    });
    // Each bc1p address alone, and with each exchange deposit address.
    const candidates = xs.flatMap((x) => [undefined, ...exchanges].map((exchange) => ({ x, exchange })));
    const found = hop ? candidates.find((c) => u.deposit_address(ctxFor(c)) === hop) : { x: xs[0] };
    if (!found) {
      throw new Error(candidates.length > 1
        ? "None of these addresses gives that hop address. Check the rescue key and server key, or paste more of your wallet's or the exchange's addresses."
        : "That bc1p address doesn't give that hop address. Check the rescue key and server key, or try another address. A hop address made for depositing to an exchange also needs that exchange's deposit address.");
    }
    const ctx = ctxFor(found);
    const desc = u.descriptor(ctx);
    $("y").textContent = u.deposit_address(ctx);
    // Split evenly on a narrow screen, as on the main page.
    $("y").style.setProperty("--half", Math.ceil($("y").textContent.length / 2));
    // Each address in its holder's colour, as on the main page.
    const addr = (address, theirs) => Object.assign(document.createElement("span"), { className: theirs ? "addr theirs" : "addr", textContent: address });
    const via = found.exchange ? [" with the exchange's deposit address ", addr(found.exchange, true)] : [];
    $("x-used").replaceChildren(...(hop ? ["Matches ", addr(found.x), ...via, ". Claim with ", addr(found.x), "'s key."] : []));
    $("desc").value = desc;
    $("cmd").textContent = `bitcoin-cli ${cliFlag(network)}deriveaddresses "${desc}"`;
    $("out").hidden = false;
  } catch (e) {
    $("err").textContent = e.message ?? e;
  }
});

$("upload").addEventListener("click", (e) => {
  e.preventDefault();
  $("kit-file").click();
});

// Fills the fields from the kit, so nothing is retyped wrong. The bc1p address isn't in it.
$("kit-file").addEventListener("change", async () => {
  $("err").textContent = "";
  $("kit-ok").textContent = "";
  const file = $("kit-file").files[0];
  $("kit-file").value = "";
  if (!file) return;
  const text = await file.text();
  if (!text.includes("UNRAVEL RULE EMERGENCY KIT")) {
    $("err").textContent = "that file isn't an emergency kit.";
    return;
  }
  const format = text.match(/^format:\s*(\d+)/m)?.[1];
  if (format !== String(KIT_FORMAT)) {
    $("err").textContent = format
      ? `that kit is format ${format}, and this page reads format ${KIT_FORMAT}.`
      : "that kit is from before kits had a format, and this page can't read it.";
    return;
  }
  const rescue = text.match(/[0-9a-f]{4}(?:-[0-9a-f]{4}){8}/i)?.[0];
  const spk = text.match(/server key:\s*([0-9a-f]{66})/i)?.[1];
  const network = text.match(/^network:\s*(\S+)/m)?.[1];
  if (!rescue || !spk) {
    $("err").textContent = "No rescue key or server key in that kit. Is it complete?";
    return;
  }
  $("rescue").value = rescue;
  $("spk").value = spk;
  if (network && [...$("net").options].some((o) => o.value === network)) $("net").value = network;
  const exchanges = text.match(/exchange deposit addresses used so far:\n((?:[ \t]+\S+\n?)+)/)?.[1].trim().split(/\s+/) ?? [];
  $("exchange").value = exchanges.join("\n");
  $("kit-ok").textContent = exchanges.length
    ? "Filled in from your kit. Now enter your bc1p address, and the hop address."
    : "Filled in from your kit. Now enter your bc1p address.";
  $("x").focus();
});

onCopy("copy-y", "y");
onCopy("copy-desc", "desc");
onCopy("copy-cmd", "cmd");

await init();
// Only a convenience. The kit has both values, so the page still works with our server gone.
try {
  const res = await fetch("api/info", { method: "POST", body: "{}" });
  const info = await res.json();
  if (res.ok && info.service_pk) {
    if (!$("spk").value) {
      $("spk").value = info.service_pk;
      $("net").value = info.network;
    }
  }
} catch {}
