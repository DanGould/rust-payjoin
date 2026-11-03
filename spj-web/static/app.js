// The stage: a payer's phone, Bob's phone, and the transaction they build.
//
// Every step a wallet takes arrives as an event from the server. Events are
// played one at a time, so a message can fly to the directory before the
// next one lands. Events from before this page loaded are applied without
// motion, so a reload in the middle of a take shows the same state.

const $ = (sel, root = document) => root.querySelector(sel);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const fmt = (n) => Math.abs(n).toLocaleString("en-US");
const sats = (n) => `${fmt(n)} sats`;
const shortMid = (s, a = 10, b = 6) =>
  s && s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : (s ?? "");

const PEOPLE = {
  carol: { name: "Carol", kind: "Payjoin wallet" },
  alice: { name: "Alice", kind: "Silent payment wallet" },
  exchange: { name: "Exchange", kind: "Back office" },
  bob: { name: "Bob", kind: "Silent payment wallet" },
};

const payerState = () => ({
  screen: "home",
  balance: 0,
  activity: [],
  steps: [],
  status: "",
  done: null,
  contacts: [],
  scan: null,
});

const state = {
  payer: "carol",
  amount: 40000,
  replyBy: 60,
  height: 0,
  explorer: "",
  bob: {
    screen: "home",
    balance: 0,
    activity: [],
    steps: [],
    request: null,
    contact: null,
    awake: true,
    status: "",
  },
  payers: { carol: payerState(), alice: payerState(), exchange: payerState() },
  uri: null,
  tx: null,
};
let moving = false;
// What the recorder waits on: every event kind the page has played, and how
// many times.
window.__seen = new Set();
window.__count = {};

// ---------------------------------------------------------------------------
// Server

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error || `${path} failed`);
  return json;
}

function toast(text) {
  const el = $("#toast");
  el.textContent = text;
  el.classList.add("show");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => el.classList.remove("show"), 3200);
}

// ---------------------------------------------------------------------------
// Events

const queue = [];
let playing = false;
let lastSeq = 0;

function receive(event) {
  if (event.seq <= lastSeq) return;
  lastSeq = event.seq;
  queue.push(event);
  if (!playing) play();
}

async function play() {
  playing = true;
  while (queue.length) {
    const event = queue.shift();
    try {
      await apply(event);
    } catch (e) {
      console.error(event, e);
    }
    window.__seen.add(event.kind);
    window.__count[event.kind] = (window.__count[event.kind] ?? 0) + 1;
    render();
  }
  playing = false;
}

const payerName = (who) => PEOPLE[who]?.name ?? who;

// The payer named in Bob's events is whoever is on stage: Bob's wallet never
// learns who paid it.
function withOwners(tx) {
  if (!tx) return tx;
  const fix = (side) =>
    side.map((io) => ({
      ...io,
      owner: io.owner === "payer" ? state.payer : io.owner,
    }));
  return { inputs: fix(tx.inputs), outputs: fix(tx.outputs) };
}

function setTx(tx, status, cls = "") {
  const old = state.tx;
  state.tx = {
    ...withOwners(tx),
    status,
    cls,
    checked: old?.checked ?? false,
    found: old?.found ?? false,
    rederived: old?.rederived ?? false,
    // The key Bob's output had in the payer's transaction, before Bob worked
    // it out again.
    firstKey: old?.firstKey ?? bobKey(tx),
  };
}

function bobKey(tx) {
  return tx?.outputs?.find((o) => o.owner === "bob" && o.silent)?.key ?? null;
}

async function apply({ kind, data }) {
  const [who, step] = kind.split(".");
  const p = state.payers[who];
  switch (kind) {
    case "stage":
      if (data.payer) state.payer = data.payer;
      if (data.amount) state.amount = data.amount;
      if (data.reply_by) state.replyBy = data.reply_by;
      if (data.clear) {
        state.tx = null;
        state.uri = null;
      }
      return;
    case "chain.block":
      state.height = data.height;
      return;
    case "bob.ready":
      state.bob.balance = data.balance;
      return;
    case "bob.request":
      Object.assign(state.bob, { screen: "request", request: data, steps: [] });
      state.uri = { kind: "one_time", ...data };
      state.tx = null;
      return;
    case "bob.contact":
      Object.assign(state.bob, { screen: "contact", contact: data, steps: [] });
      state.uri = { kind: "contact", ...data };
      state.tx = null;
      return;
    case "bob.awake":
      state.bob.awake = data.awake;
      return;
    case "bob.original":
      await pickUp("#bob");
      Object.assign(state.bob, {
        screen: "incoming",
        steps: ["A transaction is waiting in my mailbox"],
        status: "Answering",
      });
      return;
    case "bob.found":
      state.bob.steps.push(
        data.silent
          ? "Found my output in it by scanning"
          : "It pays my address",
      );
      if (state.tx) state.tx.found = data.silent;
      return;
    case "bob.coin": {
      const steps = state.bob.steps;
      steps.push(`Added a coin of ${sats(data.coin)}`);
      if (data.rederived)
        steps.push("Worked out my output again, over all inputs");
      if (data.proofs) steps.push("Attached a proof the payer can check");
      setTx(data.tx, "Bob adds a coin");
      if (data.rederived) state.tx.rederived = true;
      return;
    }
    case "bob.proposal_sent":
      state.bob.steps.push("Sent it back");
      state.bob.status = "Waiting for the payer";
      setTx(data.tx, `Back to ${payerName(state.payer)}`);
      render();
      await post("#bob", "With Bob's coin");
      return;
    case "bob.declined":
      state.bob.steps.push(
        data.already_paid
          ? "It already went out on chain. Nothing to add"
          : `Declined: ${data.reason}`,
      );
      state.bob.status = data.already_paid ? "Scanning the chain" : "";
      state.bob.alreadyPaid = data.already_paid;
      return;
    case "bob.received": {
      const tags = data.by_scan
        ? data.payjoin
          ? ["spj", "Silent Payjoin"]
          : ["sp", "Silent payment"]
        : ["pj", "Payjoin"];
      // A message read after its transaction went out: the steps stay up,
      // ending with where the money was found.
      if (state.bob.screen === "incoming" && state.bob.alreadyPaid) {
        state.bob.steps.push(
          `Found it in a block by scanning, +${sats(data.amount)}`,
        );
        state.bob.status = "";
        state.bob.alreadyPaid = false;
      } else {
        state.bob.screen = "home";
      }
      state.bob.activity.unshift({
        what: "Received",
        amount: data.amount,
        tag: tags,
        sub: data.by_scan ? "Found by scanning" : "Paid to the URI's address",
        fresh: moving,
      });
      state.bob.balance = data.balance;
      return;
    }
  }
  if (!p) return;
  switch (step) {
    case "ready":
      p.balance = data.balance;
      return;
    case "scanned":
      return;
    case "paying":
      Object.assign(p, {
        screen: "progress",
        steps: [],
        status: "Paying Bob",
        amount: data.amount,
      });
      return;
    case "original_sent": {
      p.screen = "progress";
      p.steps.push(
        who === "carol"
          ? "Signed a transaction to the address"
          : "Worked out Bob's output and signed",
      );
      p.status = "Waiting for Bob";
      state.uri = null;
      setTx(data.tx, `${payerName(who)}'s transaction`);
      state.tx.checked = false;
      state.tx.found = false;
      state.tx.rederived = false;
      state.tx.firstKey = bobKey(state.tx);
      render();
      await post("#payer", "Transaction");
      if (state.tx) state.tx.status = "In Bob's mailbox";
      return;
    }
    case "proposal":
      await pickUp("#payer");
      p.steps.push("Bob added a coin");
      p.status = who === "carol" ? "Signing" : "Checking Bob's proof";
      setTx(data.tx, "Checking");
      return;
    case "checked":
      p.steps.push(
        `Checked ${data.proofs === 1 ? "the proof" : `${data.proofs} proofs`} and found Bob's output`,
      );
      p.status = "Signing";
      setTx(data.tx, "Checked");
      state.tx.checked = true;
      return;
    case "fallback":
    case "rejected":
      p.steps.push(
        step === "fallback"
          ? "No answer from Bob in time"
          : `Rejected the proposal: ${data.reason}`,
      );
      p.status = "Sending the transaction as it is";
      if (state.tx) {
        state.tx.status = "Sent as it is";
        state.tx.cls = "fallback";
      }
      p.fallback = true;
      return;
    case "broadcast":
      p.steps.push(
        data.payjoin ? "Signed and broadcast" : "Sent the transaction as it is",
      );
      p.status = "Broadcasting";
      setTx(data.tx, "In mempool", "mempool");
      if (!data.payjoin) state.tx.cls = "mempool";
      render();
      await fly("#payer", "#network", data.payjoin ? "Payjoin" : "Transaction");
      return;
    case "confirmed": {
      const silent = who !== "carol";
      const tag = data.payjoin
        ? silent
          ? ["spj", "Silent Payjoin"]
          : ["pj", "Payjoin"]
        : ["sp", "Silent payment"];
      if (state.tx) {
        state.tx.status = `Block ${data.height}`;
        state.tx.cls = "confirmed";
      }
      state.height = Math.max(state.height, data.height);
      p.balance = data.balance;
      p.activity.unshift({
        what: who === "exchange" ? "Payout to Bob" : "Paid Bob",
        amount: -data.amount,
        tag,
        sub: `Block ${data.height}`,
        fresh: moving,
      });
      p.done = { ...data, tag };
      p.screen = who === "exchange" ? "home" : "done";
      p.fallback = false;
      return;
    }
    case "contact_saved":
      p.contacts = [data];
      if (who === "exchange") p.screen = "home";
      return;
    case "error":
      p.steps.push(`Error: ${data.error}`);
      toast(data.error);
      return;
  }
}

// ---------------------------------------------------------------------------
// Flights between the phones, through the directory

function center(sel) {
  const r = $(sel).getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
}

function flyer(label, sealed) {
  const el = document.createElement("div");
  el.className = `flyer ${sealed ? "sealed" : ""}`;
  el.textContent = label;
  $("#flyers").appendChild(el);
  return el;
}

function place(el, { x, y }) {
  el.style.transform = `translate(${x - el.offsetWidth / 2}px, ${y - el.offsetHeight / 2}px)`;
}

// A message posted to a mailbox waits there, on screen, until the other
// side reads it.
let parked = null;

async function post(from, label) {
  if (!moving) return;
  const el = flyer(label, true);
  el.style.transition = "none";
  place(el, center(from));
  el.offsetHeight;
  el.style.transition = "";
  // Just below the mailbox's name, so the label stays readable.
  const r = $("#directory").getBoundingClientRect();
  place(el, { x: r.left + r.width / 2, y: r.bottom + el.offsetHeight / 2 + 6 });
  $("#directory").classList.add("lit");
  await sleep(850);
  el.classList.add("parked");
  parked = el;
}

async function pickUp(to) {
  const el = parked;
  parked = null;
  $("#directory").classList.remove("lit");
  if (!moving || !el) return el?.remove();
  el.classList.remove("parked");
  place(el, center(to));
  await sleep(800);
  el.style.opacity = "0";
  await sleep(300);
  el.remove();
}

/** A message straight to `to`, such as a transaction to the network. */
async function fly(from, to, label) {
  if (!moving) return;
  const el = flyer(label, false);
  el.style.transition = "none";
  place(el, center(from));
  el.offsetHeight;
  el.style.transition = "";
  place(el, center(to));
  $(to).classList.add("lit");
  await sleep(800);
  el.style.opacity = "0";
  await sleep(300);
  el.remove();
}

// ---------------------------------------------------------------------------
// Rendering

const lastHtml = {};
const lastScreen = {};

function statusbar(who) {
  return `<div class="statusbar"><span>9:41</span><span class="net">regtest</span></div>`;
}

function who(name) {
  const p = PEOPLE[name];
  return `<div class="who"><div class="avatar">${p.name[0]}</div><div><div class="who-name">${p.name}</div><div class="who-kind">${p.kind}</div></div></div>`;
}

function balance(sat) {
  return `<div class="balance-label">Balance</div><div class="balance">${fmt(sat)}<span class="unit">sats</span></div>`;
}

const tagHtml = ([cls, text]) => `<span class="tag ${cls}">${text}</span>`;

function activity(rows, empty = "Nothing yet") {
  if (!rows.length) return `<div class="empty">${empty}</div>`;
  return `<ul class="list">${rows
    .slice(0, 4)
    .map(
      (r) => `<li class="${r.fresh ? "fresh" : ""}">
    <span class="what">${r.what}${r.tag ? tagHtml(r.tag) : ""}</span>
    <span class="amt ${r.amount > 0 ? "in" : ""}">${r.amount > 0 ? "+" : "−"}${fmt(r.amount)}</span>
    ${r.sub ? `<span class="sub">${r.sub}</span>` : ""}</li>`,
    )
    .join("")}</ul>`;
}

// A QR finder: four corners and a scan line.
const SCAN_ICON = `<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M4 9V5a1 1 0 0 1 1-1h4M15 4h4a1 1 0 0 1 1 1v4M20 15v4a1 1 0 0 1-1 1h-4M9 20H5a1 1 0 0 1-1-1v-4"/><path d="M7 12h10"/></svg>`;

function contactCard(c) {
  if (!c) return "";
  // A contact without reusable payjoin offers to scan the contact's
  // contact URI, which has it.
  const note = c.note
    ? `<div class="note"><span>${esc(c.note[0].toUpperCase() + c.note.slice(1))}</span><button class="note-scan" type="button" aria-label="Scan ${esc(c.name)}'s contact URI">${SCAN_ICON}</button></div>`
    : '<div class="c-ok">Silent payments and reusable payjoin</div>';
  return `<div class="contact"><div class="c-head"><span class="avatar">B</span>${esc(c.name)}</div>
    <div class="c-sp">${esc(shortMid(c.sp, 18, 8))}</div>${note}</div>`;
}

function steps(list) {
  return `<ul class="steps">${list.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`;
}

function statusLine(text) {
  return text
    ? `<div class="status-line"><span class="spinner"></span><span>${esc(text)}</span></div>`
    : "";
}

function uriParts(uri) {
  const [, body = "", query = ""] =
    uri.match(/^bitcoin:([^?]*)\??(.*)$/i) ?? [];
  const params = Object.fromEntries(
    query
      .split("&")
      .filter(Boolean)
      .map((kv) => {
        const i = kv.indexOf("=");
        return [kv.slice(0, i), kv.slice(i + 1)];
      }),
  );
  return {
    address: body,
    amount: params.amount,
    sp: params.sp,
    pj: params.pj ?? params.pjv2,
    pjKey: params.pj ? "pj" : "pjv2",
  };
}

function miniUri(uri) {
  const p = uriParts(uri);
  const pieces = [];
  pieces.push(`bitcoin:<span class="p-addr">${esc(p.address)}</span>`);
  return `<div class="uri-mini">${pieces.join("")}?…&amp;<span class="p-sp">sp=${esc(shortMid(p.sp, 12, 4))}</span>&amp;<span class="p-pj">${p.pjKey}=${esc(shortMid(p.pj.toLowerCase(), 16, 4))}</span></div>`;
}

function bobView() {
  const b = state.bob;
  switch (b.screen) {
    case "request": {
      const r = b.request;
      return `<div class="view">
        <div class="head"><h2>Receive</h2></div>
        <div class="qr">${r.qr ?? ""}</div>
        <div class="request-amount">${sats(r.amount)}</div>
        <div class="request-kind">One-time URI</div>
        ${miniUri(r.uri)}
        ${statusLine("Waiting to be paid")}
      </div>`;
    }
    case "contact": {
      const c = b.contact;
      return `<div class="view">
        <div class="head"><h2>My contact</h2></div>
        <div class="qr">${c.qr ?? ""}</div>
        <div class="request-kind" style="margin-top:10px">Reusable. Share it with anyone you transact with again and again</div>
        ${miniUri(c.uri)}
        <div class="spacer"></div>
        ${activity(b.activity)}
      </div>`;
    }
    case "incoming":
      return `<div class="view">
        <div class="head"><h2>Receiving</h2></div>
        ${statusLine(b.status)}
        ${steps(b.steps)}
      </div>`;
    default:
      return `<div class="view">
        ${who("bob")}
        ${balance(b.balance)}
        <div class="actions">
          <button class="btn primary" data-act="request" type="button">Receive</button>
          <button class="btn soft" data-act="share-contact" type="button">My contact</button>
        </div>
        <div class="section-title">Activity</div>
        ${activity(b.activity)}
      </div>`;
  }
}

// A URI carries no name, so the payer names the contact before saving it.
function saveContact(p) {
  if (p.contacts[0])
    return `<div class="section-title">Saved to contacts</div>${contactCard(p.contacts[0])}`;
  return `<div class="section-title">Save to contacts</div>
    <div class="save-contact">
      <input class="field" id="contact-name" placeholder="Name" autocomplete="off" />
      <button class="btn primary" data-act="save-contact" type="button">Save</button>
    </div>`;
}

// The exchange is a desktop back office in a browser window, not a phone.
function exchangeView(p) {
  const contact = p.contacts[0];
  let main;
  if (p.screen === "scan") {
    main = `<div class="panel wide">
      <div class="section-title">Add a contact</div>
      <label class="field-label">Contact URI</label>
      <div class="field mono">${esc(shortMid(p.scan.uri.toLowerCase(), 34, 10))}</div>
      <div class="status-line"><span class="spinner"></span><span>Saving</span></div>
    </div>`;
  } else if (p.screen === "progress") {
    main = `<div class="panel wide">
      <div class="section-title">Payout to Bob, ${sats(state.amount)}</div>
      ${statusLine(p.status)}
      ${steps(p.steps)}
    </div>`;
  } else {
    const act = contact
      ? `<button class="btn primary" data-act="pay-bob" type="button">Pay Bob ${fmt(state.amount)} sats</button>`
      : '<button class="btn primary" data-act="scan" type="button">Add contact</button>';
    main = `<div class="panel">
        <div class="section-title">Saved contact</div>
        ${contact ? contactCard(contact) : '<div class="empty">No contacts yet</div>'}
      </div>
      <div class="panel">
        <div class="section-title">Payouts</div>
        ${activity(p.activity)}
      </div>
      <div class="console-actions">${act}</div>`;
  }
  return `<div class="view console-view">
    <div class="console-head">${who("exchange")}<div class="console-balance">${balance(p.balance)}</div></div>
    <div class="console-body">${main}</div>
  </div>`;
}

function payerView(name) {
  const p = state.payers[name];
  if (name === "exchange") return exchangeView(p);
  const scanned = p.scan;
  switch (p.screen) {
    case "scan":
      return `<div class="view">
        <div class="head"><h2>Scan</h2></div>
        <div class="finder">${scanned?.qr ? `<div class="shot">${scanned.qr}</div>` : ""}<div class="scanline"></div></div>
        <div class="request-kind">Point the camera at Bob's code</div>
      </div>`;
    case "review": {
      const u = uriParts(scanned.uri);
      const amount = Math.round(Number(u.amount ?? 0) * 1e8);
      const silent = name !== "carol";
      return `<div class="view">
        <div class="head"><h2>Pay Bob</h2></div>
        <div class="pay-amount">${sats(amount)}</div>
        <div class="sees">
          ${
            silent
              ? `<div><span class="k">Silent payment</span><span class="v">${esc(shortMid(u.sp, 8, 4))}</span></div>`
              : `<div><span class="k">Address</span><span class="v">${esc(shortMid(u.address, 8, 4))}</span></div>`
          }
          <div><span class="k">Payjoin</span><span class="v">Yes</span></div>
          ${silent ? "" : '<div><span class="k">Silent payment</span><span class="v off">Not supported</span></div>'}
        </div>
        <button class="btn primary block" style="margin-top:16px" data-act="send" type="button">Send</button>
      </div>`;
    }
    case "progress":
      return `<div class="view">
        <div class="head"><h2>Paying Bob</h2></div>
        ${statusLine(p.status)}
        ${steps(p.steps)}
      </div>`;
    case "done": {
      const d = p.done;
      return `<div class="view done-view">
        <div class="seal">✓</div>
        <p class="done-title">Sent</p>
        <div class="done-sub">${sats(d.amount)} to Bob</div>
        <div class="done-tags">${tagHtml(d.tag)}</div>
        ${name === "alice" ? saveContact(p) : ""}
        <div class="spacer"></div>
        ${d.explorer ? `<a class="btn primary block" id="view-explorer" href="${esc(d.explorer)}">View in explorer</a>` : ""}
      </div>`;
    }
    default: {
      const contact = p.contacts[0];
      const act =
        name === "exchange"
          ? contact
            ? '<button class="btn primary" data-act="pay-bob" type="button">Pay Bob</button>'
            : '<button class="btn primary" data-act="scan" type="button">Add contact</button>'
          : '<button class="btn primary" data-act="scan" type="button">Scan to pay</button>';
      return `<div class="view">
        ${who(name)}
        ${balance(p.balance)}
        <div class="actions">${act}</div>
        ${contact ? `<div class="section-title">Contact</div>${contactCard(contact)}` : ""}
        <div class="section-title">${name === "exchange" ? "Payouts" : "Activity"}</div>
        ${activity(p.activity)}
      </div>`;
    }
  }
}

function browserbar() {
  return `<div class="browserbar"><span class="dots"><i></i><i></i><i></i></span><span class="url">backoffice.exchange.example/payouts</span></div>`;
}

function renderPhone(id, html, screenKey) {
  const root = $(`#${id}`);
  if (lastHtml[id] === html) return;
  const bar = screenKey.startsWith("exchange:") ? browserbar() : statusbar();
  root.innerHTML = bar + html;
  if (moving && lastScreen[id] !== screenKey)
    root.querySelector(".view")?.classList.add("enter");
  lastHtml[id] = html;
  lastScreen[id] = screenKey;
}

function renderUri() {
  const root = $("#uri");
  const u = state.uri;
  const html = u
    ? (() => {
        const p = uriParts(u.uri);
        const contact = u.kind === "contact";
        return `<div class="uri-card"><div class="label">${contact ? "Bob's contact URI" : "Bob's one-time URI"}</div><div class="uri-parts">
      <div class="part addr ${p.address ? "" : "dim"}"><span class="name">Address</span><span class="val">${p.address ? esc(shortMid(p.address, 18, 8)) : "none"}</span></div>
      <div class="part sp"><span class="name">sp=</span><span class="val">${esc(shortMid(p.sp, 22, 8))}</span></div>
      <div class="part pj"><span class="name">${p.pjKey}=</span><span class="val">${esc(shortMid(p.pj.toLowerCase(), 26, 6))}</span></div>
    </div></div>`;
      })()
    : "";
  if (root.dataset.html !== html) {
    root.innerHTML = html;
    root.dataset.html = html;
  }
}

function rowsHtml(list, side) {
  const t = state.tx;
  return list
    .map((io, i) => {
      const chips = [];
      if (side === "in" && io.proof)
        chips.push(t.checked ? ["ok", "proof checked"] : ["proof", "proof"]);
      if (side === "out" && io.silent) {
        chips.push(["sp", "silent payment"]);
        if (io.owner === "bob" && t.checked)
          chips.push(["ok", `= ${payerName(state.payer)}'s`]);
        else if (io.owner === "bob" && t.rederived)
          chips.push(["fresh", "worked out again"]);
        else if (io.owner === "bob" && t.found)
          chips.push(["fresh", "found by scanning"]);
      }
      if (side === "out" && !io.silent && io.owner === "bob")
        chips.push(["plain", "address"]);
      // Bob's output key, so a new derivation shows as a new key, and the
      // payer's own derivation as the same one.
      if (side === "out" && io.silent && io.owner === "bob" && io.key) {
        chips.unshift(["key", io.key]);
        if (t.firstKey && t.firstKey !== io.key && !t.checked)
          chips.unshift(["key was", t.firstKey]);
      }
      if (side === "out" && io.owner !== "bob") chips.push(["plain", "change"]);
      const key = `${side}-${io.owner}-${side === "out" ? (io.owner === "bob" ? "pay" : "change") : i}`;
      return `<div class="row ${io.owner}" data-key="${key}"><span class="bar-owner"></span><span class="owner">${payerName(io.owner)}</span>
      <span class="chips">${chips.map(([c, text]) => `<span class="chip ${c}">${esc(text)}</span>`).join("")}</span>
      <span class="value">${io.value == null ? "" : fmt(io.value)}</span></div>`;
    })
    .join("");
}

const lastValues = {};

function renderTx() {
  const root = $("#tx");
  const t = state.tx;
  if (!t) {
    root.innerHTML = "";
    root.dataset.html = "";
    return;
  }
  const html = `<div class="card">
    <div class="card-head"><span class="card-title">Transaction</span><span class="status ${t.cls}">${esc(t.status)}</span></div>
    <div class="rows-label">Inputs</div><div class="rows">${rowsHtml(t.inputs, "in")}</div>
    <div class="rows-label">Outputs</div><div class="rows">${rowsHtml(t.outputs, "out")}</div>
  </div>`;
  if (root.dataset.html === html) return;
  const hadCard = !!root.querySelector(".card");
  const before = new Set(
    [...root.querySelectorAll(".row")].map((r) => r.dataset.key),
  );
  root.innerHTML = html;
  root.dataset.html = html;
  if (hadCard) root.querySelector(".card").style.animation = "none";
  for (const row of root.querySelectorAll(".row")) {
    const key = row.dataset.key;
    const value = row.querySelector(".value").textContent;
    if (moving && hadCard && !before.has(key)) row.classList.add("enter");
    if (moving && lastValues[key] && lastValues[key] !== value)
      row.querySelector(".value").classList.add("changed");
    lastValues[key] = value;
  }
}

function render() {
  $("#height").textContent = state.height
    ? `Regtest, block ${state.height}`
    : "Regtest";
  const party = $("#payer-party");
  party.dataset.who = state.payer;
  document.body.dataset.payer = state.payer;
  renderPhone(
    "payer",
    payerView(state.payer),
    `${state.payer}:${state.payers[state.payer].screen}`,
  );
  renderPhone("bob", bobView(), state.bob.screen);
  $("#bob").classList.toggle("asleep", !state.bob.awake);
  renderUri();
  renderTx();
}

// ---------------------------------------------------------------------------
// Taps

document.addEventListener("click", async (ev) => {
  const el = ev.target.closest("[data-act]");
  if (!el) return;
  const act = el.dataset.act;
  const name = state.payer;
  const p = state.payers[name];
  try {
    if (act === "request") {
      el.disabled = true;
      await api("/api/bob/one-time", { amount: state.amount });
    }
    if (act === "share-contact") {
      el.disabled = true;
      await api("/api/bob/contact");
    }
    if (act === "scan") {
      if (!state.uri) {
        toast("Bob has nothing to scan yet");
        return;
      }
      p.scan = { ...state.uri };
      p.screen = "scan";
      render();
      await sleep(1600);
      if (p.scan.kind === "contact") {
        await api("/api/exchange/contact", { uri: p.scan.uri });
        p.screen = "home";
      } else {
        p.screen = "review";
      }
      render();
    }
    if (act === "send") {
      el.disabled = true;
      Object.assign(p, { screen: "progress", steps: [], status: "Preparing" });
      render();
      await api(`/api/${name}/pay`, { uri: p.scan.uri });
    }
    if (act === "save-contact") {
      const field = $("#contact-name");
      if (!field.value.trim()) {
        field.focus();
        return;
      }
      el.disabled = true;
      await api("/api/alice/save-contact", { name: field.value });
    }
    if (act === "pay-bob") {
      el.disabled = true;
      Object.assign(p, { screen: "progress", steps: [], status: "Preparing" });
      render();
      await api("/api/exchange/pay-contact", {
        amount: state.amount,
        reply_by: state.replyBy,
      });
    }
  } catch (e) {
    toast(e.message);
    el.disabled = false;
  }
});

// ---------------------------------------------------------------------------
// Start: replay what already happened without motion, then go live.

async function start() {
  const s = await fetch("/api/state").then((r) => r.json());
  state.height = s.height;
  state.explorer = s.explorer;
  render();
  const source = new EventSource("/api/events");
  source.onmessage = (msg) => receive(JSON.parse(msg.data));
  // History arrives first, in one burst; once it has been played, the page
  // goes live and later events move.
  await sleep(400);
  while (playing || queue.length) await sleep(50);
  moving = true;
  window.__ready = true;
}

start();
