#!/usr/bin/env node
// rubric-harness-attest 0.2 - anchored evidence that your agent harness ran.
// spool: append one hashed event per tool call. Never blocks, never fails the agent.
// flush: one attestation per session. Hashes only. Code never leaves the machine.
// escrow: encrypt the session file locally and store the ciphertext with Rubric.
//         Rubric never receives the plaintext or the key.
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const HOME = path.join(os.homedir(), ".rubric");
const SPOOL = path.join(HOME, "spool");
const SESSIONS = path.join(HOME, "sessions");
const CONFIG = path.join(HOME, "config.json");
const EVIDENCE_KEY = path.join(HOME, "evidence-key.json");
const PAYLOAD_KEYS = path.join(HOME, "payload-keys.jsonl");
const ESCROWS = path.join(HOME, "escrows.jsonl");
const DEFAULT_ENDPOINT = "https://rubric-protocol.com/verify/v1/tiered-attest";
const DEFAULT_EVIDENCE_ENDPOINT = "https://rubric-protocol.com/v1/evidence";

function jcs(v) {
  if (v === null || v === undefined) return "null";
  if (typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  const k = Object.keys(v).filter(x => v[x] !== undefined).sort();
  return "{" + k.map(x => JSON.stringify(x) + ":" + jcs(v[x])).join(",") + "}";
}
const h = s => "sha3-256:" + crypto.createHash("sha3-256").update(s).digest("hex");
const cfg = () => {
  let c = {};
  try { c = JSON.parse(fs.readFileSync(CONFIG, "utf8")); } catch {}
  return {
    apiKey: process.env.RUBRIC_API_KEY || c.apiKey || "",
    endpoint: process.env.RUBRIC_ENDPOINT || c.endpoint || DEFAULT_ENDPOINT,
    evidenceEndpoint: process.env.RUBRIC_EVIDENCE_ENDPOINT || c.evidenceEndpoint || DEFAULT_EVIDENCE_ENDPOINT,
    retainContent: !!c.retainContent,
  };
};

// ---- evidence crypto --------------------------------------------------------
// X25519 keys are stored as raw 32-byte values, not DER, so the key file stays
// readable and portable. node:crypto only imports DER, so the fixed ASN.1
// prefixes below turn raw bytes back into a KeyObject. Both prefixes are fully
// determined by the algorithm OID and never vary for X25519.
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const HKDF_INFO = Buffer.from("rubric-evidence-v1", "utf8");
const GCM_AAD = Buffer.from("rubric-evidence/1", "utf8");

const rawPub = k => k.export({ type: "spki", format: "der" }).subarray(SPKI_PREFIX.length);
const rawPriv = k => k.export({ type: "pkcs8", format: "der" }).subarray(PKCS8_PREFIX.length);
const pubFromRaw = b => crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, b]), format: "der", type: "spki" });
const privFromRaw = b => crypto.createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, b]), format: "der", type: "pkcs8" });

// Salt binds the derived key to both public keys, so an envelope resealed to a
// different recipient cannot reuse a derived key. Wrong recipient key therefore
// fails at the GCM tag rather than producing plausible bytes.
function deriveKey(ephPubRaw, userPubRaw, shared) {
  return Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.concat([ephPubRaw, userPubRaw]), HKDF_INFO, 32));
}

export function seal(userPubRaw, plaintext) {
  const eph = crypto.generateKeyPairSync("x25519");
  const ephPubRaw = rawPub(eph.publicKey);
  const shared = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: pubFromRaw(userPubRaw) });
  const key = deriveKey(ephPubRaw, userPubRaw, shared);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  c.setAAD(GCM_AAD);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return {
    v: 1,
    eph: ephPubRaw.toString("base64"),
    iv: iv.toString("base64"),
    tag: c.getAuthTag().toString("base64"),
    ct: ct.toString("base64"),
  };
}

export function open(userPrivRaw, env) {
  if (!env || env.v !== 1) throw new Error("unsupported envelope version");
  const priv = privFromRaw(userPrivRaw);
  const userPubRaw = rawPub(crypto.createPublicKey(priv));
  const ephPubRaw = Buffer.from(String(env.eph), "base64");
  const shared = crypto.diffieHellman({ privateKey: priv, publicKey: pubFromRaw(ephPubRaw) });
  const key = deriveKey(ephPubRaw, userPubRaw, shared);
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(String(env.iv), "base64"));
  d.setAAD(GCM_AAD);
  d.setAuthTag(Buffer.from(String(env.tag), "base64"));
  return Buffer.concat([d.update(Buffer.from(String(env.ct), "base64")), d.final()]);
}

export const cipherHashOf = env => h(jcs(env));

export function loadEvidenceKey() {
  const k = JSON.parse(fs.readFileSync(EVIDENCE_KEY, "utf8"));
  return { publicKey: Buffer.from(k.publicKey, "base64"), privateKey: Buffer.from(k.privateKey, "base64") };
}

// Never overwrite an existing key: the ciphertext already stored with Rubric is
// only openable by this key, and Rubric holds no copy to fall back on.
function ensureEvidenceKey() {
  if (fs.existsSync(EVIDENCE_KEY)) return JSON.parse(fs.readFileSync(EVIDENCE_KEY, "utf8"));
  const kp = crypto.generateKeyPairSync("x25519");
  const rec = {
    v: 1, alg: "X25519",
    publicKey: rawPub(kp.publicKey).toString("base64"),
    privateKey: rawPriv(kp.privateKey).toString("base64"),
    createdAt: new Date().toISOString(),
  };
  fs.mkdirSync(HOME, { recursive: true });
  fs.writeFileSync(EVIDENCE_KEY, JSON.stringify(rec, null, 2), { mode: 0o600 });
  return rec;
}

// The exact object submitted to /v1/tiered-attest. escrow rebuilds it from the
// decrypted session to open the attestation's commitment, so the two callers
// must produce identical bytes -- hence one definition.
function sessionData(session, events) {
  const tools = {};
  for (const e of events) tools[e.tool] = (tools[e.tool] || 0) + 1;
  return {
    spec: "rubric-harness-attest/0.1",
    session, eventCount: events.length, eventsHash: h(jcs(events)),
    firstTs: events[0].ts, lastTs: events[events.length - 1].ts, tools,
    note: "eventsHash commits to the local session file. Only hashes were transmitted.",
  };
}

async function readStdin() {
  let s = ""; for await (const c of process.stdin) s += c; return s;
}

async function spool() {
  try {
    const raw = await readStdin();
    let j = {}; try { j = JSON.parse(raw); } catch {}
    const session = String(j.session_id || "unknown").replace(/[^a-zA-Z0-9-]/g, "").slice(0, 64) || "unknown";
    const ev = {
      ts: new Date().toISOString(),
      tool: String(j.tool_name || "unknown").slice(0, 128),
      argsHash: h(jcs(j.tool_input ?? null)),
      resultHash: h(jcs(j.tool_response ?? null)),
      cwdHash: h(String(j.cwd || process.cwd())),
    };
    // Content mode: keep the letter, not just the seal. Off by default; some
    // users want plaintext to never persist anywhere. When on, escrow retains
    // recoverable evidence rather than a manifest of fingerprints. Per-field
    // cap keeps one giant tool output from blowing the 2MB envelope.
    try {
      if (cfg().retainContent) {
        const cap = (v) => { const t = jcs(v ?? null); return t.length > 65536 ? { truncated: true, bytes: t.length, head: t.slice(0, 65536) } : (v ?? null); };
        ev.args = cap(j.tool_input);
        ev.result = cap(j.tool_response);
      }
    } catch (e) { console.error("[rubric-attest] content retention failed (hashes still committed): " + (e?.message || e)); }
    fs.mkdirSync(SPOOL, { recursive: true });
    fs.appendFileSync(path.join(SPOOL, session + ".jsonl"), JSON.stringify(ev) + "\n");
  } catch { /* evidence is best-effort; the agent always comes first */ }
  process.exit(0);
}

async function flush() {
  const { apiKey, endpoint } = cfg();
  if (!apiKey) { console.error("[rubric-attest] no API key. Run: node attest.mjs init <key>  (free key: https://rubric-protocol.com)"); process.exit(0); }
  let files = [];
  try { files = fs.readdirSync(SPOOL).filter(f => f.endsWith(".jsonl")); } catch {}
  for (const f of files) {
    const fp = path.join(SPOOL, f);
    const session = f.replace(/\.jsonl$/, "");
    let events = [];
    try {
      events = fs.readFileSync(fp, "utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
    } catch { continue; }
    if (!events.length) { try { fs.unlinkSync(fp); } catch {} continue; }
    const eventsHash = h(jcs(events));
    const data = sessionData(session, events);
    try {
      const r = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-api-key": apiKey },
        body: JSON.stringify({ agentId: "harness-attest", sourceId: "harness-session-" + session + "-" + eventsHash.slice(9, 17), decision: "harness-session", data }),
      });
      const j = await r.json().catch(() => null);
      if (!j?.attestationId) { console.error("[rubric-attest] attest failed status=" + r.status + "; keeping spool for retry"); continue; }
      fs.mkdirSync(SESSIONS, { recursive: true });
      fs.renameSync(fp, path.join(SESSIONS, f));
      // payloadKey opens the commitment on the anchored attestation and Rubric
      // does not retain it. It lives in HOME at 0600, never in the repo-local
      // .rubric/, which routinely gets committed.
      if (j.payloadKey) {
        try {
          fs.appendFileSync(PAYLOAD_KEYS, JSON.stringify({
            session, attestationId: j.attestationId,
            payloadKey: j.payloadKey, payloadCommitment: j.payloadCommitment ?? null,
            at: new Date().toISOString(),
          }) + "\n", { mode: 0o600 });
        } catch (e) { console.error("[rubric-attest] could not store payloadKey: " + (e?.message || e)); }
      }
      const rec = {
        session, attestationId: j.attestationId,
        verifyUrl: "https://rubric-protocol.com/v1/verify/" + j.attestationId,
        eventsHash, eventCount: events.length,
        payloadCommitment: j.payloadCommitment ?? null,
        at: new Date().toISOString(),
      };
      let out = path.join(process.cwd(), ".rubric");
      try { fs.mkdirSync(out, { recursive: true }); } catch { out = HOME; }
      fs.appendFileSync(path.join(out, "attestations.jsonl"), JSON.stringify(rec) + "\n");
      console.error("[rubric-attest] anchored session=" + session + " events=" + events.length + " verify=" + rec.verifyUrl);
    } catch (e) {
      console.error("[rubric-attest] network error, keeping spool: " + (e?.message || e));
    }
  }
  process.exit(0);
}

// Records written by flush, from the repo-local .rubric first then HOME.
function attestationRecords() {
  const out = [];
  for (const fp of [path.join(process.cwd(), ".rubric", "attestations.jsonl"), path.join(HOME, "attestations.jsonl")]) {
    try {
      for (const l of fs.readFileSync(fp, "utf8").split("\n")) {
        if (l) { try { out.push(JSON.parse(l)); } catch {} }
      }
    } catch {}
  }
  return out;
}

function payloadKeyFor(session) {
  try {
    for (const l of fs.readFileSync(PAYLOAD_KEYS, "utf8").split("\n").reverse()) {
      if (!l) continue;
      try { const r = JSON.parse(l); if (r.session === session) return r; } catch {}
    }
  } catch {}
  return null;
}

function escrowedSessions() {
  const seen = new Set();
  try {
    for (const l of fs.readFileSync(ESCROWS, "utf8").split("\n")) {
      if (l) { try { seen.add(JSON.parse(l).session); } catch {} }
    }
  } catch {}
  return seen;
}

async function escrow(years) {
  const { apiKey, evidenceEndpoint } = cfg();
  if (!apiKey) { console.error("[rubric-attest] no API key. Run: node attest.mjs init <key>"); process.exit(0); }
  let key = null;
  try { key = loadEvidenceKey(); } catch {}
  if (!key) { console.error("[rubric-attest] no evidence key. Run: node attest.mjs init <key>"); process.exit(0); }
  const retentionYears = [1, 7, 10].includes(years) ? years : 1;

  const done = escrowedSessions();
  let sent = 0;
  for (const rec of attestationRecords()) {
    if (!rec.session || !rec.attestationId || done.has(rec.session)) continue;
    const fp = path.join(SESSIONS, rec.session + ".jsonl");
    if (!fs.existsSync(fp)) continue;
    done.add(rec.session);

    // The session file is encrypted here, on this machine. What crosses the
    // wire is ciphertext; the key never leaves.
    // The opening proves this evidence belongs to that attestation. salt is
    // one-way in payloadKey, so it can be disclosed; the key never is.
    const pk = payloadKeyFor(rec.session);
    if (!pk) {
      console.error("[rubric-attest] no payloadKey for session=" + rec.session + "; cannot bind it to the attestation, skipping");
      continue;
    }
    const raw = fs.readFileSync(fp);
    const events = raw.toString("utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
    const opening = {
      salt: crypto.createHash("sha256").update(pk.payloadKey + ":rubric-commit-v1").digest("hex"),
      data: sessionData(rec.session, events),
    };
    const envelope = seal(key.publicKey, raw);
    const cipherHash = cipherHashOf(envelope);
    try {
      const body = JSON.stringify({ envelope, eventsHash: rec.eventsHash, attestationId: rec.attestationId, retentionYears, cipherHash, opening });
      let r = null, j = null;
      // A tiered attestation carries no commitment until the tier-1 flush lands,
      // so the binding is uncheckable for ~30s after flush. Wait it out rather
      // than drop the evidence.
      const deadline = Date.now() + 120_000;
      for (;;) {
        r = await fetch(evidenceEndpoint + "/" + rec.session, {
          method: "PUT",
          headers: { "Content-Type": "application/json", "x-api-key": apiKey },
          body,
        });
        j = await r.json().catch(() => null);
        if (r.status !== 503 || !j?.retryable || Date.now() >= deadline) break;
        console.error("[rubric-attest] waiting for the attestation to flush before binding session=" + rec.session);
        await new Promise(z => setTimeout(z, Math.min(15_000, j.retryAfterMs ?? 15_000)));
      }
      if (r.status === 409) { console.error("[rubric-attest] already escrowed session=" + rec.session); continue; }
      if (!r.ok) { console.error("[rubric-attest] escrow failed session=" + rec.session + " status=" + r.status + " " + (j?.error ?? "")); continue; }
      // The server echoes the hash it computed over the stored bytes. If that
      // disagrees with ours, what it stored is not what we sealed.
      if (j?.cipherHash !== cipherHash) {
        console.error("[rubric-attest] CIPHERHASH MISMATCH session=" + rec.session + " sent=" + cipherHash + " echoed=" + (j?.cipherHash ?? "none"));
        continue;
      }
      fs.appendFileSync(ESCROWS, JSON.stringify({
        session: rec.session, cipherHash, attestationId: rec.attestationId,
        escrowAttestationId: j.escrowAttestationId ?? null,
        retentionYears, expiresAt: j.expiresAt ?? null, at: new Date().toISOString(),
      }) + "\n");
      sent++;
      console.error("[rubric-attest] escrowed session=" + rec.session + " retention=" + retentionYears + "y expires=" + (j.expiresAt ?? "?") +
        (j.escrowAttestationId ? " verify=https://rubric-protocol.com/v1/verify/" + j.escrowAttestationId : " (anchor pending)"));
    } catch (e) {
      console.error("[rubric-attest] escrow network error session=" + rec.session + ": " + (e?.message || e));
    }
  }
  if (!sent) console.error("[rubric-attest] nothing new to escrow");
  process.exit(0);
}

async function restore(session) {
  const { apiKey, evidenceEndpoint } = cfg();
  if (!session) { console.error("usage: attest.mjs restore <sessionId>"); process.exit(1); }
  let key = null;
  try { key = loadEvidenceKey(); } catch {}
  if (!key) { console.error("[rubric-attest] no evidence key; the evidence cannot be opened without it"); process.exit(1); }
  const r = await fetch(evidenceEndpoint + "/" + session, { headers: { "x-api-key": apiKey } });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j?.envelope) {
    console.error("[rubric-attest] restore failed session=" + session + " status=" + r.status + " " + (j?.note ?? j?.error ?? ""));
    process.exit(1);
  }
  // Check the bytes before trusting them: the envelope must rehash to the
  // cipherHash the escrow anchored.
  const ch = cipherHashOf(j.envelope);
  if (j.cipherHash && ch !== j.cipherHash) {
    console.error("[rubric-attest] CIPHERHASH MISMATCH — stored bytes differ from the anchored hash. Refusing to decrypt.");
    process.exit(1);
  }
  let plain;
  try { plain = open(key.privateKey, j.envelope); }
  catch { console.error("[rubric-attest] decryption failed — this evidence was sealed to a different key"); process.exit(1); }

  const dir = path.join(HOME, "restored");
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, session + ".jsonl");
  fs.writeFileSync(out, plain, { mode: 0o600 });

  const events = plain.toString("utf8").split("\n").filter(Boolean).map(l => JSON.parse(l));
  const eventsHash = h(jcs(events));
  console.error("[rubric-attest] restored session=" + session + " events=" + events.length + " -> " + out);
  console.error("[rubric-attest] eventsHash(recomputed)=" + eventsHash);
  console.error("[rubric-attest] eventsHash(escrowed)  =" + (j.eventsHash ?? "?"));
  console.error("[rubric-attest] " + (eventsHash === j.eventsHash ? "MATCH — the decrypted evidence is the session that was attested." : "MISMATCH"));
  process.exit(eventsHash === j.eventsHash ? 0 : 1);
}

function init(key, retainContent) {
  fs.mkdirSync(HOME, { recursive: true });
  fs.writeFileSync(CONFIG, JSON.stringify({ apiKey: key, endpoint: DEFAULT_ENDPOINT, evidenceEndpoint: DEFAULT_EVIDENCE_ENDPOINT, retainContent: !!retainContent }, null, 2), { mode: 0o600 });
  if (retainContent) console.error("[rubric-attest] content retention ON: tool inputs and outputs are stored locally and included in escrow. Hash-only mode is the default; this was your explicit choice.");
  const existed = fs.existsSync(EVIDENCE_KEY);
  const k = ensureEvidenceKey();
  console.error("[rubric-attest] configured. Free tier: 1,000 sessions/month.");
  console.error("");
  console.error("  ##############################################################");
  console.error("  #  EVIDENCE KEY " + (existed ? "ALREADY PRESENT" : "GENERATED") + " AT " + EVIDENCE_KEY);
  console.error("  #  fingerprint " + h(k.publicKey).slice(10, 26));
  console.error("  #");
  console.error("  #  BACK THIS FILE UP NOW. It is the only key that can open");
  console.error("  #  escrowed evidence. Rubric stores ciphertext only and holds");
  console.error("  #  no copy of this key. If you lose it, your evidence is gone");
  console.error("  #  permanently and Rubric CANNOT recover it.");
  console.error("  ##############################################################");
  console.error("");
}

const mode = process.argv[2];
// Only dispatch when run as a CLI, so the crypto above can be imported by tests.
if (process.argv[1] && path.basename(process.argv[1]) === "attest.mjs") {
  if (mode === "spool") spool();
  else if (mode === "flush") flush();
  else if (mode === "escrow") escrow(Number(process.argv[3] ?? 1));
  else if (mode === "restore") restore(process.argv[3]);
  else if (mode === "init") init(process.argv[3] || "", process.argv.includes("--retain-content"));
  else console.error("usage: attest.mjs init <apiKey> [--retain-content] | spool | flush | escrow [years] | restore <sessionId>");
}
