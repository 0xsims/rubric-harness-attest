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
    endpoint: c.endpoint || DEFAULT_ENDPOINT,
    evidenceEndpoint: c.evidenceEndpoint || DEFAULT_EVIDENCE_ENDPOINT,
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
    const tools = {};
    for (const e of events) tools[e.tool] = (tools[e.tool] || 0) + 1;
    const data = {
      spec: "rubric-harness-attest/0.1",
      session, eventCount: events.length, eventsHash,
      firstTs: events[0].ts, lastTs: events[events.length - 1].ts, tools,
      note: "eventsHash commits to the local session file. Only hashes were transmitted.",
    };
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
      const rec = {
        session, attestationId: j.attestationId,
        verifyUrl: "https://rubric-protocol.com/v1/verify/" + j.attestationId,
        eventsHash, eventCount: events.length, at: new Date().toISOString(),
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

function init(key) {
  fs.mkdirSync(HOME, { recursive: true });
  fs.writeFileSync(CONFIG, JSON.stringify({ apiKey: key, endpoint: DEFAULT_ENDPOINT, evidenceEndpoint: DEFAULT_EVIDENCE_ENDPOINT }, null, 2), { mode: 0o600 });
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
  else if (mode === "init") init(process.argv[3] || "");
  else console.error("usage: attest.mjs init <apiKey> | spool | flush | escrow");
}
