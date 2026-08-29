#!/usr/bin/env node
// rubric-harness-attest 0.1 - anchored evidence that your agent harness ran.
// spool: append one hashed event per tool call. Never blocks, never fails the agent.
// flush: one attestation per session. Hashes only. Code never leaves the machine.
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

const HOME = path.join(os.homedir(), ".rubric");
const SPOOL = path.join(HOME, "spool");
const SESSIONS = path.join(HOME, "sessions");
const CONFIG = path.join(HOME, "config.json");
const DEFAULT_ENDPOINT = "https://rubric-protocol.com/verify/v1/tiered-attest";

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
  return { apiKey: process.env.RUBRIC_API_KEY || c.apiKey || "", endpoint: c.endpoint || DEFAULT_ENDPOINT };
};

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
  fs.writeFileSync(CONFIG, JSON.stringify({ apiKey: key, endpoint: DEFAULT_ENDPOINT }, null, 2), { mode: 0o600 });
  console.error("[rubric-attest] configured. Free tier: 1,000 sessions/month.");
}

const mode = process.argv[2];
if (mode === "spool") spool();
else if (mode === "flush") flush();
else if (mode === "init") init(process.argv[3] || "");
else console.error("usage: attest.mjs init <apiKey> | spool | flush");
