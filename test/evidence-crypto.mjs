// Phase 1 acceptance gate: client evidence crypto.
import * as crypto from "node:crypto";
import { seal, open, cipherHashOf } from "../attest.mjs";

const SPKI = 12, PKCS8 = 16;
function kp() {
  const k = crypto.generateKeyPairSync("x25519");
  return {
    pub: k.publicKey.export({ type: "spki", format: "der" }).subarray(SPKI),
    priv: k.privateKey.export({ type: "pkcs8", format: "der" }).subarray(PKCS8),
  };
}

let fail = 0;
const ok = (name, cond, extra = "") => {
  if (!cond) fail++;
  console.log((cond ? "PASS" : "FAIL") + "  " + name + (extra ? "  " + extra : ""));
};

// 1. round trip
const alice = kp();
const plaintext = Buffer.from(JSON.stringify({ session: "abc", events: [1, 2, 3], note: "plaintext never leaves" }), "utf8");
const env = seal(alice.pub, plaintext);
ok("envelope shape {v,eph,iv,tag,ct}",
  JSON.stringify(Object.keys(env).sort()) === JSON.stringify(["ct", "eph", "iv", "tag", "v"]) && env.v === 1);
ok("eph is 32 raw bytes", Buffer.from(env.eph, "base64").length === 32);
ok("iv is 12 bytes", Buffer.from(env.iv, "base64").length === 12);
ok("tag is 16 bytes", Buffer.from(env.tag, "base64").length === 16);
ok("ciphertext differs from plaintext", !Buffer.from(env.ct, "base64").equals(plaintext));
const back = open(alice.priv, env);
ok("round trip decrypt equals input", back.equals(plaintext));

// 2. wrong private key must fail GCM auth, not return garbage
const mallory = kp();
let threw = null, returned = null;
try { returned = open(mallory.priv, env); } catch (e) { threw = e; }
ok("wrong private key throws", threw !== null, threw ? "err=" + threw.message : "RETURNED " + (returned && returned.length) + " BYTES");
ok("failure is GCM auth, not garbage output",
  threw !== null && returned === null && /auth|unsupported state/i.test(threw.message), threw ? "msg=" + threw.message : "");

// tampered ciphertext must also fail the tag
const tampered = { ...env };
const ctBuf = Buffer.from(env.ct, "base64"); ctBuf[0] ^= 0xff;
tampered.ct = ctBuf.toString("base64");
let tamperThrew = null;
try { open(alice.priv, tampered); } catch (e) { tamperThrew = e; }
ok("tampered ciphertext fails the tag", tamperThrew !== null, tamperThrew ? "err=" + tamperThrew.message : "");

// 3. 1MB payload under 200ms
const big = crypto.randomBytes(1024 * 1024);
const t0 = process.hrtime.bigint();
const bigEnv = seal(alice.pub, big);
const t1 = process.hrtime.bigint();
const bigBack = open(alice.priv, bigEnv);
const t2 = process.hrtime.bigint();
const sealMs = Number(t1 - t0) / 1e6, openMs = Number(t2 - t1) / 1e6;
ok("1MB round trip byte-identical", bigBack.equals(big));
ok("1MB seal under 200ms", sealMs < 200, "seal=" + sealMs.toFixed(1) + "ms");
ok("1MB open under 200ms", openMs < 200, "open=" + openMs.toFixed(1) + "ms");
ok("1MB seal+open under 200ms", sealMs + openMs < 200, "total=" + (sealMs + openMs).toFixed(1) + "ms");

// cipherHash is deterministic over JCS(envelope)
ok("cipherHash deterministic", cipherHashOf(env) === cipherHashOf({ ct: env.ct, v: env.v, tag: env.tag, iv: env.iv, eph: env.eph }),
  cipherHashOf(env).slice(0, 26));
ok("cipherHash is sha3-256", cipherHashOf(env).startsWith("sha3-256:") && cipherHashOf(env).length === 9 + 64);

console.log("");
console.log(fail === 0 ? "PHASE 1 GATE: PASS" : "PHASE 1 GATE: FAIL (" + fail + " failing)");
process.exit(fail === 0 ? 0 : 1);
