# Verifying a session without trusting anyone

Three independent checks. Each one can be done by someone with no Rubric account and no access to this machine.

## 1. The local file matches the anchor

The attestation commits to eventsHash: the SHA3-256 of the JCS-canonicalized event array. Recompute it from the session file:

    node -e '
    const fs=require("fs"),crypto=require("crypto");
    function jcs(v){if(v===null||v===undefined)return"null";if(typeof v!=="object")return JSON.stringify(v);if(Array.isArray(v))return"["+v.map(jcs).join(",")+"]";const k=Object.keys(v).filter(x=>v[x]!==undefined).sort();return"{"+k.map(x=>JSON.stringify(x)+":"+jcs(v[x])).join(",")+"}"}
    const ev=fs.readFileSync(process.argv[1],"utf8").split("\n").filter(Boolean).map(JSON.parse);
    console.log("sha3-256:"+crypto.createHash("sha3-256").update(jcs(ev)).digest("hex"));' ~/.rubric/sessions/<session>.jsonl

Compare against eventsHash in the attestation data. Match means the file has not changed since it was anchored.

The JCS subset: recursive key sort, no whitespace, undefined dropped, JSON.stringify for scalars. Ten lines, shown above in full. No library needed.

## 2. The anchor exists on public consensus

The verify URL reports the HCS sequence number. Check it against Hedera directly, no Rubric involvement:

    curl -s "https://mainnet-public.mirrornode.hedera.com/api/v1/topics/0.0.10416909/messages?sequencenumber=<seq>&limit=1"

The consensus timestamp is Hedera's, not ours. The message payload commits to the aggregate root that includes this attestation.

## 3. The signature is real

Every attestation is ML-DSA-65 signed (FIPS 204). The verify endpoint returns the public key, the signature, and the signed payload; any FIPS 204 implementation checks it offline. Worked example against a live session from this repo:

    https://rubric-protocol.com/v1/verify/5194b356-5289-46f5-ac74-48ac7e67db9e

Anchored at HCS sequence 293705. Recompute the eventsHash above, check the sequence on the mirror node, verify the signature with any ML-DSA-65 library. If all three hold, the session happened as recorded. Not because we say so.
