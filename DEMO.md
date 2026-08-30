# The demo is a lab report

Everything below happened on 2026-08-30 against Hedera mainnet. The session names, hashes, and sequence numbers are real. You can check every one of them right now.

## Act 1: a session becomes evidence

A Claude Code session ran one tool call. The hook spooled it, the flush anchored it, escrow sealed it for seven years.

    [rubric-attest] anchored session=myproof1 events=1
      verify=https://rubric-protocol.com/v1/verify/90d2a57d-73b9-4ef4-adcc-bb086d46815f
    [rubric-attest] escrowed session=myproof1 retention=7y expires=2033-08-30
      verify=https://rubric-protocol.com/v1/verify/41578ed8-3f15-45c8-aa69-210df8f9c5e4

Two attestations: one for the session, one for the escrow. Both ML-DSA-65 signed, both anchored on HCS topic 0.0.10416909. The ciphertext went to Rubric. The key did not.

## Act 2: the laptop dies

We deleted everything. What survived is one file: evidence-key.json, 201 bytes, the file the install told you to back up on day one.

## Act 3: a bare directory recovers the evidence

A fresh directory. One key file. The public client, curled from rubric-protocol.com/pack/attest.mjs. No API key, no account, no config.

    $ node attest.mjs restore myproof1
    [rubric-attest] restored session=myproof1 events=1
    [rubric-attest] eventsHash(recomputed)=sha3-256:44110a9b17a9e6fa...
    [rubric-attest] eventsHash(escrowed)  =sha3-256:44110a9b17a9e6fa...
    [rubric-attest] MATCH — the decrypted evidence is the session that was attested.

    $ grep "212 passing" .rubric/restored/myproof1.jsonl
    212 passing

The literal tool output came back. Not a fingerprint of it. The output. Recovery proved possession by decrypting a challenge sealed to the evidence key. No password, no support ticket, no trust in the custodian.

## The negative test

We also tried to restore with the wrong key.

    [rubric-attest] challenge did not open with this evidence key
    [rubric-attest] no possession proof accepted and no API key configured; cannot restore

The refusal happens at the GCM tag. A wrong key produces a clean failure, never plausible garbage. This was not staged. We hit it by accident during testing and kept the transcript because a skeptic should see the failure mode, not just the success.

## What hash-only mode recovers, honestly

The first version of this demo failed. Hash-only escrow (the default) recovered a perfect manifest of fingerprints and zero content, because that is exactly what it seals. If recovery of the words is why you escrow, turn on content mode:

    node attest.mjs init <key> --retain-content

Hash-only proves which session existed, unaltered. Content mode brings the session back. Choose deliberately. We found this the hard way so you do not have to.

## Check our work

The anchors above resolve at rubric-protocol.com/v1/verify/<id>. The HCS sequence is on Hedera's mirror node, not our word:

    curl "https://mainnet-public.mirrornode.hedera.com/api/v1/topics/0.0.10416909/messages?sequencenumber=<seq>&limit=1"

The consensus timestamp is assigned by the network. Rubric cannot backdate it, and neither can you. That asymmetry is the product.
