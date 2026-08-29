# rubric-harness-attest

Agent = Model + Harness. This is the seventh layer: proof the harness ran.

Your coding agent makes hundreds of tool calls per session. Linters fire, tests run, gates decide. All of it lands in logs you control, which means none of it is evidence. This pack turns each session into one attestation: ML-DSA-65 signed (FIPS 204, post-quantum), Merkle aggregated, anchored on Hedera. Verifiable by anyone, forever, with no Rubric involvement.

## Install (60 seconds)

    mkdir -p ~/.rubric && curl -so ~/.rubric/attest.mjs https://rubric-protocol.com/pack/attest.mjs
    node ~/.rubric/attest.mjs init <your-free-api-key>

Then merge hooks.example.json into .claude/settings.json. Done. Every session attests itself on Stop.

macOS and Linux today. Windows: replace ~ with %USERPROFILE% paths in the hook commands, untested.

## Privacy

Your code stays home. Only the evidence leaves. The hook transmits tool names, timestamps, and hashes. Prompts, file contents, and tool outputs never leave the machine. The local session file in ~/.rubric/sessions/ is the full record; the anchor proves it existed, unmodified, at that time.

## What you get

- .rubric/attestations.jsonl in each project: session, attestationId, verifyUrl, event count
- A public verify URL per session backed by Hedera consensus
- Independent verification: HashScan, Mirror Node, or the standalone verifier scripts. No account needed to check.

## Why not just signed local receipts

Ed25519 receipts in a JSONL you host prove the chain to whoever trusts your key and your disk. An anchored attestation proves it to people who trust neither. The proof outlives the operator, the laptop, and eventually the signature algorithm. That is the difference between a log and evidence.

## CI variant

    EVENTS=$(jq -c . < harness-events.json)
    curl -s -X POST https://rubric-protocol.com/verify/v1/tiered-attest \
      -H "Content-Type: application/json" -H "x-api-key: $RUBRIC_API_KEY" \
      -d "{\"agentId\":\"harness-ci\",\"sourceId\":\"ci-$GITHUB_SHA\",\"decision\":\"harness-ci-run\",\"data\":{\"commit\":\"$GITHUB_SHA\",\"eventsHash\":\"$(echo -n $EVENTS | sha256sum | cut -d' ' -f1)\"}}"

## Cost

Free tier covers 1,000 sessions a month. Heavy fleets, batch ingest, and the paid x402 endpoints are at https://rubric-protocol.com.

Built by Rubric Protocol. Post-quantum AI attestation infrastructure on Hedera mainnet.

## See one

A real anchored session from this pack: https://rubric-protocol.com/v1/verify/5194b356-5289-46f5-ac74-48ac7e67db9e (HCS seq 293705). Check it on HashScan without touching Rubric: https://hashscan.io/mainnet/topic/0.0.10416909
