---
name: rubric-harness-attest
description: Produce anchored, post-quantum-signed evidence that an agent harness actually ran. Use this whenever the user wants proof of agent activity, an audit trail for AI agent sessions, harness attestation, tamper-evident records of tool calls, compliance evidence for agent work (EU AI Act, SOC 2, ISO 42001), or asks how to verify what an agent did. Also use it when setting up Claude Code hooks for logging or governance, even if the user does not say "attestation".
---

# Rubric Harness Attestation

Every agent session produces evidence. This skill anchors it.

A PostToolUse hook appends one hashed event per tool call to a local spool. A Stop hook flushes the session as a single attestation to Rubric Protocol: ML-DSA-65 signed, Merkle aggregated, anchored on Hedera Consensus Service. Anyone can verify it without trusting the operator, the vendor, or this machine.

## What leaves the machine

Hashes. Tool names, timestamps, and SHA3-256 digests of inputs and outputs. Never the inputs or outputs themselves. The full event list stays in ~/.rubric/sessions/. The attestation commits to its hash, so the local file is provable evidence and the chain is the notary.

## Setup

1. Copy attest.mjs to ~/.rubric/attest.mjs
2. Get a free API key at https://rubric-protocol.com and run: node ~/.rubric/attest.mjs init <key>
3. Merge hooks.example.json into .claude/settings.json (project or user scope)

That is the whole install. Sessions attest themselves from then on.

## Verify a session

Read .rubric/attestations.jsonl in the project. Each line has a verifyUrl. Open it, or check the HCS sequence on HashScan directly. Recompute eventsHash from ~/.rubric/sessions/<session>.jsonl with the same JCS canonicalization to confirm the local file matches the anchor.

## CI variant

One step after tests: POST commit hash, test result hash, and lint result hash to the same endpoint. See README.

## Failure behavior

The spool hook always exits 0. A dead network keeps the spool on disk and retries at the next flush. Evidence is best-effort by design: the agent is never blocked, slowed, or failed by attestation.
