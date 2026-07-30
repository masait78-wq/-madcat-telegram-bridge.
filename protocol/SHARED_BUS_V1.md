# MadCat Shared Bus 1.0

Status: paused, receipt authentication repaired, no production signer key provisioned

## Architecture

The studio uses two GitHub lanes:

1. Private control: `masait78-wq/-madcat-control` stores accepted state, task capsules, event history, and confidential production references.
2. Shared bus: `masait78-wq/-madcat-telegram-bridge.` stores only public-safe command envelopes and receipts that both connected engines can independently read and write.

The public bus is a transport layer, not studio memory and not an asset store.

## Delivery model

GitHub cannot push a command into a native Grok conversation by itself. Grok must either:

- run a native Grok Automation that polls `bus/state/current.json`; or
- be asked in the Grok app to run the current bus command.

The bootstrap canary tests whether the connected Grok GitHub route can read the exact command, write a receipt, and create a native polling automation if that surface is available.

## Integrity and sender authentication

- Commands use canonical SHA-256 hashes. Receipt schema v2 adds an Ed25519 signature and hashes the complete signed envelope.
- A receipt is accepted only when its command ID, command hash, and nonce match the inbox command; its schema and result hash pass; and its signature verifies under an active, in-window public key from `trust/receipt-signers.json`.
- The signer registry is bound to this exact repository and Ed25519. It stores public keys, fingerprints, principals, status, validity windows, and revocation timestamps; it never stores private signing material.
- Commands and receipts are immutable after acceptance.
- The active pointer may move to a later command, but it never rewrites history.

Canonical hashing removes `command_hash` or `result_hash`, then serializes UTF-8 JSON with recursively sorted keys, no insignificant whitespace, and non-ASCII characters preserved. The result hash includes the signature object.

The Ed25519 signing input starts with the exact binary domain:

`MADCAT-SHARED-BUS-RECEIPT-V2\0masait78-wq/-madcat-telegram-bridge.\0`

It is followed by the canonical UTF-8 receipt after removing `result_hash` and only `signature.value`. Signature version, algorithm, key ID, repository protocol, result ID, command ID, observed command hash, nonce, timestamps, status, claims, actions, and cost therefore remain covered.

### Replay rejection

- Inbox command nonces must be unique.
- The verifier rejects a consumed result ID, command ID, signer-key/nonce pair, or signature.
- Immediately before acceptance, private control must atomically reserve all four claims in its authoritative replay store. A read/check without the atomic reservation is not acceptance.
- CI also detects duplicates within the current repository tree. Cross-history tamper resistance is a separate signed append-only/checkpoint control; the current-tree validator does not claim to solve it.

No production public key is registered yet. Until a Grok-controlled key is verified through a separate channel and added by an authorized registry change, every receipt is rejected and the bus remains paused.

An Ed25519 signature proves possession of the registered private key and detects alteration of the covered receipt. It does not by itself prove a human identity, account ownership, independent review, truth of the signed claim, or correct external execution.

## Confidentiality

The shared bus may carry:

- command IDs;
- public-safe operation names;
- content hashes;
- non-secret nonces;
- connector read/write receipts;
- automation schedule evidence.

It may not carry private film content or media. A later confidential Grok worker requires a private connector or the xAI API with provider credentials stored in an approved secret manager. A SuperGrok consumer subscription is not treated as an API credential.

## Bootstrap acceptance

`MC-BUS-CANARY-001` passes only when:

1. Grok independently reads the exact repository name including the trailing dot.
2. Grok reads the active command and reports its exact hash and nonce.
3. Grok creates the required schema-v2 signed outbox receipt through its own GitHub connector.
4. ChatGPT independently reads it and validates the schema, result hash, trusted signer, signature, key window, command binding, and replay claims.
5. Native automation is either proven with its actual schedule or truthfully recorded as blocked.

These steps cannot currently pass because no production signer key is provisioned. That is a deliberate fail-closed state, not evidence that Grok identity has been established.

No render, paid API call, publication, message, permission change, or private payload is part of this canary.

## Primary cryptographic basis

- IETF RFC 8032, Ed25519/EdDSA: <https://www.rfc-editor.org/rfc/rfc8032.html>
- NIST FIPS 186-5, Digital Signature Standard: <https://csrc.nist.gov/pubs/fips/186-5/final>
- SLSA artifact verification, signature verification against configured roots of trust: <https://slsa.dev/spec/v1.1/verifying-artifacts>
