# MadCat Shared Bus 1.0

Status: paused; receipt acceptance disabled; replay store null; route and poller not observable

## Architecture

The studio uses two GitHub lanes:

1. Private control: `masait78-wq/-madcat-control` is a preserved historical derivative in `retired_no_append` mode. It is not current authority, a replay store, or an operational fallback.
2. Shared bus: `masait78-wq/-madcat-telegram-bridge.` preserves public-safe historical command envelopes. No live engine route, write path, poller, or independent read/write loop is currently observable, and receipt writing and acceptance remain disabled.

The public bus is a transport layer, not studio memory and not an asset store.

## Delivery model

GitHub cannot push a command into a native Grok conversation by itself. No live Grok route, native polling automation, worker, or resume mechanism is currently observed. Historical canary instructions do not authorize execution.

## Integrity and sender authentication

- Commands use canonical SHA-256 hashes. Receipt schema v2 adds an Ed25519 signature and hashes the complete signed envelope.
- Receipt parsing and signature verification are retained only as lint. Every receipt is rejected as `receipt_acceptance_disabled` under the current policy.
- The signer registry is bound to this exact repository and Ed25519. It stores public keys, fingerprints, principals, status, validity windows, and revocation timestamps; it never stores private signing material.
- Commands and receipts are immutable after acceptance.
- The active pointer may move to a later command, but it never rewrites history.

Canonical hashing removes `command_hash` or `result_hash`, then serializes UTF-8 JSON with recursively sorted keys, no insignificant whitespace, and non-ASCII characters preserved. The result hash includes the signature object.

The Ed25519 signing input starts with the exact binary domain:

`MADCAT-SHARED-BUS-RECEIPT-V2\0masait78-wq/-madcat-telegram-bridge.\0`

It is followed by the canonical UTF-8 receipt after removing `result_hash` and only `signature.value`. Signature version, algorithm, key ID, repository protocol, result ID, command ID, observed command hash, nonce, timestamps, status, claims, actions, and cost therefore remain covered.

### Replay boundary

- `replay_store` is `null` and in-memory fallback is forbidden.
- A repository-tree duplicate scan is lint-only and is not an atomic replay reservation.
- Private control is `retired_no_append` and cannot receive replay claims.
- No production public key is registered. Every receipt is rejected and the bus remains paused.

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

## Activation contract

The historical `MC-BUS-CANARY-001` envelope is inert. A new activation may be proposed only by a separately reviewed change that proves all of the following at the same time:

1. a current explicit founder decision for the exact activation;
2. a founder-designated durable atomic replay store;
3. a freshly verified current Grok Ed25519 public key;
4. a live route with successful write and independent readback.

Until then `receipt_acceptance` remains disabled, state remains paused, and no historical phrase or command authorizes resume.

No render, paid API call, publication, message, permission change, or private payload is part of this canary.

## Primary cryptographic basis

- IETF RFC 8032, Ed25519/EdDSA: <https://www.rfc-editor.org/rfc/rfc8032.html>
- NIST FIPS 186-5, Digital Signature Standard: <https://csrc.nist.gov/pubs/fips/186-5/final>
- SLSA artifact verification, signature verification against configured roots of trust: <https://slsa.dev/spec/v1.1/verifying-artifacts>
