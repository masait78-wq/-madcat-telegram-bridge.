# MadCat Shared Bus Agent Contract

These rules apply to the whole repository.

## Roles

- `ChatGPT` owns `bus/inbox/` and `bus/state/current.json`.
- `Grok` reads the active inbox command and owns its matching signed file under `bus/outbox/`.
- Neither engine edits or deletes an accepted command or receipt.
- Every direct GitHub read or write claim must cite evidence returned by that engine's own connector.
- A receipt claiming `agent: Grok` is not trusted by name alone. It must verify under an active Ed25519 key in `trust/receipt-signers.json`.

## Public safety boundary

This repository is public. Never place any of the following here:

- credentials, access tokens, cookies, private keys, payment data, or raw connector output;
- private film scripts, storyboards, prompts, source media, client material, personal data, or unpublished strategy;
- a render request that may consume credits without a separate exact founder approval.

Only `public_control_only` envelopes are allowed. Private production material stays in `masait78-wq/-madcat-control` and approved private asset storage.

## Command handling

1. Read `bus/state/current.json`.
2. Read the named command under `bus/inbox/`.
3. Verify its `command_hash` and `nonce`.
4. Perform only the listed non-sensitive action.
5. Write exactly one schema-v2 receipt to the required `bus/outbox/` path and sign the domain-separated canonical receipt payload with the registered Ed25519 key.
6. Preserve `command_id`, `observed_command_hash`, and `nonce` exactly.
7. Never place the private signing key in this repository, a receipt, a log, a test fixture, or chat.
8. Report unsupported native automation as `blocked`; never imitate success.

Before accepting a receipt, the verifier must validate its schema and hash, load the trusted key registry, verify the signature and key validity window, compare the command binding, and reject a previously consumed result ID, command ID, signer-key/nonce pair, or signature. The accepting private-control transaction must atomically reserve all four replay claims before recording success. A check followed by a later non-atomic write is not acceptance.

No production signer key is currently provisioned, so the bus remains fail-closed and paused. Key onboarding requires an out-of-band fingerprint check and an authorized registry change; never invent or self-assert a Grok key.

## Hard stops

- Never modify another engine's mailbox file.
- Never accept an unsigned, unknown-key, revoked-key, expired-key, forged, or replayed receipt.
- Never publish private payloads to make the bridge convenient.
- Never claim that a native Grok automation exists until Grok returns its actual schedule or an explicit unsupported result.
- Never generate media, spend credits, publish, send messages, change permissions, or perform destructive actions from the bootstrap canary.
