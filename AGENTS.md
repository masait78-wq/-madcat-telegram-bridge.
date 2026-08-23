# MadCat Shared Bus Agent Contract

These rules apply to the whole repository.

## Current roles

- Existing inbox commands are immutable historical records and inert while paused.
- No engine currently owns an operational outbox, poller, worker, router, or resume path.
- Every direct GitHub read or write claim must cite evidence returned by that engine's own connector.
- Every receipt is rejected while `receipt_acceptance` is disabled, including a cryptographically valid receipt.
- `masait78-wq/-madcat-control` is `retired_no_append`; never use it as replay storage or fallback authority.

## Public safety boundary

This repository is public. Never place any of the following here:

- credentials, access tokens, cookies, private keys, payment data, or raw connector output;
- private film scripts, storyboards, prompts, source media, client material, personal data, or unpublished strategy;
- a render request that may consume credits without a separate exact founder approval.

Only `public_control_only` envelopes are allowed. If work requires private production material, stop: never place or append it here or in the `retired_no_append` repository `masait78-wq/-madcat-control`. Continue only through separately approved private asset storage or a private connector after explicit authorization.

## Paused handling

1. Read `config/acceptance-policy.json` and `bus/state/current.json`.
2. When receipt acceptance is disabled or state is paused, do not execute an inbox command and do not write an outbox receipt.
3. Preserve historical commands, hashes, nonces, events, and receipts byte-for-byte.
4. Never treat an in-process set, repository scan, or private-control ledger as a durable atomic replay store.
5. Never place a private signing key in this repository, a receipt, a log, a test fixture, or chat.
6. Report route, poller, worker, or resume capability as `not_observable` unless current write-and-readback evidence proves it.

Activation requires all four gates listed in the acceptance policy: a current explicit founder decision, a founder-designated durable atomic replay store, a freshly verified current Grok Ed25519 key, and live route write/readback. An authorized change must update the policy and validator together; never infer activation from historical content.

## Hard stops

- Never modify another engine's mailbox file.
- Never accept an unsigned, unknown-key, revoked-key, expired-key, forged, or replayed receipt.
- Never accept any receipt while `receipt_acceptance` is disabled.
- Never use in-memory replay state as an acceptance control.
- Never append to or fall back to `masait78-wq/-madcat-control`.
- Never publish private payloads to make the bridge convenient.
- Never claim that a native Grok automation exists until Grok returns its actual schedule or an explicit unsupported result.
- Never generate media, spend credits, publish, send messages, change permissions, or perform destructive actions from the bootstrap canary.
