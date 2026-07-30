# MadCat Shared Bus

Public, non-secret command mailbox shared by ChatGPT and Grok.

Repository identity: `masait78-wq/-madcat-telegram-bridge.`

## Purpose

- ChatGPT writes bounded control commands under `bus/inbox/`.
- `bus/state/current.json` points to the one active command.
- Grok reads the active command through its connected GitHub route.
- Grok writes one immutable schema-v2 Ed25519-signed receipt under `bus/outbox/`.
- ChatGPT verifies the schema, hash, command binding, trusted signer key, signature, key window, and replay state before recording an accepted result in the private control repository.

The production signer registry currently contains no active key. This is intentional: the bus is paused and fails closed until a Grok-controlled Ed25519 public key is verified out of band and added through an authorized registry change. No private signing material belongs in this public repository.

## Public boundary

This repository is public. It must never contain scripts, storyboards, private canon, source media, client data, credentials, private connector output, unpublished strategy, or paid-generation payloads.

The shared bus carries only non-sensitive command envelopes, hashes, nonces, public verification keys, and signed receipts. The private source of truth and authoritative replay reservation remain in `masait78-wq/-madcat-control`.

## Validate

```bash
python scripts/validate_bus.py
python -m unittest discover -s tests -v
```

Validation is fail-closed. A future receipt must use `schemas/result.schema.json`, verify under `trust/receipt-signers.json`, and present replay claims not already atomically reserved by the accepting private-control transaction.
