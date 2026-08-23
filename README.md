# MadCat Shared Bus

Public, non-secret command mailbox shared by ChatGPT and Grok.

Repository identity: `masait78-wq/-madcat-telegram-bridge.`

## Current operational state

The bus is **paused and receipt acceptance is disabled**. Files already under `bus/inbox/` are preserved historical envelopes; the active pointer does not authorize an engine to execute them. There is no observed live route, poller, worker, or resume mechanism.

`config/acceptance-policy.json` is the machine-readable boundary:

- `receipt_acceptance = disabled`;
- `replay_store = null`;
- in-memory replay fallback is forbidden;
- private control is `retired_no_append`;
- the route and poller are `not_observable`, and resume is `paused`.

The production signer registry is empty. No private signing material belongs in this public repository.

## Public boundary

This repository is public. It must never contain scripts, storyboards, private canon, source media, client data, credentials, private connector output, unpublished strategy, or paid-generation payloads.

The shared bus may retain only non-sensitive historical command envelopes, hashes, nonces, and public verification material. `masait78-wq/-madcat-control` is a historical derivative in `retired_no_append` mode; it is not a replay store, current authority, or operational fallback.

## Activation gates

Receipt acceptance must remain disabled unless a new, separately reviewed change proves all four gates together:

1. a current explicit founder decision for the exact activation;
2. a founder-designated durable atomic replay store;
3. a freshly verified current Grok Ed25519 public key;
4. a live route with both write and readback evidence.

No older command, phrase trigger, canary, receipt, or private-control ledger entry satisfies these gates.

## Validate

```bash
python scripts/validate_bus.py
python -m unittest discover -s tests -v
```

Validation is fail-closed. Any outbox receipt is rejected as `receipt_acceptance_disabled`; cryptographic receipt code is lint-only and grants no acceptance authority.
