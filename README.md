# MadCat Shared Bus

Public, non-secret command mailbox shared by ChatGPT and Grok.

Repository identity: `masait78-wq/-madcat-telegram-bridge.`

## Purpose

- ChatGPT writes bounded control commands under `bus/inbox/`.
- `bus/state/current.json` points to the one active command.
- Grok reads the active command through its connected GitHub route.
- Grok writes one immutable receipt under `bus/outbox/`.
- ChatGPT verifies the receipt and records the accepted result in the private control repository.

## Public boundary

This repository is public. It must never contain scripts, storyboards, private canon, source media, client data, credentials, private connector output, unpublished strategy, or paid-generation payloads.

The shared bus carries only non-sensitive command envelopes, hashes, nonces, and receipts. The private source of truth remains `masait78-wq/-madcat-control`.

## Validate

```bash
python scripts/validate_bus.py
python -m unittest discover -s tests -v
```
