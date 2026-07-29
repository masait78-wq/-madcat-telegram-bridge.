# MadCat Shared Bus 1.0

Status: bootstrap canary

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

## Integrity

- Commands and receipts use canonical SHA-256 hashes.
- A receipt is accepted only when its command ID, command hash, and nonce match the inbox command.
- Commands and receipts are immutable after acceptance.
- The active pointer may move to a later command, but it never rewrites history.

Canonical hashing removes `command_hash` or `result_hash`, then serializes UTF-8 JSON with recursively sorted keys, no insignificant whitespace, and non-ASCII characters preserved.

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
3. Grok creates the required outbox receipt through its own GitHub connector.
4. ChatGPT independently reads and validates that receipt.
5. Native automation is either proven with its actual schedule or truthfully recorded as blocked.

No render, paid API call, publication, message, permission change, or private payload is part of this canary.
