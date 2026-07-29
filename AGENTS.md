# MadCat Shared Bus Agent Contract

These rules apply to the whole repository.

## Roles

- `ChatGPT` owns `bus/inbox/` and `bus/state/current.json`.
- `Grok` reads the active inbox command and owns its matching file under `bus/outbox/`.
- Neither engine edits or deletes an accepted command or receipt.
- Every direct GitHub read or write claim must cite evidence returned by that engine's own connector.

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
5. Write exactly one receipt to the required `bus/outbox/` path.
6. Preserve `command_id`, `observed_command_hash`, and `nonce` exactly.
7. Report unsupported native automation as `blocked`; never imitate success.

## Hard stops

- Never modify another engine's mailbox file.
- Never publish private payloads to make the bridge convenient.
- Never claim that a native Grok automation exists until Grok returns its actual schedule or an explicit unsupported result.
- Never generate media, spend credits, publish, send messages, change permissions, or perform destructive actions from the bootstrap canary.
