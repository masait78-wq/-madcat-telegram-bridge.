#!/usr/bin/env python3
"""Validate the public-safe MadCat Shared Bus."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_BUS_REPOSITORY = "masait78-wq/-madcat-telegram-bridge."
RECEIPT_SIGNATURE_DOMAIN = (
    b"MADCAT-SHARED-BUS-RECEIPT-V2\x00"
    + PUBLIC_BUS_REPOSITORY.encode("utf-8")
    + b"\x00"
)
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMAND_FIELDS = {
    "schema_version",
    "protocol",
    "command_id",
    "created_at",
    "sender",
    "target",
    "classification",
    "task_type",
    "private_payload_included",
    "payload",
    "required_result",
    "nonce",
    "status",
    "command_hash",
}
RESULT_FIELDS = {
    "schema_version",
    "protocol",
    "result_id",
    "command_id",
    "completed_at",
    "agent",
    "status",
    "observed_command_hash",
    "nonce",
    "summary",
    "checks",
    "external_actions",
    "credits_spent",
    "signature",
    "result_hash",
}
SIGNATURE_FIELDS = {"version", "algorithm", "key_id", "value"}
STATE_FIELDS = {
    "schema_version",
    "protocol",
    "active_command",
    "active_command_hash",
    "status",
    "next",
}
SIGNER_REGISTRY_FIELDS = {
    "schema_version",
    "registry_id",
    "repository",
    "algorithm",
    "keys",
    "truth_boundary",
}
SIGNER_KEY_FIELDS = {
    "key_id",
    "principal",
    "public_key",
    "public_key_sha256",
    "status",
    "valid_from",
    "valid_until",
    "revoked_at",
}
FORBIDDEN_KEY_NAMES = {
    "accesskey",
    "accesstoken",
    "apikey",
    "authorization",
    "bearer",
    "clientsecret",
    "cookie",
    "credential",
    "credentials",
    "passphrase",
    "password",
    "paymentcard",
    "privatekey",
    "refreshtoken",
    "secret",
    "sessiontoken",
    "signingkey",
    "token",
    "webhooksecret",
}
PROVIDER_SECRET_PATTERNS = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    ("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("openai-or-xai", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("stripe", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("aws", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("telegram", re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b")),
    ("slack", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("npm", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b")),
    ("gitlab", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
)
ENTROPY_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=.:~-]{24,}(?![A-Za-z0-9])"
)
MIN_ENTROPY = 4.4
PUBLIC_IDENTIFIER_KINDS = {
    "drive_doc",
    "drive_file",
    "drive_folder",
    "site_project",
}
PUBLIC_IDENTIFIER_PREFIXES = (
    "drive_file:",
    "drive_folder:",
    "site_project:",
)
ALLOWED_SUFFIXES = {".json", ".md", ".py", ".yml", ".yaml"}
ALLOWED_FILENAMES = {"requirements.txt"}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value must be an object")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_hash(value: dict[str, Any], hash_field: str) -> str:
    payload = {key: item for key, item in value.items() if key != hash_field}
    return "sha256:" + hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def receipt_signing_bytes(result: dict[str, Any]) -> bytes:
    """Return the domain-separated payload covered by an Ed25519 receipt signature."""
    payload = {
        key: item
        for key, item in result.items()
        if key not in {"result_hash", "signature"}
    }
    signature = result.get("signature")
    if isinstance(signature, dict):
        payload["signature"] = {
            key: item for key, item in signature.items() if key != "value"
        }
    return RECEIPT_SIGNATURE_DOMAIN + canonical_json_bytes(payload)


def decode_base64url(value: Any, expected_bytes: int) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ValueError("value must be unpadded base64url")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("value must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, TypeError) as exc:
        raise ValueError("value must be unpadded base64url") from exc
    normalized = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if normalized != value or len(decoded) != expected_bytes:
        raise ValueError(f"value must encode exactly {expected_bytes} bytes")
    return decoded


def parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


def signer_registry_errors(registry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(registry) != SIGNER_REGISTRY_FIELDS:
        errors.append("registry fields do not match the protocol")
    if registry.get("schema_version") != 1:
        errors.append("unexpected registry schema_version")
    if registry.get("registry_id") != "MADCAT-RECEIPT-SIGNERS-1":
        errors.append("unexpected registry_id")
    if registry.get("repository") != PUBLIC_BUS_REPOSITORY:
        errors.append("unexpected registry repository")
    if registry.get("algorithm") != "Ed25519":
        errors.append("unexpected registry algorithm")
    keys = registry.get("keys")
    if not isinstance(keys, list):
        return errors + ["keys must be an array"]
    seen_ids: set[str] = set()
    seen_fingerprints: set[str] = set()
    for index, key in enumerate(keys):
        label = f"keys[{index}]"
        if not isinstance(key, dict):
            errors.append(f"{label}: key record must be an object")
            continue
        if set(key) != SIGNER_KEY_FIELDS:
            errors.append(f"{label}: key fields do not match the protocol")
        key_id = key.get("key_id")
        if not isinstance(key_id, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9._-]{2,63}",
            key_id,
        ):
            errors.append(f"{label}: invalid key_id")
        elif key_id in seen_ids:
            errors.append(f"{label}: duplicate key_id")
        else:
            seen_ids.add(key_id)
        try:
            public_key = decode_base64url(key.get("public_key"), 32)
        except ValueError as exc:
            errors.append(f"{label}: invalid Ed25519 public key: {exc}")
            public_key = None
        if public_key is not None:
            expected_fingerprint = "sha256:" + hashlib.sha256(public_key).hexdigest()
            if key.get("public_key_sha256") != expected_fingerprint:
                errors.append(f"{label}: public key fingerprint mismatch")
            elif expected_fingerprint in seen_fingerprints:
                errors.append(f"{label}: duplicate public key")
            else:
                seen_fingerprints.add(expected_fingerprint)
        if key.get("principal") != "Grok":
            errors.append(f"{label}: unexpected principal")
        try:
            valid_from = parse_timestamp(key.get("valid_from"))
        except (TypeError, ValueError):
            errors.append(f"{label}: invalid valid_from")
            valid_from = None
        valid_until_value = key.get("valid_until")
        try:
            valid_until = (
                None
                if valid_until_value is None
                else parse_timestamp(valid_until_value)
            )
        except (TypeError, ValueError):
            errors.append(f"{label}: invalid valid_until")
            valid_until = None
        if valid_from is not None and valid_until is not None:
            if valid_until <= valid_from:
                errors.append(f"{label}: valid_until must be after valid_from")
        status = key.get("status")
        if status not in {"active", "revoked"}:
            errors.append(f"{label}: invalid status")
        revoked_at = key.get("revoked_at")
        if status == "active" and revoked_at is not None:
            errors.append(f"{label}: active key cannot have revoked_at")
        if status == "revoked" and revoked_at is None:
            errors.append(f"{label}: revoked key requires revoked_at")
        if revoked_at is not None:
            try:
                parse_timestamp(revoked_at)
            except (TypeError, ValueError):
                errors.append(f"{label}: invalid revoked_at")
    return errors


def signer_key_map(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keys = registry.get("keys")
    if not isinstance(keys, list):
        return {}
    return {
        key["key_id"]: key
        for key in keys
        if isinstance(key, dict) and isinstance(key.get("key_id"), str)
    }


def empty_replay_state() -> dict[str, set[str]]:
    return {
        "result_ids": set(),
        "command_ids": set(),
        "signer_nonces": set(),
        "signatures": set(),
    }


def receipt_replay_claims(result: dict[str, Any]) -> dict[str, str]:
    signature = result.get("signature")
    if not isinstance(signature, dict):
        signature = {}
    key_id = signature.get("key_id")
    nonce = result.get("nonce")
    return {
        "result_ids": result.get("result_id")
        if isinstance(result.get("result_id"), str)
        else "",
        "command_ids": result.get("command_id")
        if isinstance(result.get("command_id"), str)
        else "",
        "signer_nonces": f"{key_id}:{nonce}"
        if isinstance(key_id, str) and isinstance(nonce, str)
        else "",
        "signatures": signature.get("value")
        if isinstance(signature.get("value"), str)
        else "",
    }


def reserve_receipt_claims(
    result: dict[str, Any],
    replay_state: dict[str, set[str]],
) -> None:
    for bucket, claim in receipt_replay_claims(result).items():
        if claim:
            replay_state[bucket].add(claim)


def receipt_authentication_errors(
    result: dict[str, Any],
    registry: dict[str, Any],
    replay_state: dict[str, set[str]] | None = None,
) -> list[str]:
    """Verify signer trust, Ed25519 signature, key validity, and replay claims."""
    if signer_registry_errors(registry):
        return ["signer_registry_invalid"]
    errors: list[str] = []
    signature = result.get("signature")
    if not isinstance(signature, dict) or set(signature) != SIGNATURE_FIELDS:
        return ["receipt signature fields do not match the protocol"]
    if signature.get("version") != 1:
        errors.append("receipt_signature_version_unsupported")
    if signature.get("algorithm") != "Ed25519":
        errors.append("receipt_signature_algorithm_unsupported")
    key_id = signature.get("key_id")
    key = signer_key_map(registry).get(key_id)
    if key is None:
        errors.append("unknown_signer_key")
    elif key.get("status") != "active":
        errors.append("signer_key_not_active")
    elif result.get("agent") != key.get("principal"):
        errors.append("signer_principal_mismatch")

    completed_at: datetime | None
    try:
        completed_at = parse_timestamp(result.get("completed_at"))
    except (TypeError, ValueError):
        completed_at = None
        errors.append("receipt_completed_at_invalid")
    if key is not None and completed_at is not None:
        try:
            valid_from = parse_timestamp(key.get("valid_from"))
            valid_until = (
                None
                if key.get("valid_until") is None
                else parse_timestamp(key.get("valid_until"))
            )
        except (TypeError, ValueError):
            errors.append("signer_key_window_invalid")
        else:
            if completed_at < valid_from:
                errors.append("receipt_predates_signer_key")
            if valid_until is not None and completed_at >= valid_until:
                errors.append("receipt_postdates_signer_key")

    if key is not None:
        try:
            public_key_type = Ed25519PublicKey
            public_key = public_key_type.from_public_bytes(
                decode_base64url(key.get("public_key"), 32)
            )
            signature_bytes = decode_base64url(signature.get("value"), 64)
            public_key.verify(signature_bytes, receipt_signing_bytes(result))
        except (InvalidSignature, TypeError, ValueError):
            errors.append("receipt_signature_invalid")

    if replay_state is not None:
        for bucket, claim in receipt_replay_claims(result).items():
            if claim and claim in replay_state[bucket]:
                errors.append(f"{bucket[:-1]}_replayed")
    return errors


def schema_errors(value: dict[str, Any], schema_path: Path, label: str) -> list[str]:
    schema = load_json(schema_path)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        f"{label}: schema violation at {'.'.join(str(part) for part in error.absolute_path) or '$'}: {error.message}"
        for error in sorted(
            validator.iter_errors(value),
            key=lambda item: tuple(str(part) for part in item.absolute_path),
        )
    ]


def normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def forbidden_key_paths(value: Any, prefix: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{prefix}.{key}"
            if normalized_key(key) in FORBIDDEN_KEY_NAMES:
                found.append(key_path)
            found.extend(forbidden_key_paths(item, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(forbidden_key_paths(item, f"{prefix}[{index}]"))
    return found


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (value.count(character) / len(value))
        * math.log2(value.count(character) / len(value))
        for character in set(value)
    )


def character_class_count(value: str) -> int:
    return sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(character in "_+/=.:~-" for character in value),
        )
    )


def credential_findings(
    text: str,
    allowed_public_crypto: set[str] | None = None,
) -> list[str]:
    """Return non-secret finding labels; never echo candidate material."""
    scanned_text = text
    for value in allowed_public_crypto or set():
        if value:
            scanned_text = scanned_text.replace(value, "_" * len(value))
    findings: set[str] = set()
    for provider, pattern in PROVIDER_SECRET_PATTERNS:
        for match in pattern.finditer(scanned_text):
            line = scanned_text.count("\n", 0, match.start()) + 1
            findings.add(f"provider:{provider}:line:{line}")
    for match in ENTROPY_TOKEN_RE.finditer(scanned_text):
        candidate = match.group(0)
        preceding_context = scanned_text[max(0, match.start() - 200) : match.start()]
        if (
            "/" in candidate
            or "://" in candidate
            or not any(character.isdigit() for character in candidate)
            or candidate.startswith("sha256:")
        ):
            continue
        if candidate.startswith(PUBLIC_IDENTIFIER_PREFIXES):
            continue
        public_kind_pattern = "|".join(sorted(PUBLIC_IDENTIFIER_KINDS))
        if (
            re.search(
                rf'"kind"\s*:\s*"(?:{public_kind_pattern})"',
                preceding_context,
            )
            and re.search(r'"id"\s*:\s*"\s*$', preceding_context)
        ):
            continue
        if (
            character_class_count(candidate) >= 3
            and shannon_entropy(candidate) >= MIN_ENTROPY
        ):
            line = scanned_text.count("\n", 0, match.start()) + 1
            findings.add(f"high-entropy:line:{line}")
    return sorted(findings)


def validate_repository(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    commands: dict[str, dict[str, Any]] = {}
    command_nonces: set[str] = set()
    allowed_public_crypto: set[str] = set()

    registry_path = root / "trust" / "receipt-signers.json"
    try:
        registry = load_json(registry_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"trust/receipt-signers.json: {exc}")
        registry = {}
    try:
        errors.extend(
            schema_errors(
                registry,
                root / "schemas" / "signer-registry.schema.json",
                "trust/receipt-signers.json",
            )
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(
            f"trust/receipt-signers.json: schema validation unavailable: {exc}"
        )
    registry_semantic_errors = signer_registry_errors(registry)
    errors.extend(
        f"trust/receipt-signers.json: {error}"
        for error in registry_semantic_errors
    )
    if not registry_semantic_errors:
        for key in registry.get("keys", []):
            if isinstance(key, dict) and isinstance(key.get("public_key"), str):
                allowed_public_crypto.add(key["public_key"])
    for key_path in forbidden_key_paths(registry):
        errors.append(
            f"trust/receipt-signers.json: forbidden secret-bearing key {key_path}"
        )

    for path in sorted((root / "bus" / "inbox").glob("*.json")):
        relative = path.relative_to(root)
        try:
            command = load_json(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{relative}: {exc}")
            continue
        try:
            errors.extend(
                schema_errors(
                    command,
                    root / "schemas" / "command.schema.json",
                    str(relative),
                )
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{relative}: schema validation unavailable: {exc}")
        command_id = command.get("command_id", path.stem)
        if command_id in commands:
            errors.append(f"{relative}: duplicate command_id")
        commands[command_id] = command
        nonce = command.get("nonce")
        if isinstance(nonce, str):
            if nonce in command_nonces:
                errors.append(f"{relative}: duplicate command nonce")
            command_nonces.add(nonce)
        if set(command) != COMMAND_FIELDS:
            errors.append(f"{relative}: command fields do not match the protocol")
        if command_id != path.stem:
            errors.append(f"{relative}: filename and command_id differ")
        if command.get("protocol") != "MADCAT-SHARED-BUS-1.0":
            errors.append(f"{relative}: unexpected protocol")
        if command.get("classification") != "public_control_only":
            errors.append(f"{relative}: only public_control_only commands are allowed")
        if command.get("private_payload_included") is not False:
            errors.append(f"{relative}: private payload is forbidden")
        actual_hash = command.get("command_hash")
        if not isinstance(actual_hash, str) or not HASH_RE.fullmatch(actual_hash):
            errors.append(f"{relative}: invalid command hash format")
        elif actual_hash != canonical_hash(command, "command_hash"):
            errors.append(f"{relative}: command hash mismatch")
        for key_path in forbidden_key_paths(command):
            errors.append(f"{relative}: forbidden secret-bearing key {key_path}")

    replay_state = empty_replay_state()
    for path in sorted((root / "bus" / "outbox").glob("*.json")):
        relative = path.relative_to(root)
        try:
            result = load_json(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{relative}: {exc}")
            continue
        try:
            errors.extend(
                schema_errors(
                    result,
                    root / "schemas" / "result.schema.json",
                    str(relative),
                )
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{relative}: schema validation unavailable: {exc}")
        command = commands.get(result.get("command_id"))
        if set(result) != RESULT_FIELDS:
            errors.append(f"{relative}: result fields do not match the protocol")
        if result.get("result_id") != path.stem:
            errors.append(f"{relative}: filename and result_id differ")
        actual_hash = result.get("result_hash")
        if not isinstance(actual_hash, str) or not HASH_RE.fullmatch(actual_hash):
            errors.append(f"{relative}: invalid result hash format")
        elif actual_hash != canonical_hash(result, "result_hash"):
            errors.append(f"{relative}: result hash mismatch")
        if command is None:
            errors.append(f"{relative}: referenced command does not exist")
        else:
            if result.get("observed_command_hash") != command.get("command_hash"):
                errors.append(f"{relative}: observed command hash mismatch")
            if result.get("nonce") != command.get("nonce"):
                errors.append(f"{relative}: nonce mismatch")
        authentication_errors = receipt_authentication_errors(
            result,
            registry,
            replay_state,
        )
        errors.extend(
            f"{relative}: {error}" for error in authentication_errors
        )
        if not authentication_errors:
            signature = result.get("signature")
            if isinstance(signature, dict) and isinstance(
                signature.get("value"), str
            ):
                allowed_public_crypto.add(signature["value"])
        reserve_receipt_claims(result, replay_state)
        for key_path in forbidden_key_paths(result):
            errors.append(f"{relative}: forbidden secret-bearing key {key_path}")

    state_path = root / "bus" / "state" / "current.json"
    try:
        state = load_json(state_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"bus/state/current.json: {exc}")
        state = {}
    try:
        errors.extend(
            schema_errors(
                state,
                root / "schemas" / "state.schema.json",
                "bus/state/current.json",
            )
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"bus/state/current.json: schema validation unavailable: {exc}")
    if set(state) != STATE_FIELDS:
        errors.append("bus/state/current.json: fields do not match the protocol")
    active = commands.get(state.get("active_command"))
    if active is None:
        errors.append("bus/state/current.json: active_command does not resolve")
    elif active.get("command_hash") != state.get("active_command_hash"):
        errors.append("bus/state/current.json: active_command_hash mismatch")

    for path in sorted(root.rglob("*")):
        if (
            not path.is_file()
            or ".git" in path.parts
            or "__pycache__" in path.parts
            or path.suffix == ".pyc"
        ):
            continue
        if (
            path.suffix.lower() not in ALLOWED_SUFFIXES
            and path.name not in ALLOWED_FILENAMES
        ):
            errors.append(f"{path.relative_to(root)}: unsupported public-bus file type")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"{path.relative_to(root)}: non-text content is forbidden")
            continue
        for finding in credential_findings(text, allowed_public_crypto):
            errors.append(
                f"{path.relative_to(root)}: possible credential material ({finding})"
            )

    return errors


def main() -> int:
    errors = validate_repository()
    if errors:
        print("MadCat shared bus validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("MadCat shared bus validation passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
