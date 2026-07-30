#!/usr/bin/env python3
"""Validate the public-safe MadCat Shared Bus."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
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
    "result_hash",
}
STATE_FIELDS = {
    "schema_version",
    "protocol",
    "active_command",
    "active_command_hash",
    "status",
    "next",
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
ALLOWED_SUFFIXES = {".json", ".md", ".py", ".yml", ".yaml"}
ALLOWED_FILENAMES = {"requirements.txt"}


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("top-level JSON value must be an object")
    return value


def canonical_hash(value: dict[str, Any], hash_field: str) -> str:
    payload = {key: item for key, item in value.items() if key != hash_field}
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


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


def credential_findings(text: str) -> list[str]:
    """Return non-secret finding labels; never echo candidate material."""
    findings: set[str] = set()
    for provider, pattern in PROVIDER_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.add(f"provider:{provider}:line:{line}")
    for match in ENTROPY_TOKEN_RE.finditer(text):
        candidate = match.group(0)
        preceding_context = text[max(0, match.start() - 200) : match.start()]
        if (
            "/" in candidate
            or "://" in candidate
            or not any(character.isdigit() for character in candidate)
            or candidate.startswith("sha256:")
        ):
            continue
        if (
            re.search(r'"kind"\s*:\s*"drive_doc"', preceding_context)
            and re.search(r'"id"\s*:\s*"\s*$', preceding_context)
        ):
            continue
        if (
            character_class_count(candidate) >= 3
            and shannon_entropy(candidate) >= MIN_ENTROPY
        ):
            line = text.count("\n", 0, match.start()) + 1
            findings.add(f"high-entropy:line:{line}")
    return sorted(findings)


def validate_repository(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    commands: dict[str, dict[str, Any]] = {}

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
        commands[command_id] = command
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
        for finding in credential_findings(text):
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
