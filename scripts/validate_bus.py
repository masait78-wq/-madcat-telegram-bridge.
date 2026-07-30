#!/usr/bin/env python3
"""Validate the public-safe MadCat Shared Bus."""

from __future__ import annotations

import hashlib
import json
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
FORBIDDEN_KEYS = {
    "api_key",
    "authorization",
    "cookie",
    "credentials",
    "password",
    "payment_card",
    "private_key",
    "secret",
    "session_token",
    "token",
}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)
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


def forbidden_key_paths(value: Any, prefix: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_path = f"{prefix}.{key}"
            if key.lower() in FORBIDDEN_KEYS:
                found.append(key_path)
            found.extend(forbidden_key_paths(item, key_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(forbidden_key_paths(item, f"{prefix}[{index}]"))
    return found


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
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{path.relative_to(root)}: possible credential material")

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
