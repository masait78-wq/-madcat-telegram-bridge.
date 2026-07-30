import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_bus",
    ROOT / "scripts" / "validate_bus.py",
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class SharedBusValidationTests(unittest.TestCase):
    def test_repository_is_valid(self) -> None:
        self.assertEqual(VALIDATOR.validate_repository(ROOT), [])

    def test_hash_detects_command_mutation(self) -> None:
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        original_hash = VALIDATOR.canonical_hash(command, "command_hash")
        mutated = copy.deepcopy(command)
        mutated["status"] = "cancelled"
        self.assertNotEqual(
            original_hash,
            VALIDATOR.canonical_hash(mutated, "command_hash"),
        )

    def test_forbidden_key_detection_is_recursive(self) -> None:
        self.assertEqual(
            VALIDATOR.forbidden_key_paths({"nested": [{"token": "redacted"}]}),
            ["$.nested[0].token"],
        )

    def test_secret_key_detection_normalizes_case_and_separators(self) -> None:
        self.assertEqual(
            VALIDATOR.forbidden_key_paths(
                {
                    "Api-Key": "redacted",
                    "nested": {
                        "clientSecret": "redacted",
                        "SESSION_TOKEN": "redacted",
                    },
                }
            ),
            ["$.Api-Key", "$.nested.clientSecret", "$.nested.SESSION_TOKEN"],
        )

    def test_provider_patterns_cover_aws_and_slack(self) -> None:
        aws = "AK" + "IA0123456789ABCDEF"
        slack = "xox" + "b-123456789012-" + "abcdefghijklmnopqrstuvwx"
        findings = VALIDATOR.credential_findings(f"{aws}\n{slack}")
        self.assertTrue(any("provider:aws" in finding for finding in findings))
        self.assertTrue(any("provider:slack" in finding for finding in findings))

    def test_entropy_scanner_flags_opaque_candidate(self) -> None:
        opaque = (
            "Q2ZvbjM1dHdQ"
            + "OVJhbmRvbVNl"
            + "Y3JldFZhbHVl"
            + "MTIzNDU2"
        )
        findings = VALIDATOR.credential_findings(opaque)
        self.assertTrue(
            any("high-entropy" in finding for finding in findings)
        )

    def test_entropy_scanner_ignores_hash_and_public_nonce(self) -> None:
        safe_text = (
            "sha256:"
            + ("a1" * 32)
            + "\nMCBUS-20260729-1edbecd55d995f81"
        )
        self.assertEqual(VALIDATOR.credential_findings(safe_text), [])

    def test_entropy_scanner_ignores_typed_public_identifiers(self) -> None:
        drive_id = (
            "1lG__urF-drQL"
            + "RzWujP9wMUhP"
            + "QVYRQPoeJP746dt4g0Q"
        )
        site_id = "appgprj_" + "6a58757f52bc8191a8866f420a3c86ab"
        safe_text = (
            '{"kind": "drive_folder", "id": "'
            + drive_id
            + '", "title": "Public reference"}\n'
            + '{"kind": "site_project", "id": "'
            + site_id
            + '", "title": "Public project"}\n'
            + '"location": "drive_folder:'
            + drive_id
            + '"'
        )
        self.assertEqual(VALIDATOR.credential_findings(safe_text), [])

    def test_command_schema_rejects_untrusted_sender(self) -> None:
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        command["sender"] = "UnknownAgent"
        errors = VALIDATOR.schema_errors(
            command,
            ROOT / "schemas" / "command.schema.json",
            "command",
        )
        self.assertTrue(any("sender" in error for error in errors))

    def test_command_schema_rejects_naive_timestamp(self) -> None:
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        command["created_at"] = "2026-07-29T01:54:56"
        errors = VALIDATOR.schema_errors(
            command,
            ROOT / "schemas" / "command.schema.json",
            "command",
        )
        self.assertTrue(any("created_at" in error for error in errors))

    def test_state_schema_rejects_unknown_status(self) -> None:
        state = VALIDATOR.load_json(ROOT / "bus" / "state" / "current.json")
        state["status"] = "looks_good"
        errors = VALIDATOR.schema_errors(
            state,
            ROOT / "schemas" / "state.schema.json",
            "state",
        )
        self.assertTrue(any("status" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
