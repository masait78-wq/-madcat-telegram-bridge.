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
