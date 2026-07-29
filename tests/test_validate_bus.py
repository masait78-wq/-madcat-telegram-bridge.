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


if __name__ == "__main__":
    unittest.main()
