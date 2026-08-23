import base64
import copy
import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_bus",
    ROOT / "scripts" / "validate_bus.py",
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def signer_fixture(
    private_key: Ed25519PrivateKey,
    *,
    status: str = "active",
    valid_from: str = "2026-07-01T00:00:00Z",
    valid_until: str | None = "2026-08-01T00:00:00Z",
) -> dict:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    registry = VALIDATOR.load_json(ROOT / "trust" / "receipt-signers.json")
    registry["keys"] = [
        {
            "key_id": "grok-ed25519-test-1",
            "principal": "Grok",
            "public_key": base64url(public_key),
            "public_key_sha256": "sha256:" + hashlib.sha256(public_key).hexdigest(),
            "status": status,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "revoked_at": "2026-07-15T00:00:00Z"
            if status == "revoked"
            else None,
        }
    ]
    return registry


def signed_result_fixture(
    command: dict,
    private_key: Ed25519PrivateKey,
) -> dict:
    result = {
        "schema_version": 2,
        "protocol": "MADCAT-SHARED-BUS-1.0",
        "result_id": f"{command['command_id']}-RESULT",
        "command_id": command["command_id"],
        "completed_at": "2026-07-30T00:00:00Z",
        "agent": "Grok",
        "status": "blocked",
        "observed_command_hash": command["command_hash"],
        "nonce": command["nonce"],
        "summary": "Synthetic signed receipt fixture; no external action.",
        "checks": [],
        "external_actions": [],
        "credits_spent": 0,
        "signature": {
            "version": 1,
            "algorithm": "Ed25519",
            "key_id": "grok-ed25519-test-1",
            "value": "A" * 86,
        },
        "result_hash": "sha256:" + ("0" * 64),
    }
    result["signature"]["value"] = base64url(
        private_key.sign(VALIDATOR.receipt_signing_bytes(result))
    )
    result["result_hash"] = VALIDATOR.canonical_hash(result, "result_hash")
    return result


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

    def test_historical_inbox_rejects_mutation_with_recomputed_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            command_path = root / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
            command = VALIDATOR.load_json(command_path)
            command["status"] = "cancelled"
            command["command_hash"] = VALIDATOR.canonical_hash(
                command,
                "command_hash",
            )
            command_path.write_text(
                json.dumps(command, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            errors = VALIDATOR.validate_repository(root)
            self.assertIn(
                "bus/inbox/MC-BUS-CANARY-001.json: pinned historical content SHA-256 mismatch",
                errors,
            )
            self.assertIn(
                "bus/inbox/MC-BUS-CANARY-001.json: pinned historical Git blob mismatch",
                errors,
            )

    def test_historical_inbox_rejects_added_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            extra_path = root / "bus" / "inbox" / "UNPINNED.JSON"
            extra_path.write_text("{}\n", encoding="utf-8")
            self.assertIn(
                "bus/inbox/UNPINNED.JSON: unexpected historical inbox path",
                VALIDATOR.validate_repository(root),
            )

    def test_historical_inbox_rejects_missing_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            missing_path = root / "bus" / "inbox" / "TLV-CH01-RENDER-001.json"
            missing_path.unlink()
            self.assertIn(
                "bus/inbox/TLV-CH01-RENDER-001.json: pinned historical inbox file is missing",
                VALIDATOR.validate_repository(root),
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

    def test_production_registry_is_fail_closed_without_fabricated_key(self) -> None:
        registry = VALIDATOR.load_json(ROOT / "trust" / "receipt-signers.json")
        self.assertEqual(registry["keys"], [])
        self.assertEqual(VALIDATOR.signer_registry_errors(registry), [])

    def test_valid_ed25519_receipt_is_rejected_while_disabled(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        registry = signer_fixture(private_key)
        result = signed_result_fixture(command, private_key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            (root / "trust" / "receipt-signers.json").write_text(
                json.dumps(registry, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            outbox = root / "bus" / "outbox"
            outbox.mkdir()
            (outbox / f"{result['result_id']}.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            errors = VALIDATOR.validate_repository(root)
            self.assertTrue(
                any("receipt_acceptance_disabled" in error for error in errors)
            )
            self.assertTrue(
                any("signer registry must remain empty" in error for error in errors)
            )

    def test_nested_case_variant_json_outbox_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            nested = root / "bus" / "outbox" / "nested"
            nested.mkdir(parents=True)
            (nested / "FORGED.JSON").write_text("{}\n", encoding="utf-8")
            self.assertIn(
                "bus/outbox/nested/FORGED.JSON: receipt_acceptance_disabled",
                VALIDATOR.validate_repository(root),
            )

    def test_every_file_type_in_case_variant_outbox_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            nested = root / "bus" / "OutBoX" / "nested"
            nested.mkdir(parents=True)
            (nested / "receipt.BIN").write_bytes(b"not-json")
            self.assertIn(
                "bus/OutBoX/nested/receipt.BIN: receipt_acceptance_disabled",
                VALIDATOR.validate_repository(root),
            )

    def test_uppercase_bus_component_cannot_bypass_disabled_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            outbox = root / "BUS" / "outbox"
            outbox.mkdir(parents=True)
            (outbox / "receipt.txt").write_text("not-json\n", encoding="utf-8")
            errors = VALIDATOR.validate_repository(root)
            self.assertIn(
                "BUS/outbox/receipt.txt: receipt_acceptance_disabled",
                errors,
            )
            self.assertIn("BUS: case-variant bus path is forbidden", errors)

    def test_mixed_case_bus_and_uppercase_outbox_cannot_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            nested = root / "Bus" / "OUTBOX" / "nested"
            nested.mkdir(parents=True)
            (nested / "FORGED.JSON").write_text("{}\n", encoding="utf-8")
            errors = VALIDATOR.validate_repository(root)
            self.assertIn(
                "Bus/OUTBOX/nested/FORGED.JSON: receipt_acceptance_disabled",
                errors,
            )
            self.assertIn("Bus: case-variant bus path is forbidden", errors)
            self.assertIn(
                "Bus/OUTBOX: case-variant outbox path is forbidden",
                errors,
            )

    def test_case_variant_bus_symlink_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            (root / "BUS").symlink_to(root / "bus", target_is_directory=True)
            errors = VALIDATOR.validate_repository(root)
            self.assertIn("BUS: case-variant bus path is forbidden", errors)
            self.assertIn("BUS: bus path symlinks are forbidden", errors)

    def test_outbox_file_anomaly_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            (root / "bus" / "OUTBOX").write_text("not-a-directory\n", encoding="utf-8")
            errors = VALIDATOR.validate_repository(root)
            self.assertIn("bus/OUTBOX: receipt_acceptance_disabled", errors)
            self.assertIn("bus/OUTBOX: outbox path must be a directory", errors)

    def test_forged_receipt_with_recomputed_hash_is_rejected(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        registry = signer_fixture(private_key)
        result = signed_result_fixture(command, private_key)
        result["summary"] = "Forged claim."
        result["result_hash"] = VALIDATOR.canonical_hash(result, "result_hash")
        errors = VALIDATOR.receipt_authentication_errors(result, registry)
        self.assertIn("receipt_signature_invalid", errors)

    def test_unknown_signer_key_is_rejected(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        registry = signer_fixture(private_key)
        result = signed_result_fixture(command, private_key)
        result["signature"]["key_id"] = "grok-ed25519-unknown"
        result["result_hash"] = VALIDATOR.canonical_hash(result, "result_hash")
        errors = VALIDATOR.receipt_authentication_errors(result, registry)
        self.assertIn("unknown_signer_key", errors)

    def test_policy_rejects_non_null_replay_store(self) -> None:
        policy = VALIDATOR.load_json(ROOT / "config" / "acceptance-policy.json")
        policy["replay_store"] = "memory://unsafe"
        self.assertIn(
            "replay_store must remain None",
            VALIDATOR.acceptance_policy_errors(policy),
        )

    def test_policy_rejects_in_memory_replay_fallback(self) -> None:
        policy = VALIDATOR.load_json(ROOT / "config" / "acceptance-policy.json")
        policy["in_memory_replay_fallback_allowed"] = True
        self.assertIn(
            "in_memory_replay_fallback_allowed must remain False",
            VALIDATOR.acceptance_policy_errors(policy),
        )

    def test_policy_rejects_non_retired_private_control(self) -> None:
        policy = VALIDATOR.load_json(ROOT / "config" / "acceptance-policy.json")
        policy["private_control_mode"] = "active"
        self.assertIn(
            "private_control_mode must remain 'retired_no_append'",
            VALIDATOR.acceptance_policy_errors(policy),
        )

    def test_ready_state_is_rejected_while_acceptance_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            shutil.copytree(
                ROOT,
                root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
            )
            state_path = root / "bus" / "state" / "current.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            state["status"] = "ready"
            state_path.write_text(
                json.dumps(state, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            errors = VALIDATOR.validate_repository(root)
            self.assertTrue(
                any("status must remain paused" in error for error in errors)
            )

    def test_revoked_signer_key_is_rejected(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        result = signed_result_fixture(command, private_key)
        registry = signer_fixture(private_key, status="revoked")
        errors = VALIDATOR.receipt_authentication_errors(result, registry)
        self.assertIn("signer_key_not_active", errors)

    def test_receipt_outside_key_validity_window_is_rejected(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        result = signed_result_fixture(command, private_key)
        registry = signer_fixture(
            private_key,
            valid_until="2026-07-29T00:00:00Z",
        )
        errors = VALIDATOR.receipt_authentication_errors(result, registry)
        self.assertIn("receipt_postdates_signer_key", errors)

    def test_signature_metadata_tamper_is_rejected(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        registry = signer_fixture(private_key)
        result = signed_result_fixture(command, private_key)
        result["signature"]["version"] = 2
        errors = VALIDATOR.receipt_authentication_errors(result, registry)
        self.assertIn("receipt_signature_version_unsupported", errors)
        self.assertIn("receipt_signature_invalid", errors)

    def test_result_schema_rejects_missing_signature(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        command = VALIDATOR.load_json(
            ROOT / "bus" / "inbox" / "MC-BUS-CANARY-001.json"
        )
        result = signed_result_fixture(command, private_key)
        del result["signature"]
        errors = VALIDATOR.schema_errors(
            result,
            ROOT / "schemas" / "result.schema.json",
            "result",
        )
        self.assertTrue(any("signature" in error for error in errors))

    def test_signer_registry_rejects_public_key_fingerprint_drift(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        registry = signer_fixture(private_key)
        registry["keys"][0]["public_key_sha256"] = "sha256:" + ("0" * 64)
        errors = VALIDATOR.signer_registry_errors(registry)
        self.assertIn("keys[0]: public key fingerprint mismatch", errors)

    def test_signer_registry_rejects_duplicate_public_key_alias(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        registry = signer_fixture(private_key)
        alias = copy.deepcopy(registry["keys"][0])
        alias["key_id"] = "grok-ed25519-test-alias"
        registry["keys"].append(alias)
        errors = VALIDATOR.signer_registry_errors(registry)
        self.assertIn("keys[1]: duplicate public key", errors)


if __name__ == "__main__":
    unittest.main()
