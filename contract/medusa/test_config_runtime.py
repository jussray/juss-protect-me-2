"""Synthetic offline integration tests: Layer 5 sensor and Layer 6 inert supervisor."""
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import eventbus as BUS
import config_sensor as SENSOR
import medusa_daemon as DAEMON


class ConfigRuntimeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="medusa-config-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        old = {key: os.environ.get(key) for key in
               ("MEDUSA_BUS_DIR", "MEDUSA_TRUSTED_SENSORS", "MEDUSA_LAB_MODE")}
        self.addCleanup(lambda: [
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
            for k, v in old.items()])
        os.environ["MEDUSA_BUS_DIR"] = str(self.root / "bus")
        os.environ["MEDUSA_TRUSTED_SENSORS"] = str(self.root / "trusted.json")
        os.environ["MEDUSA_LAB_MODE"] = "1"
        trusted = {}
        self.keys = {}
        for name in ("config-1", "detect-1"):
            private = Ed25519PrivateKey.generate()
            pem = self.root / (name + ".pem")
            pem.write_bytes(private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            pem.chmod(0o600)
            self.keys[name] = str(pem)
            trusted[name] = base64.b64encode(private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw)).decode("ascii")
        manifest = self.root / "trusted.json"
        manifest.write_text(json.dumps({"sensors": trusted}))
        manifest.chmod(0o600)
        self.file = self.root / "config.txt"
        self.file.write_text("synthetic-private-content")

    def test_first_scan_baseline_then_change_and_no_duplicate(self):
        paths = [str(self.file)]
        first = SENSOR.scan_once(paths, key=self.keys["config-1"])
        self.assertEqual([e["action"] for e in first], ["baseline"])
        self.assertEqual(SENSOR.scan_once(paths, key=self.keys["config-1"]), [])
        self.file.write_text("synthetic-change")
        changed = SENSOR.scan_once(paths, key=self.keys["config-1"])
        self.assertEqual([e["action"] for e in changed], ["modified"])
        self.assertTrue(BUS.verify_chain()["ok"])
        raw = (self.root / "bus" / "events.jsonl").read_text()
        self.assertNotIn("synthetic-private-content", raw)
        self.assertNotIn(str(self.file), raw)

    def test_removed_and_restored_config_are_signed(self):
        path = str(self.file)
        SENSOR.scan_once([path], key=self.keys["config-1"])
        self.file.unlink()
        self.assertEqual(SENSOR.scan_once([path], key=self.keys["config-1"])[0]["action"], "missing")
        self.file.write_text("restored")
        self.assertEqual(SENSOR.scan_once([path], key=self.keys["config-1"])[0]["action"], "restored")

    def test_symlink_and_duplicate_paths_fail_closed(self):
        target = self.root / "link"
        target.symlink_to(self.file)
        with self.assertRaises(BUS.BusError):
            SENSOR.scan_once([str(target)], key=self.keys["config-1"])
        with self.assertRaises(BUS.BusError):
            SENSOR.scan_once([str(self.file), str(self.file)], key=self.keys["config-1"])
        self.assertEqual(len(BUS.read_events()), 0)

    def test_invalid_second_path_never_writes_partial_baseline(self):
        broken = self.root / "bad-link"
        broken.symlink_to(self.file)
        with self.assertRaises(BUS.BusError):
            SENSOR.scan_once([str(self.file), str(broken)], key=self.keys["config-1"])
        self.assertEqual(BUS.read_events(), [])

    def test_supervisor_only_runs_in_lab_and_never_acts(self):
        rules = [{"ruleset_id": "config-test", "version": "1", "rules": [{
            "id": "change", "description": "synthetic config change",
            "severity": "High", "confidence": "medium",
            "confidence_basis": "a registered local sensor observed a change",
            "window_seconds": 0,
            "when": {"all": [
                {"event_type": "config_change"},
                {"where": {"action": "modified"}}
            ]}
        }]}]
        args = dict(paths=[str(self.file)], sensor_key=self.keys["config-1"],
                    rulesets=rules, detect_key=self.keys["detect-1"])
        first = DAEMON.run_once(**args)
        self.assertEqual(first["detections"], [])
        self.file.write_text("modified")
        second = DAEMON.run_once(**args)
        self.assertEqual(len(second["detections"]), 1)
        self.assertFalse(second["can_authorize"])
        self.assertFalse(second["effect_executed"])
        self.assertEqual(second["actuator_state"], "HOLD")
        self.assertTrue(second["chain"]["ok"])
        self.assertTrue(any(x["event"]["event_type"] == "detection_feedback"
                            for x in BUS.read_events()))
        os.environ.pop("MEDUSA_LAB_MODE")
        with self.assertRaisesRegex(BUS.BusError, "LAB_MODE"):
            DAEMON.run_once(**args)


if __name__ == "__main__":
    unittest.main()
