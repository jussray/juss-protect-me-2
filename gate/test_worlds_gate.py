#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("worlds_gate.py")
spec = importlib.util.spec_from_file_location("worlds_gate", MODULE_PATH)
worlds_gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worlds_gate)


class WorldsPatchRegressionTests(unittest.TestCase):
    def test_cycle_members_excludes_downstream_nodes(self):
        deps = {"A": ["B"], "B": ["A"], "C": ["A"]}
        order, cyclic = worlds_gate.topo_order(deps)
        self.assertEqual(order, [])
        self.assertEqual(cyclic, ["A", "B"])

    def test_downstream_of_cycle_is_blocked_without_false_cycle_attribution(self):
        worlds = [
            {"id": "A", "depends_on": ["B"]},
            {"id": "B", "depends_on": ["A"]},
            {"id": "C", "depends_on": ["A"]},
        ]
        result = worlds_gate.evaluate(worlds, [{"id": "p", "world": "C", "files": ["x.py"]}])["results"][0]
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(any("upstream dependency cycle involves: A, B" in reason for reason in result["blocked"]))
        self.assertFalse(any("world is in a dependency cycle" in reason for reason in result["blocked"]))

    def test_duplicate_world_ids_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate world id"):
            worlds_gate.evaluate([{"id": "A"}, {"id": "A"}], [])

    def test_blank_evidence_does_not_verify_pass(self):
        worlds = [{
            "id": "A",
            "governance": {"required_checks": ["unit"]},
        }]
        patches = [{
            "id": "p",
            "world": "A",
            "files": ["x.py"],
            "checks": {"unit": {"status": "pass", "evidence": "   "}},
        }]
        result = worlds_gate.evaluate(worlds, patches)["results"][0]
        self.assertEqual(result["status"], "PENDING")
        self.assertEqual(result["proof"], [])
        self.assertTrue(any("UNVERIFIED" in reason for reason in result["pending"]))


    def test_posture_of_example_map(self):
        import json
        doc = json.loads((MODULE_PATH.parent.parent / "examples" / "worlds.example.json").read_text())
        posture = worlds_gate.world_posture(worlds_gate.evaluate(doc["worlds"], []))
        self.assertEqual({k: v["status"] for k, v in posture.items()}, {
            "core-auth": "HEALTHY", "billing": "BLOCKED",
            "app-web": "AT_RISK", "marketing-site": "FROZEN",
        })
        self.assertTrue(posture["app-web"]["next_gate"].startswith("Fix upstream first: billing"))
        self.assertTrue(any("no evidence" in u for u in posture["billing"]["unverified"]))

    def test_posture_never_guesses_missing_fields(self):
        posture = worlds_gate.world_posture(worlds_gate.evaluate([{"id": "bare"}], []))["bare"]
        self.assertEqual(posture["status"], "UNKNOWN")
        for field in ("required_checks", "governance.owner", "governance.merge_policy", "repo not declared"):
            self.assertTrue(any(field in u for u in posture["unknown"]), field)
        self.assertEqual(posture["proof"], [])

    def test_posture_pass_without_evidence_is_not_healthy(self):
        worlds = [{"id": "A", "governance": {"required_checks": ["unit"]},
                   "state": {"checks": {"unit": {"status": "pass"}}}}]
        self.assertEqual(worlds_gate.world_posture(worlds_gate.evaluate(worlds, []))["A"]["status"], "UNVERIFIED")

    def test_posture_cycle_blocks_both_members(self):
        worlds = [{"id": "A", "depends_on": ["B"]}, {"id": "B", "depends_on": ["A"]}]
        posture = worlds_gate.world_posture(worlds_gate.evaluate(worlds, []))
        self.assertEqual(posture["A"]["status"], "BLOCKED")
        self.assertEqual(posture["B"]["status"], "BLOCKED")

    def test_patch_waits_when_upstream_baseline_is_failing(self):
        worlds = [
            {"id": "up", "governance": {"required_checks": ["unit"]},
             "state": {"checks": {"unit": {"status": "fail"}}}},
            {"id": "down", "depends_on": ["up"], "governance": {"required_checks": []}},
        ]
        r = worlds_gate.evaluate(worlds, [{"id": "p", "world": "down", "files": ["a.ts"]}])["results"][0]
        self.assertEqual(r["status"], "PENDING")
        self.assertTrue(any("upstream world 'up' is failing unit" in x for x in r["pending"]))

if __name__ == "__main__":
    unittest.main()
