#!/usr/bin/env python3
import copy
import json
import pathlib
import unittest

import importlib.util

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("preflight", HERE / "preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
EXAMPLE = json.loads((HERE.parent.parent / "examples" / "preflight.example.json").read_text())


def with_(**changes):
    d = copy.deepcopy(EXAMPLE)
    d.update(changes)
    return d


class PreflightTests(unittest.TestCase):
    def test_example_proceeds(self):
        self.assertEqual(preflight.check(EXAMPLE)["verdict"], "PROCEED")

    def test_more_reasoning_never_buys_authority(self):
        r = preflight.check(with_(consequence_class="consequential",
                                  authority={"holder": "agent", "state": "INFERRED", "action": "merge"}))
        self.assertEqual(r["verdict"], "BLOCKED")
        self.assertTrue(any("needs VERIFIED authority" in b for b in r["blocked"]))

    def test_mode_cannot_promote_itself(self):
        r = preflight.check(with_(planes={"reasoning_mode": "ULTRATHINK", "requested_authority_change": True}))
        self.assertEqual(r["verdict"], "BLOCKED")

    def test_blank_field_blocks_but_unknown_is_honest(self):
        self.assertEqual(preflight.check(with_(bottleneck=""))["verdict"], "BLOCKED")
        self.assertEqual(preflight.check(with_(bottleneck="UNKNOWN"))["verdict"], "PROCEED")

    def test_failed_premise_narrows(self):
        d = with_(devil_i={"premise_holds": False, "falsifier": "flaky on main too"})
        self.assertEqual(preflight.check(d)["verdict"], "NARROW")

    def test_more_than_three_options_narrows_unless_breadth_requested(self):
        opts = EXAMPLE["options"] + [dict(EXAMPLE["options"][0], name=f"o{i}") for i in range(2)]
        self.assertEqual(preflight.check(with_(options=opts))["verdict"], "NARROW")
        self.assertEqual(preflight.check(with_(options=opts, breadth_requested=True))["verdict"], "PROCEED")

    def test_option_missing_proof_blocks(self):
        bad = dict(EXAMPLE["options"][0])
        del bad["proof_required"]
        self.assertEqual(preflight.check(with_(options=[bad]))["verdict"], "BLOCKED")

    def test_devil_ii_required_before_mutation(self):
        d = with_()
        del d["devil_ii"]
        self.assertEqual(preflight.check(d)["verdict"], "BLOCKED")

    def test_informational_skips_devil_gates(self):
        d = with_(consequence_class="informational", options=[], selected=None)
        del d["devil_i"], d["devil_ii"]
        self.assertEqual(preflight.check(d)["verdict"], "PROCEED")

    def test_repair_budget_requires_evidence_and_positive_rounds(self):
        b = dict(EXAMPLE["budget"], require_evidence=False)
        self.assertEqual(preflight.check(with_(budget=b))["verdict"], "BLOCKED")
        b = dict(EXAMPLE["budget"], max_rounds=0)
        self.assertEqual(preflight.check(with_(budget=b))["verdict"], "BLOCKED")
        b = dict(EXAMPLE["budget"], max_rounds=True)
        self.assertEqual(preflight.check(with_(budget=b))["verdict"], "BLOCKED")

    def test_garbage_input_blocks_cleanly(self):
        for junk in ([], "x", None, {"budget": "lots"}):
            self.assertEqual(preflight.check(junk)["verdict"], "BLOCKED")

    def test_cli_exit_codes(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "p.json")
            for doc, code in ((EXAMPLE, 0), (with_(devil_i={"premise_holds": False, "falsifier": "x"}), 1), ({}, 2)):
                with open(p, "w") as f:
                    json.dump(doc, f)
                self.assertEqual(preflight.main([p, "--compact"]), code)


if __name__ == "__main__":
    unittest.main()
