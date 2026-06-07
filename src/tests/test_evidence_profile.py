import unittest

from src.core.analyzer.evidence_profile import build_evidence_profile, evidence_adjusted_score


class EvidenceProfileTests(unittest.TestCase):
    def test_well_supported_candidate_profile(self) -> None:
        candidate = {
            "binary_path": "/bin/httpd",
            "web_exposed": True,
            "confirmed_input": "query_string",
            "handler_symbols": ["formApply"],
            "confirmed_sink": "system",
            "all_sinks": ["system(cmd)"],
            "attacker_controlled_argument": "confirmed",
            "same_request": "confirmed",
            "auth_boundary": "pre-auth",
            "sanitization": "absent",
            "endpoints": ["/goform/apply"],
        }

        profile = build_evidence_profile(candidate)

        self.assertEqual(profile["review_state"], "well-supported")
        self.assertEqual(profile["field_states"]["entrypoint"], "confirmed")
        self.assertEqual(profile["field_states"]["argument_control"], "confirmed")
        self.assertTrue(profile["evidence_refs"])
        self.assertEqual(evidence_adjusted_score(candidate, 80), 80)

    def test_false_positive_risk_blocks_profile(self) -> None:
        candidate = {
            "binary_path": "/bin/foo",
            "all_sinks": ["system"],
            "false_positive_risks": ["sink_import_only"],
        }

        profile = build_evidence_profile(candidate)

        self.assertEqual(profile["review_state"], "reject-risk")
        blocker_codes = {row["code"] for row in profile["blockers"]}
        self.assertIn("sink_import_only", blocker_codes)
        candidate["evidence_profile"] = profile
        self.assertLess(evidence_adjusted_score(candidate, 90), 40)

    def test_missing_evidence_generates_validation_targets(self) -> None:
        candidate = {
            "binary_path": "/bin/foo",
            "endpoints": ["/cgi-bin/foo"],
            "all_sinks": ["popen(cmd)"],
            "missing_links": ["dispatch_unknown", "attacker_argument_unknown"],
        }

        profile = build_evidence_profile(candidate)

        self.assertEqual(profile["review_state"], "needs-evidence")
        goals = {row["goal"] for row in profile["validation_targets"]}
        self.assertIn("confirm handler dispatch", goals)
        self.assertIn("trace attacker-controlled argument into sink", goals)
        candidate["evidence_profile"] = profile
        self.assertLess(evidence_adjusted_score(candidate, 82), 40)


if __name__ == "__main__":
    unittest.main()
