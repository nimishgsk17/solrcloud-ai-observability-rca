"""Test the LangGraph dossier/validator without a model or network.

If the optional langgraph library is installed, also run actual graph traversal.
"""
import importlib.util
import unittest
from agent import prepare_evidence, check_response, apply_confidence_policy, fallback, investigate
from tests.test_project import run_case


class AgentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report, _ = run_case("gc")
        cls.report = report
        cls.incident = report["incidents"][0]
        cls.dossier = prepare_evidence(cls.incident, report["events"])

    def valid_candidate(self):
        return {"hypotheses": [{
            "cause": "GC pressure could contribute to latency",
            "reason": "A long pause overlaps with delayed queries but causality is not proven",
            "evidence_ids": [self.dossier["observations"][0]["id"]], "confidence": "low"}],
            "potential_impact": "Some searches may be slow; customer impact is not measured",
            "manual_checks": ["Compare exact GC pause intervals and request traces"],
            "limitations": "Only log-based evidence is present"}

    def test_dossier(self):
        self.assertTrue(self.dossier["observations"])
        self.assertTrue(self.dossier["runbook_checks"])
        self.assertTrue({e["id"] for e in self.dossier["observations"]}.issubset(self.incident["evidence_ids"]))

    def test_valid_candidate(self):
        self.assertEqual(check_response(self.valid_candidate(), self.dossier), "")

    def test_reject_fake_evidence(self):
        fake = self.valid_candidate()
        fake["hypotheses"][0]["evidence_ids"] = ["invented-id"]
        self.assertIn("invented", check_response(fake, self.dossier))

    def test_reject_overconfident(self):
        fake = self.valid_candidate()
        fake["hypotheses"][0]["confidence"] = "high"
        self.assertIn("Confidence", check_response(fake, self.dossier))

    def test_confidence_cap_is_disclosed(self):
        proposal = self.valid_candidate()
        proposal["hypotheses"][0]["confidence"] = "high"
        fixed, notes = apply_confidence_policy(proposal, self.dossier)
        self.assertEqual(fixed["hypotheses"][0]["confidence"], self.dossier["detector_confidence"])
        self.assertTrue(notes)
        self.assertEqual(check_response(fixed, self.dossier), "")

    def test_missing_confidence_defaults_low_transparently(self):
        proposal = self.valid_candidate()
        proposal["hypotheses"][0].pop("confidence")
        fixed, notes = apply_confidence_policy(proposal, self.dossier)
        self.assertEqual(fixed["hypotheses"][0]["confidence"], "low")
        self.assertTrue(notes)

    def test_confidence_normalization_does_not_invent_evidence(self):
        proposal = self.valid_candidate()
        proposal["hypotheses"][0]["confidence"] = "high"
        proposal["hypotheses"][0]["evidence_ids"] = ["nonexistent"]
        fixed, notes = apply_confidence_policy(proposal, self.dossier)
        self.assertIn("invented", check_response(fixed, self.dossier))

    @unittest.skipUnless(importlib.util.find_spec("langgraph"), "LangGraph not installed here")
    def test_graph_capped_confidence_publish(self):
        def overconfident(dossier, feedback):
            if dossier.get("stage") == "triage":
                return {"preliminary_hypothesis": "Possible JVM memory pressure affecting logged queries",
                        "evidence_ids": [dossier["observations"][0]["id"]],
                        "requested_check": "gc_query_timeline",
                        "why_this_check": "Compare GC and latency minute-level summaries"}
            proposal = self.valid_candidate()
            proposal["hypotheses"][0]["confidence"] = "high"
            return proposal
        out = investigate(self.incident, self.report["events"], overconfident)
        self.assertEqual(out["report"]["status"], "AI_PROPOSAL_REQUIRES_HUMAN_REVIEW")
        self.assertTrue(out["report"]["confidence_adjustments"])
        self.assertEqual(out["report"]["diagnostic"]["check"], "gc_query_timeline")

    def test_fallback(self):
        self.assertEqual(fallback(self.incident)["severity"], self.incident["severity"])

    @unittest.skipUnless(importlib.util.find_spec("langgraph"), "LangGraph not installed here")
    def test_graph_valid_path(self):
        from agent import practice_model
        result = investigate(self.incident, self.report["events"], practice_model)
        self.assertEqual(result["report"]["status"], "AI_PROPOSAL_REQUIRES_HUMAN_REVIEW")
        self.assertEqual(len(result["graph_steps"]), 5)
        self.assertEqual(result["report"]["diagnostic"]["check"], "gc_query_timeline")

    @unittest.skipUnless(importlib.util.find_spec("langgraph"), "LangGraph not installed here")
    def test_graph_retry_fallback(self):
        calls = []
        def bad_model(dossier, feedback):
            calls.append(1)
            return {"hypotheses": []}
        result = investigate(self.incident, self.report["events"], bad_model)
        self.assertEqual(len(calls), 2)  # triage attempt + 1 retry, never runs diagnostics
        self.assertEqual(result["report"]["status"], "RULE_BASED_FALLBACK")


if __name__ == "__main__":
    unittest.main()
