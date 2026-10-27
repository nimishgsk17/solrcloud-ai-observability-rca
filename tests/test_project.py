"""Focused regression suite for the simplified project, no external services."""
import unittest
from generate_logs import gen
from analyzer import analyze
from parser import parse_line


def run_case(case: str, seed: int = 23, rate: int = 22):
    logs, truth, topology = gen(case, seed=seed, rate=rate)
    sources = [{"filename": name, "node": name.rsplit("_", 1)[0],
                "source": name.rsplit("_", 1)[1].split(".")[0], "text": text}
               for name, text in logs.items()]
    return analyze(sources, topology=topology), truth


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {case: run_case(case) for case in
                       ["normal", "gc", "zk", "slow_no_gc", "benign_zk", "oom", "independent", "mixed"]}

    def test_normal(self):
        report, _ = self.results["normal"]
        self.assertEqual(report["incidents"], [])

    def test_gc(self):
        report, _ = self.results["gc"]
        self.assertEqual(len(report["incidents"]), 1)
        self.assertIn("gc_pause", report["incidents"][0]["anomalies"])

    def test_zookeeper_cross_node(self):
        report, _ = self.results["zk"]
        self.assertEqual(len(report["incidents"]), 1)
        self.assertEqual(set(report["incidents"][0]["nodes"]), {"node-a", "node-b"})

    def test_slow_queries_without_gc(self):
        report, _ = self.results["slow_no_gc"]
        self.assertEqual(len(report["incidents"]), 1)
        self.assertIn("latency_shift", report["incidents"][0]["anomalies"])
        self.assertNotIn("JVM", report["incidents"][0]["root_cause_hypothesis"])

    def test_benign_reconnect(self):
        self.assertEqual(self.results["benign_zk"][0]["incidents"], [])

    def test_oom(self):
        self.assertIn("oom", self.results["oom"][0]["incidents"][0]["anomalies"])

    def test_independent_faults(self):
        inc = self.results["independent"][0]["incidents"]
        self.assertEqual(len(inc), 2)
        self.assertEqual({tuple(i["nodes"]) for i in inc}, {("node-a",), ("node-b",)})

    def test_mixed_faults(self):
        self.assertEqual(len(self.results["mixed"][0]["incidents"]), 2)

    def test_after_gc_memory_not_larger(self):
        for report, _ in self.results.values():
            for event in report["events"]:
                measures = event["measures"]
                if "before_mb" in measures:
                    self.assertLessEqual(measures["after_mb"], measures["before_mb"])

    def test_seed_is_reproducible(self):
        self.assertEqual(gen("normal", seed=77)[0], gen("normal", seed=77)[0])

    def test_parser_no_false_http_500_from_millisecond(self):
        line = "2026-10-26 10:00:00.500 INFO Request QTime=42 status=0"
        self.assertNotEqual(parse_line(line, "solr", "node-a", "f.log", 1)["kind"], "http_5xx")

    def test_gc_subphase_not_full_pause(self):
        line = "[2026-10-26T10:00:00.000+0000][info][gc,phases] GC(7) Ext Root Scanning 1430.0ms"
        self.assertNotIn("pause_ms", parse_line(line, "gc", "node-a", "gc.log", 1)["measures"])


if __name__ == "__main__":
    unittest.main()
