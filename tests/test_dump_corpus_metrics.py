import json
import tempfile
import unittest
from pathlib import Path
from scripts.dump_corpus_metrics import analyze_corpus, format_text_report


class TestDumpCorpusMetrics(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.tmp_dir.name)
        self.corpus_path = self.base_dir / "test_corpus.json"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_missing_corpus_file_returns_error(self):
        non_existent = self.base_dir / "missing.json"
        res = analyze_corpus(non_existent)
        self.assertFalse(res["exists"])
        self.assertIn("File not found", res["error"])
        out = format_text_report(res)
        self.assertIn("Corpus Error", out)

    def test_analyze_valid_corpus_computes_yield_and_decay(self):
        corpus_data = {
            "unix_sock_fuzzer": {
                "sig_ok_0": 4,
                "sig_trunc_1": 1,
            },
            "path_escape_harness": {
                "sig_veto_0": 2,
            },
        }
        self.corpus_path.write_text(json.dumps(corpus_data), encoding="utf-8")

        metrics = analyze_corpus(self.corpus_path)
        self.assertTrue(metrics["exists"])
        self.assertEqual(metrics["total_signatures"], 3)
        self.assertEqual(metrics["total_observations"], 7)
        # Global yield: 3 / 7 ~ 0.4286
        self.assertAlmostEqual(metrics["global_mutation_yield"], 0.4286, places=3)

        unix_stats = metrics["harnesses"]["unix_sock_fuzzer"]
        self.assertEqual(unix_stats["unique_signatures"], 2)
        self.assertEqual(unix_stats["total_observations"], 5)
        # Mutation yield for unix_sock_fuzzer: 2 / 5 = 0.4
        self.assertEqual(unix_stats["mutation_yield"], 0.4)

        # Check signature decay calculation
        sig_ok = next(s for s in unix_stats["signatures"] if s["signature"] == "sig_ok_0")
        self.assertEqual(sig_ok["occurrences"], 4)
        self.assertEqual(sig_ok["novelty_linear"], 0.25)
        self.assertEqual(sig_ok["novelty_steep"], 0.125)

        # Test text formatter
        report = format_text_report(metrics)
        self.assertIn("DREAM CORPUS METRICS", report)
        self.assertIn("unix_sock_fuzzer", report)
        self.assertIn("Global Mutation Yield: 42.86%", report)


if __name__ == "__main__":
    unittest.main()
