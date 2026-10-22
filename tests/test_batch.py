import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_security import batch
from agent_security.config import ScanConfig


def config(host):
    start = f"https://{host}/"
    return ScanConfig(start_url=start, allowed_hosts=frozenset({host}), seeds=((start, "seed"),))


def fake_scan(cfg, progress=None):
    if progress:
        progress(1, {"requested_url": cfg.start_url, "status": 200, "error": None})
    if "broken" in cfg.start_url:
        raise RuntimeError("boom")
    return {
        "target": cfg.start_url,
        "status": "complete: ok",
        "route": {"selected": "direct"},
        "scope": {"pages_assessed": 1, "pages_failed": 0},
        "groups": [],
    }


class RunBatchTests(unittest.TestCase):
    def run_batch(self, hosts, **kwargs):
        written = []

        def write(report, directory):
            written.append(report)
            return Path("r.html"), Path("r.json")

        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(batch, "run_scan", side_effect=fake_scan),
            mock.patch.object(batch, "write_reports", side_effect=write),
        ):
            rows = batch.run_batch([config(h) for h in hosts], Path(directory), batch_id="B1", **kwargs)
        return rows, written

    def test_each_domain_gets_its_own_report_linked_by_batch(self):
        seen = []
        rows, written = self.run_batch(["a.example.com", "b.example.com"], progress=lambda i, n, r: seen.append(i))
        self.assertEqual([row["target"] for row in rows], ["https://a.example.com/", "https://b.example.com/"])
        self.assertEqual(rows[0]["json"], "r.json")
        self.assertEqual(seen, [0, 1])
        self.assertEqual([r["batch"]["index"] for r in written], [0, 1])
        self.assertEqual({r["batch"]["id"] for r in written}, {"B1"})
        self.assertEqual(written[0]["batch"]["targets"], ["https://a.example.com/", "https://b.example.com/"])

    def test_a_failing_domain_does_not_stop_the_batch(self):
        rows, _ = self.run_batch(["broken.example.com", "b.example.com"])
        self.assertEqual(rows[0]["status"], "failed")
        self.assertIn("boom", rows[0]["error"])
        self.assertTrue(rows[1]["status"].startswith("complete"))

    def test_stop_skips_the_remaining_domains(self):
        rows, written = self.run_batch(["a.example.com", "b.example.com"], stop=lambda: True)
        self.assertEqual([row["status"] for row in rows], ["not run: cancelled"] * 2)
        self.assertEqual(written, [])

    def test_cancellation_is_seen_by_the_crawler_as_an_interruption(self):
        self.assertTrue(issubclass(batch.ScanCancelled, KeyboardInterrupt))


if __name__ == "__main__":
    unittest.main()
