import json
import tempfile
import threading
import unittest
from pathlib import Path

from agent_security.console import data, forms, jobs
from agent_security.findings import group_findings, summarize
from agent_security.taxonomy import RULE_INFO


def report(host="www.example.com", batch=None, started="2026-10-22T08:00:00+00:00", groups=(), pages=3, cookies=()):
    grouped = group_findings(
        [
            {
                "severity": severity,
                "rule": rule,
                "title": rule,
                "evidence": "e",
                "expected": "x",
                "remediation": "r",
                "url": f"https://{host}/",
            }
            for rule, severity in groups
        ]
    )
    return {
        "target": f"https://{host}/",
        "started_at": started,
        "status": "partial: page limit (3) reached",
        "route": {"selected": "direct", "attempts": []},
        "scope": {"pages_assessed": pages, "pages_failed": 0},
        "summary": summarize(grouped),
        "groups": grouped,
        "cookies": {"classification": {"status": "not_configured"}, "inventory": list(cookies)},
        **({"batch": batch} if batch else {}),
    }


class DataTests(unittest.TestCase):
    def test_reports_are_loaded_grouped_by_batch_and_corrupt_files_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for name, content in (
                ("site-security-report-a.json", report("a.example.com", {"id": "B1", "index": 1})),
                ("site-security-report-b.json", report("b.example.com", {"id": "B1", "index": 0})),
                ("site-security-report-c.json", report("c.example.com", started="2026-10-23T08:00:00+00:00")),
                ("site-security-report-bad.json", "not json"),
                ("other.json", report("ignored.example.com")),
            ):
                text = content if isinstance(content, str) else json.dumps(content)
                (folder / name).write_text(text, encoding="utf-8")
            entries = data.load_reports(folder)
            batches = data.group_batches(entries)
        self.assertEqual([e.host for e in entries], ["c.example.com", "a.example.com", "b.example.com"])
        self.assertEqual([b.id for b in batches], ["site-security-report-c", "B1"])
        self.assertEqual([e.host for e in batches[1].reports], ["b.example.com", "a.example.com"])
        self.assertIn("b.example.com, a.example.com", batches[1].label)

    def test_domain_row_and_controls(self):
        entry = data.ReportEntry(Path("r.json"), report(groups=[("CSP-000", "High"), ("HDR-PP-001", "Low")]))
        row = data.domain_row(entry)
        self.assertEqual(
            (row["Domínio"], row["Estado"], row["Alto"], row["Baixo"]), ("www.example.com", "Parcial", 1, 1)
        )
        self.assertAlmostEqual(row["Controlos aprovados"], (len(RULE_INFO) - 2) / len(RULE_INFO))
        self.assertEqual(data.controls_passed(report(pages=0)), (0, len(RULE_INFO)))

    def test_bitsight_rows_report_failures_and_positive_only_controls(self):
        rows = {
            r["Avaliação BitSight"]: r["Resultado"]
            for r in data.bitsight_rows(report(groups=[("CSP-000", "High"), ("HDR-HSTS-003", "Info")]))
        }
        self.assertEqual(rows["Content Security Policy Configurations"], "Falha")
        self.assertEqual(rows["Mixed Content"], "Aprovado")
        self.assertEqual(rows["HSTS Preload Directive Present (positive-only)"], "Ausente")
        no_data = data.bitsight_rows(report(pages=0))
        self.assertEqual({r["Resultado"] for r in no_data}, {"Sem dados"})

    def test_reports_from_before_the_bitsight_rules_show_no_data_for_them(self):
        legacy = report(groups=[("CSP-000", "High")])
        del legacy["summary"]["bitsight"]
        rows = {r["Avaliação BitSight"]: r["Resultado"] for r in data.bitsight_rows(legacy)}
        self.assertEqual(rows["Mixed Content"], "Sem dados")
        self.assertEqual(rows["Content Security Policy Configurations"], "Falha")
        self.assertEqual(data.controls_passed(legacy), (len(data.LEGACY_RULES) - 1, len(data.LEGACY_RULES)))
        matrix = {r["Regra"]: r["Resultado"] for r in data.rule_matrix([data.ReportEntry(Path("r.json"), legacy)])}
        self.assertEqual((matrix["MIXED-001"], matrix["HDR-PP-001"]), ("Sem dados", "Aprovado"))

    def test_rule_matrix_and_severity_rows(self):
        entries = [data.ReportEntry(Path("r.json"), report(groups=[("CSP-000", "High")]))]
        matrix = {(r["Regra"], r["Resultado"]) for r in data.rule_matrix(entries)}
        self.assertIn(("CSP-000", "Alto"), matrix)
        self.assertIn(("HDR-PP-001", "Aprovado"), matrix)
        self.assertEqual(
            data.severity_by_domain(entries), [{"Domínio": "www.example.com", "Severidade": "Alto", "Achados": 1}]
        )

    def test_cookie_rows_translate_onetrust_states(self):
        cookies = [
            {
                "name": "a",
                "pages": 2,
                "attributes": "Secure",
                "hosts": ["h"],
                "classification": {"status": "classified", "category": "Necessary", "third_party": False},
            },
            {"name": "b", "pages": 1, "attributes": "", "classification": {"status": "not_found"}},
            {"name": "c", "pages": 1, "attributes": ""},
        ]
        rows = data.cookie_rows(report(cookies=cookies))
        self.assertEqual(
            [(r["Categoria"], r["Origem"]) for r in rows],
            [("Necessary", "Própria"), ("Não encontrado na OneTrust", "—"), ("Não classificado", "—")],
        )


class PlanStateTests(unittest.TestCase):
    def test_action_state_is_merged_and_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            self.assertEqual(data.load_plan_state(folder), {})
            data.save_action_state(folder, "CSP-002", status="Em curso")
            data.save_action_state(folder, "CSP-002", note="ticket 42")
            state = data.load_plan_state(folder)
            self.assertEqual((state["CSP-002"]["status"], state["CSP-002"]["note"]), ("Em curso", "ticket 42"))
            self.assertIn("updated_at", state["CSP-002"])
            (folder / data.PLAN_STATE_FILE).write_text("corrupt", encoding="utf-8")
            self.assertEqual(data.load_plan_state(folder), {})

    def test_platform_rows_mark_reports_without_detection(self):
        new = data.ReportEntry(Path("a.json"), {**report("a.example.com"), "platform": {"cdn": "Fastly", "cms": "AEM"}})
        old = data.ReportEntry(Path("b.json"), report("b.example.com"))
        rows = data.platform_rows([new, old])
        self.assertEqual((rows[0]["CDN"], rows[0]["CMS"]), ("Fastly", "AEM"))
        self.assertEqual(rows[1]["CMS"], "Não detetado (análise anterior)")


class FormTests(unittest.TestCase):
    ENV = {"ONETRUST_HOSTNAME": "app-eu.onetrust.com", "ONETRUST_CLIENT_ID": "id", "ONETRUST_CLIENT_SECRET": "s"}

    def test_one_config_per_domain_with_its_own_extra_hosts(self):
        configs = forms.build_configs(
            [("www.example.com", "shop.example.com, cdn.example.com"), ("example.org", ""), ("", "")],
            forms.ScanOptions(max_pages=5, route="direct"),
            self.ENV,
        )
        self.assertEqual([c.host for c in configs], ["www.example.com", "example.org"])
        self.assertEqual(
            configs[0].allowed_hosts, frozenset({"www.example.com", "shop.example.com", "cdn.example.com"})
        )
        self.assertEqual(configs[1].allowed_hosts, frozenset({"example.org"}))
        self.assertTrue(configs[0].no_proxy)
        self.assertEqual(configs[0].onetrust.hostname, "app-eu.onetrust.com")

    def test_domain_lines_carry_their_extra_hosts(self):
        text = "www.example.com shop.example.com,\tcdn.example.com\n\n  # comment\nexample.org # main site\n"
        self.assertEqual(
            forms.parse_domain_lines(text),
            [("www.example.com", "shop.example.com,cdn.example.com"), ("example.org", "")],
        )
        self.assertEqual(forms.parse_domain_lines(None), [])

    def test_options_are_validated(self):
        options = forms.ScanOptions()
        for rows, opts in (
            ([], options),
            ([("http://insecure.example.com", "")], options),
            ([("www.example.com", ""), ("WWW.example.com", "")], options),
            ([("www.example.com", "10.0.0.1")], options),
            ([("www.example.com", "")], forms.ScanOptions(route="proxy")),
            ([("www.example.com", "")], forms.ScanOptions(ca_bundle="missing.pem")),
        ):
            with self.assertRaises(ValueError, msg=rows):
                forms.build_configs(rows, opts, {})

    def test_cookie_classification_can_be_turned_off(self):
        [config] = forms.build_configs([("www.example.com", "")], forms.ScanOptions(classify_cookies=False), self.ENV)
        self.assertIsNone(config.onetrust)


class JobTests(unittest.TestCase):
    def configs(self):
        return forms.build_configs([("a.example.com", ""), ("b.example.com", "")], forms.ScanOptions(), {})

    def test_job_tracks_each_domain(self):
        def runner(configs, output_dir, progress, on_start, stop, on_done, batch_id):
            for index, config in enumerate(configs):
                on_start(index, config)
                progress(index, 7, {"requested_url": config.start_url})
                on_done(index, {"status": "complete: ok", "distinct_findings": 2, "json": "r.json"})
            return []

        job = jobs.JobRegistry().start(self.configs(), Path("reports"), runner)
        job._thread.join(5)
        self.assertFalse(job.running)
        self.assertEqual([(d.state, d.pages, d.findings) for d in job.domains], [("done", 7, 2), ("done", 7, 2)])

    def test_cancel_stops_the_crawl_and_the_remaining_domains(self):
        started = threading.Event()

        def runner(configs, output_dir, progress, on_start, stop, on_done, batch_id):
            on_start(0, configs[0])
            started.set()
            while True:
                try:
                    progress(0, 1, {"requested_url": configs[0].start_url})
                except KeyboardInterrupt:
                    on_done(0, {"status": "partial: interrupted by user"})
                    break
            if stop():
                on_done(1, {"status": "not run: cancelled"})
            return []

        registry = jobs.JobRegistry()
        job = registry.start(self.configs(), Path("reports"), runner)
        started.wait(5)
        job.cancel()
        job._thread.join(5)
        self.assertEqual([d.state for d in job.domains], ["cancelled", "cancelled"])

    def test_only_one_job_runs_at_a_time(self):
        release = threading.Event()

        def runner(*args, **kwargs):
            release.wait(5)
            return []

        registry = jobs.JobRegistry()
        job = registry.start(self.configs(), Path("reports"), runner)
        with self.assertRaises(RuntimeError):
            registry.start(self.configs(), Path("reports"), runner)
        release.set()
        job._thread.join(5)
        self.assertIsNot(registry.start(self.configs(), Path("reports"), runner), job)
        release.set()

    def test_runner_errors_are_kept_on_the_job(self):
        def runner(*args, **kwargs):
            raise RuntimeError("boom")

        job = jobs.JobRegistry().start(self.configs(), Path("reports"), runner)
        job._thread.join(5)
        self.assertIn("boom", job.error)
        self.assertFalse(job.running)


if __name__ == "__main__":
    unittest.main()
