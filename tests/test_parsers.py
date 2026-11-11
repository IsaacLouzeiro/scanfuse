import csv
import re
import shutil
import string
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scanfuse as sf

FIX = Path(__file__).parent / "fixtures" / "raw" / "legacy.example_443"
ALL_FILES = ["findings.csv", "matrix.csv", "technologies.csv", "report.html", "report.md"]


def by_check(findings):
    return {f.check: f for f in findings}


def fixture_findings():
    return sf.parse_target_dir(FIX)


class Parsers(unittest.TestCase):
    def test_sslscan(self):
        r = by_check(sf.parse_sslscan("x", FIX / "sslscan.xml"))
        for c in ["protocol:SSLv3", "protocol:TLSv1.0", "protocol:TLSv1.1", "no_tls13",
                  "heartbleed", "insecure_renegotiation", "no_fallback_scsv", "cert_expired",
                  "cert_self_signed", "cert_weak_signature", "cert_weak_key",
                  "weak_ciphers", "medium_ciphers"]:
            self.assertEqual(r[c].status, sf.VULN, c)
            self.assertIn(r[c].severity, sf.SEVERITIES, c)
        self.assertEqual(r["protocol:SSLv2"].status, sf.OK)
        self.assertEqual(r["protocol:SSLv2"].severity, "")
        self.assertEqual(r["tls_compression"].status, sf.OK)
        self.assertEqual(r["protocol:SSLv3"].severity, "high")
        self.assertIn("RC4-SHA", r["weak_ciphers"].evidence)

    def test_shcheck(self):
        r = by_check(sf.parse_shcheck("x", FIX / "shcheck.json"))
        self.assertEqual(r["header:X-Frame-Options"].status, sf.OK)
        hsts = r["header:Strict-Transport-Security"]
        self.assertEqual((hsts.status, hsts.severity, hsts.msg), (sf.VULN, "low", "hsts_low"))
        self.assertEqual(r["header:Content-Security-Policy"].msg, "csp_weak")
        ref = r["header:Referrer-Policy"]
        self.assertEqual((ref.status, ref.severity, ref.msg), (sf.VULN, "low", "header_missing"))
        self.assertIn("PHP/7.2.24", r["info_disclosure"].evidence)

    def test_csp_wildcard_detection(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        cases = {
            "default-src 'self' *.example.org https://cdn.example.org": sf.OK,
            "default-src *": sf.VULN,
            "default-src 'self'; img-src *; script-src 'self'": sf.VULN,
            "script-src 'self' 'unsafe-eval'": sf.VULN,
        }
        for csp, expected in cases.items():
            p = tmp / "shcheck.json"
            p.write_text(sf.json.dumps({"https://a": {"present": {"Content-Security-Policy": csp}}}))
            r = by_check(sf.parse_shcheck("x", p))
            self.assertEqual(r["header:Content-Security-Policy"].status, expected, csp)

    def test_wafw00f(self):
        (f,) = sf.parse_wafw00f("x", FIX / "wafw00f.json")
        self.assertEqual((f.status, f.severity), (sf.VULN, "low"))

    def test_whatweb(self):
        (f,), techs = sf.parse_whatweb("x", FIX / "whatweb.json")
        self.assertEqual(f.status, sf.VULN)
        names = {t["technology"] for t in techs}
        self.assertTrue({"Apache", "PHP", "WordPress", "JQuery"} <= names)
        self.assertNotIn("Country", names)


class Translations(unittest.TestCase):
    def test_languages_have_same_keys(self):
        self.assertEqual(set(sf.I18N["en"]), set(sf.I18N["pt"]))

    def test_placeholders_match(self):
        fmt = string.Formatter()
        for key, en in sf.I18N["en"].items():
            pt = sf.I18N["pt"][key]
            names = lambda s: {n for _, n, _, _ in fmt.parse(s) if n}
            self.assertEqual(names(en), names(pt), key)

    def test_every_check_has_title_and_recommendation(self):
        findings, _ = fixture_findings()
        for lang in sf.LANGS:
            for f in findings:
                self.assertTrue(sf.check_title(f.check, lang), (lang, f.check))
                self.assertNotIn("{", sf.check_title(f.check, lang))
                if f.status == sf.VULN:
                    self.assertTrue(sf.recommendation(f.check, lang), (lang, f.check))
                    self.assertTrue(sf.sev_label(f.severity, lang), (lang, f.check))
        for h in sf.SEC_HEADERS:
            for lang in sf.LANGS:
                self.assertIn(f"rec.header:{h}", sf.I18N[lang])

    def test_parse_lang(self):
        self.assertEqual(sf.parse_lang("PT-BR"), "pt")
        self.assertEqual(sf.parse_lang("en"), "en")
        with self.assertRaises(sf.argparse.ArgumentTypeError):
            sf.parse_lang("es")


class EndToEnd(unittest.TestCase):
    def _reparse(self, *extra):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(FIX.parent, tmp / "raw")
        self.assertEqual(sf.main(["--reparse", str(tmp), "-q", *extra]), 0)
        return tmp

    def _csv(self, path, delim):
        with open(path, encoding="utf-8-sig", newline="") as fh:
            return list(csv.reader(fh, delimiter=delim))

    def test_default_is_all_formats_in_english(self):
        tmp = self._reparse()
        for n in ALL_FILES:
            self.assertTrue((tmp / n).exists(), n)
        rows = self._csv(tmp / "matrix.csv", ",")
        self.assertEqual(rows[0][:2], ["target", "total_vulns"])
        self.assertEqual(rows[1][0], "https://legacy.example")
        self.assertGreater(int(rows[1][1]), 15)
        self.assertIn("YES", rows[1])
        findings = self._csv(tmp / "findings.csv", ",")
        self.assertEqual(findings[0], ["target", "tool", "category", "check", "vulnerable",
                                       "severity", "detail", "recommendation"])
        self.assertTrue(all(len(r) == 8 for r in findings))
        h = (tmp / "report.html").read_text(encoding="utf-8")
        self.assertIn('<html lang="en">', h)
        self.assertIn("Executive summary", h)
        self.assertIn("SSLv3 enabled", h)
        self.assertIn("WordPress", h)
        m = (tmp / "report.md").read_text(encoding="utf-8")
        self.assertIn("## 2. Findings", m)
        self.assertIn("Recommendation", m)
        self.assertIn("RC4-SHA", m)

    def test_portuguese_reports(self):
        tmp = self._reparse("--lang", "pt")
        rows = self._csv(tmp / "matrix.csv", ";")
        self.assertEqual(rows[0][:2], ["alvo", "total_vulns"])
        self.assertIn("SIM", rows[1])
        self.assertIn("NÃO", rows[1])
        techs = self._csv(tmp / "technologies.csv", ";")
        self.assertEqual(techs[0], ["alvo", "url", "tecnologia", "versao", "detalhe"])
        h = (tmp / "report.html").read_text(encoding="utf-8")
        self.assertIn('<html lang="pt-BR">', h)
        self.assertIn("Resumo executivo", h)
        self.assertIn("SSLv3 habilitado", h)
        self.assertNotIn("Executive summary", h)
        m = (tmp / "report.md").read_text(encoding="utf-8")
        self.assertIn("## 2. Achados", m)
        self.assertIn("Recomendação", m)

    def test_html_counts_match_findings(self):
        tmp = self._reparse()
        findings, _ = fixture_findings()
        vulns = [f for f in findings if f.status == sf.VULN]
        h = (tmp / "report.html").read_text(encoding="utf-8")
        self.assertEqual(h.count('<article class="finding'), len(vulns))
        self.assertEqual(len(re.findall(r'class="fid">F-\d+<', h)), len(vulns))
        for s in sf.SEVERITIES:
            n = sum(f.severity == s for f in vulns)
            label = sf.sev_label(s, "en")
            self.assertIn(f'<div class="sev-card {s}"><span>{label}</span><b>{n}</b></div>', h)
        # findings are listed from most to least severe
        sevs = re.findall(r'<article class="finding (\w+)"', h)
        self.assertEqual(sevs, sorted(sevs, key=sf.sev_rank))

    def test_format_csv_only(self):
        tmp = self._reparse("--format", "csv")
        self.assertTrue((tmp / "matrix.csv").exists())
        self.assertFalse((tmp / "report.html").exists())
        self.assertFalse((tmp / "report.md").exists())

    def test_delimiter_override(self):
        tmp = self._reparse("--format", "csv", "-d", ";")
        self.assertEqual(self._csv(tmp / "matrix.csv", ";")[0][0], "target")

    def test_parse_formats(self):
        self.assertEqual(sf.parse_formats("HTML, markdown,csv,html"), ["html", "md", "csv"])
        self.assertEqual(sf.parse_formats("all"), ["csv", "html", "md"])
        with self.assertRaises(sf.argparse.ArgumentTypeError):
            sf.parse_formats("pdf")
        with self.assertRaises(SystemExit):
            sf.main(["--reparse", "x", "--format", "xls", "-q"])

    def test_reparse_missing_raw_dir(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        with self.assertRaises(SystemExit):
            sf.main(["--reparse", str(tmp), "-q"])

    def test_empty_results(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        (tmp / "raw").mkdir()
        self.assertEqual(sf.main(["--reparse", str(tmp), "-q"]), 0)
        self.assertIn("No results were found.", (tmp / "report.html").read_text(encoding="utf-8"))
        self.assertIn("No results were found.", (tmp / "report.md").read_text(encoding="utf-8"))

    def test_untrusted_content_is_escaped(self):
        evil = sf.Finding("https://a", "shcheck", "Headers", "info_disclosure", sf.VULN, "low",
                          "Server: <script>alert(1)</script> | x\nline2 *b* {evidence}")
        tech = {"target": "https://a", "url": "https://a", "technology": "<img src=x onerror=1>",
                "version": "1|2", "detail": ""}
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for lang in sf.LANGS:
            sf.write_html(tmp, [evil], [tech], lang)
            sf.write_md(tmp, [evil], [tech], lang)
            h = (tmp / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>", h)
            self.assertNotIn("<img", h)
            self.assertIn("&lt;script&gt;", h)
            m = (tmp / "report.md").read_text(encoding="utf-8")
            self.assertNotIn("<script>", m)
            self.assertNotIn("<img", m)
            self.assertIn("\\| x line2 \\*b\\* {evidence}", m)   # finding bullet
            self.assertIn("| 1\\|2 |", m)
            for line in m.splitlines():
                if line.startswith("| ") and "1\\|2" in line:
                    self.assertEqual(len(re.findall(r"(?<!\\)\|", line)), 4)


if __name__ == "__main__":
    unittest.main()
