import shutil, sys, tempfile, unittest, csv
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scanfuse as sf

FIX = Path(__file__).parent / "fixtures" / "raw" / "legado.exemplo_443"


def by_check(findings):
    return {f.verificacao: f for f in findings}


class Parsers(unittest.TestCase):
    def test_sslscan(self):
        r = by_check(sf.parse_sslscan("x", FIX / "sslscan.xml"))
        for c in ["SSLv3 habilitado", "TLSv1.0 habilitado", "TLSv1.1 habilitado",
                  "TLSv1.3 não suportado", "Heartbleed (CVE-2014-0160)", "Renegociação insegura",
                  "Sem TLS_FALLBACK_SCSV", "Certificado expirado", "Certificado autoassinado",
                  "Assinatura fraca do certificado (MD5/SHA1)", "Chave do certificado fraca",
                  "Cifras fracas (NULL/EXPORT/RC4/DES/anon)", "Cifras médias (ex: 3DES, CBC sem PFS)"]:
            self.assertEqual(r[c].vulneravel, sf.SIM, c)
        self.assertEqual(r["SSLv2 habilitado"].vulneravel, sf.NAO)
        self.assertEqual(r["Compressão TLS (CRIME)"].vulneravel, sf.NAO)
        self.assertIn("RC4-SHA", r["Cifras fracas (NULL/EXPORT/RC4/DES/anon)"].detalhe)

    def test_shcheck(self):
        r = by_check(sf.parse_shcheck("x", FIX / "shcheck.json"))
        self.assertEqual(r["Ausência X-Frame-Options"].vulneravel, sf.NAO)
        self.assertEqual(r["Ausência Strict-Transport-Security"].vulneravel, sf.SIM)  # max-age baixo
        self.assertEqual(r["Ausência Content-Security-Policy"].vulneravel, sf.SIM)    # unsafe-inline
        self.assertEqual(r["Ausência Referrer-Policy"].vulneravel, sf.SIM)
        self.assertIn("PHP/7.2.24", r["Divulgação de informação em headers"].detalhe)

    def test_wafw00f(self):
        (f,) = sf.parse_wafw00f("x", FIX / "wafw00f.json")
        self.assertEqual(f.vulneravel, sf.SIM)

    def test_whatweb(self):
        (f,), techs = sf.parse_whatweb("x", FIX / "whatweb.json")
        self.assertEqual(f.vulneravel, sf.SIM)
        names = {t["tecnologia"] for t in techs}
        self.assertTrue({"Apache", "PHP", "WordPress", "JQuery"} <= names)
        self.assertNotIn("Country", names)

    def test_reparse_end_to_end(self):
        tmp = Path(tempfile.mkdtemp())
        shutil.copytree(FIX.parent, tmp / "raw")
        self.assertEqual(sf.main(["--reparse", str(tmp), "-q"]), 0)
        with open(tmp / "matriz.csv", encoding="utf-8-sig") as fh:
            rows = list(csv.reader(fh, delimiter=";"))
        self.assertEqual(rows[1][0], "https://legado.exemplo")
        self.assertGreater(int(rows[1][1]), 15)
        shutil.rmtree(tmp)


    def _reparse(self, *extra):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(FIX.parent, tmp / "raw")
        self.assertEqual(sf.main(["--reparse", str(tmp), "-q", *extra]), 0)
        return tmp

    def test_default_format_is_csv_only(self):
        tmp = self._reparse()
        self.assertTrue((tmp / "matriz.csv").exists())
        self.assertFalse((tmp / "relatorio.html").exists())
        self.assertFalse((tmp / "relatorio.md").exists())

    def test_html_and_md_formats(self):
        tmp = self._reparse("--format", "html,md")
        self.assertFalse((tmp / "matriz.csv").exists())
        h = (tmp / "relatorio.html").read_text(encoding="utf-8")
        self.assertIn("<h2>Matriz</h2>", h)
        self.assertIn("https://legado.exemplo", h)
        self.assertIn('class="sim"', h)
        self.assertIn("WordPress", h)
        m = (tmp / "relatorio.md").read_text(encoding="utf-8")
        self.assertIn("## Achados", m)
        self.assertIn("| https://legado.exemplo |", m)
        self.assertIn("RC4-SHA", m)

    def test_format_all(self):
        tmp = self._reparse("--format", "all")
        for n in ["achados.csv", "matriz.csv", "tecnologias.csv", "relatorio.html", "relatorio.md"]:
            self.assertTrue((tmp / n).exists(), n)

    def test_parse_formats(self):
        self.assertEqual(sf.parse_formats("HTML, markdown,csv,html"), ["html", "md", "csv"])
        self.assertEqual(sf.parse_formats("all"), ["csv", "html", "md"])
        with self.assertRaises(sf.argparse.ArgumentTypeError):
            sf.parse_formats("pdf")
        with self.assertRaises(SystemExit):
            sf.main(["--reparse", "x", "--format", "xls", "-q"])

    def test_untrusted_content_is_escaped(self):
        evil = sf.Finding("https://a", "shcheck", "Headers", "Divulgação", sf.SIM, "Baixa",
                          "Server: <script>alert(1)</script> | x\nlinha2")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        sf.write_html(tmp, [evil], [])
        sf.write_md(tmp, [evil], [])
        h = (tmp / "relatorio.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>", h)
        self.assertIn("&lt;script&gt;", h)
        m = (tmp / "relatorio.md").read_text(encoding="utf-8")
        self.assertNotIn("<script>", m)
        self.assertIn("\\| x<br>linha2", m)
        achados = m.split("## Achados", 1)[1].split("## Tecnologias", 1)[0]
        row = [l for l in achados.splitlines() if l.startswith("| https://a |")][0]
        self.assertEqual(row.count(" | "), len(sf.FINDING_COLS) - 1)

if __name__ == "__main__":
    unittest.main()
