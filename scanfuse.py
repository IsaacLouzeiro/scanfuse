#!/usr/bin/env python3
"""
scanfuse - junta os scans web padrão (wafw00f, shcheck, sslscan, whatweb)
em um único resultado (CSV, HTML e/ou Markdown), indicando para cada alvo se há ou não
a vulnerabilidade.

Uso rápido:
    python3 scanfuse.py -t https://exemplo.com.br
    python3 scanfuse.py -f alvos.txt -o resultado --threads 4
    python3 scanfuse.py --reparse resultado          # reprocessa os brutos já coletados
    python3 scanfuse.py -t exemplo.com --format csv,html,md   # ou: --format all

Saídas (na pasta -o):
    achados.csv       uma linha por verificação (alvo, ferramenta, verificação, vulnerável, severidade, detalhe)
    matriz.csv        uma linha por alvo e uma coluna por verificação (SIM / NÃO / N/A)
    tecnologias.csv   inventário de tecnologias detectadas (whatweb)
    relatorio.html    relatório único com matriz, achados e tecnologias (--format html)
    relatorio.md      o mesmo relatório em Markdown (--format md)
    raw/              saída bruta de cada ferramenta, por alvo

Use apenas contra alvos que você tem autorização para testar.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

__version__ = "1.0.0"

SIM, NAO, NA, INFO = "SIM", "NÃO", "N/A", "INFO"

FORMATS = ("csv", "html", "md")


# --------------------------------------------------------------------------- #
# Modelo
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    alvo: str
    ferramenta: str
    categoria: str
    verificacao: str
    vulneravel: str          # SIM / NÃO / N/A / INFO
    severidade: str = ""     # Alta / Média / Baixa / Info
    detalhe: str = ""


@dataclass
class Target:
    raw: str
    url: str
    host: str
    port: int
    scheme: str
    slug: str = field(init=False)

    def __post_init__(self):
        self.slug = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{self.host}_{self.port}")


def parse_target(value: str) -> Target:
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    p = urlparse(value)
    scheme = p.scheme or "https"
    port = p.port or (443 if scheme == "https" else 80)
    host = p.hostname or ""
    if not host:
        raise ValueError(f"alvo inválido: {value}")
    return Target(raw=value, url=value, host=host, port=port, scheme=scheme)


# --------------------------------------------------------------------------- #
# Execução das ferramentas
# --------------------------------------------------------------------------- #
def find_bin(*names: str) -> str | None:
    for n in names:
        path = shutil.which(n)
        if path:
            return path
    return None


TOOLS = {
    "wafw00f": ("wafw00f",),
    "shcheck": ("shcheck.py", "shcheck"),
    "sslscan": ("sslscan",),
    "whatweb": ("whatweb",),
}


def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout após {timeout}s"
    except OSError as e:
        return -1, "", str(e)


def collect(t: Target, raw_dir: Path, timeout: int, skip: set[str], log) -> None:
    """Roda cada ferramenta e grava a saída bruta em raw/<alvo>/<ferramenta>.*"""
    d = raw_dir / t.slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "target.txt").write_text(t.url + "\n")

    for tool, names in TOOLS.items():
        if tool in skip:
            continue
        if tool == "sslscan" and t.scheme != "https":
            continue
        binp = find_bin(*names)
        if not binp:
            log(f"[!] {tool} não encontrado no PATH, pulando")
            continue

        if tool == "wafw00f":
            out = d / "wafw00f.json"
            out.unlink(missing_ok=True)
            cmd = [binp, t.url, "-o", str(out)]
        elif tool == "shcheck":
            out = d / "shcheck.json"
            cmd = [binp, "-j", "-i", "-d", "-g", t.url]
        elif tool == "sslscan":
            out = d / "sslscan.xml"
            cmd = [binp, "--no-colour", f"--xml={out}", f"{t.host}:{t.port}"]
        else:  # whatweb
            out = d / "whatweb.json"
            out.unlink(missing_ok=True)
            cmd = [binp, "-q", "-a", "3", f"--log-json={out}", t.url]

        log(f"[*] {t.host}:{t.port} -> {tool}")
        rc, so, se = run(cmd, timeout)
        if tool == "shcheck":
            out.write_text(so)
        (d / f"{tool}.log").write_text(f"$ {' '.join(cmd)}\nrc={rc}\n\n{so}\n{se}")
        if rc != 0 and not (out.exists() and out.stat().st_size):
            log(f"[!] {tool} falhou em {t.url} (rc={rc}): {se.strip()[:200]}")


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #
def _load_json(path: Path):
    txt = path.read_text(errors="replace").strip()
    if not txt:
        return None
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        # algumas ferramentas imprimem texto antes do JSON ou JSON por linha
        objs = []
        for line in txt.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    objs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        if objs:
            return objs
        m = re.search(r"(\{.*\}|\[.*\])", txt, re.S)
        return json.loads(m.group(1)) if m else None


# ---- wafw00f ----------------------------------------------------------------
def parse_wafw00f(alvo: str, path: Path) -> list[Finding]:
    data = _load_json(path) or []
    if isinstance(data, dict):
        data = [data]
    detected = [x for x in data if x.get("detected")]
    if detected:
        nomes = ", ".join(
            f"{x.get('firewall')} ({x.get('manufacturer')})" for x in detected
        )
        return [Finding(alvo, "wafw00f", "WAF", "Sem WAF detectado", NAO, "Info", nomes)]
    return [Finding(alvo, "wafw00f", "WAF", "Sem WAF detectado", SIM, "Baixa",
                    "Nenhum WAF identificado (pode haver WAF não reconhecido)")]


# ---- shcheck ----------------------------------------------------------------
SEC_HEADERS = {
    # header: (severidade se ausente, descrição)
    "Strict-Transport-Security": ("Média", "HSTS ausente"),
    "Content-Security-Policy": ("Média", "CSP ausente"),
    "X-Frame-Options": ("Média", "Proteção contra clickjacking ausente"),
    "X-Content-Type-Options": ("Baixa", "nosniff ausente"),
    "Referrer-Policy": ("Baixa", "Referrer-Policy ausente"),
    "Permissions-Policy": ("Baixa", "Permissions-Policy ausente"),
    "Cross-Origin-Opener-Policy": ("Baixa", "COOP ausente"),
    "Cross-Origin-Resource-Policy": ("Baixa", "CORP ausente"),
    "Cross-Origin-Embedder-Policy": ("Info", "COEP ausente"),
}
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                      "X-AspNetMvc-Version", "X-Generator", "Via"]


def parse_shcheck(alvo: str, path: Path) -> list[Finding]:
    data = _load_json(path)
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict) or not data:
        return []
    # formato: {url_final: {"present": {...}, "missing": [...], "information_disclosure": {...}}}
    res = next(iter(data.values())) if "present" not in data else data
    present = {k.lower(): v for k, v in (res.get("present") or {}).items()}
    disclosure = {k.lower(): v for k, v in (res.get("information_disclosure") or {}).items()}

    out = []
    for h, (sev, desc) in SEC_HEADERS.items():
        hl = h.lower()
        if hl in present:
            vuln, det, s = NAO, f"{h}: {present[hl]}", ""
            # validações simples de configuração fraca
            if hl == "strict-transport-security":
                m = re.search(r"max-age=(\d+)", str(present[hl]))
                if not m or int(m.group(1)) < 15552000:
                    vuln, s, det = SIM, "Baixa", f"max-age baixo: {present[hl]}"
            if hl == "content-security-policy" and re.search(r"unsafe-inline|unsafe-eval|\*", str(present[hl])):
                vuln, s, det = SIM, "Baixa", f"CSP permissiva: {str(present[hl])[:200]}"
        else:
            vuln, s, det = SIM, sev, desc
        out.append(Finding(alvo, "shcheck", "Headers", f"Ausência {h}", vuln, s, det))

    vazados = {h: disclosure.get(h.lower()) or present.get(h.lower())
               for h in DISCLOSURE_HEADERS}
    vazados = {h: v for h, v in vazados.items() if v}
    out.append(Finding(
        alvo, "shcheck", "Headers", "Divulgação de informação em headers",
        SIM if vazados else NAO, "Baixa" if vazados else "",
        "; ".join(f"{h}: {v}" for h, v in vazados.items())))
    return out


# ---- sslscan ----------------------------------------------------------------
def parse_sslscan(alvo: str, path: Path) -> list[Finding]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError):
        return []
    test = root.find("ssltest")
    if test is None:
        err = root.findtext("error") or "sem resultado"
        return [Finding(alvo, "sslscan", "TLS", "Execução do sslscan", NA, "", err)]

    def f(check, vuln, sev="", det=""):
        return Finding(alvo, "sslscan", "TLS", check, vuln, sev if vuln == SIM else "", det)

    out = []
    protos = {f"{p.get('type').upper()}v{p.get('version')}": p.get("enabled") == "1"
              for p in test.findall("protocol")}
    for name, sev in (("SSLv2", "Alta"), ("SSLv3", "Alta"),
                      ("TLSv1.0", "Média"), ("TLSv1.1", "Média")):
        if name in protos:
            out.append(f(f"{name} habilitado", SIM if protos[name] else NAO, sev))
    if "TLSv1.3" in protos:
        out.append(f("TLSv1.3 não suportado", NAO if protos["TLSv1.3"] else SIM, "Info"))

    ciphers = test.findall("cipher")
    fracas = [c for c in ciphers if c.get("strength") in ("weak", "null", "anonymous")
              or re.search(r"RC4|(^|-)DES-CBC-|NULL|EXP-|EXPORT|ADH|AECDH|anon|MD5", c.get("cipher", ""))]
    medias = [c for c in ciphers if c not in fracas
              and (c.get("strength") == "medium" or "DES-CBC3" in c.get("cipher", ""))]
    out.append(f("Cifras fracas (NULL/EXPORT/RC4/DES/anon)", SIM if fracas else NAO, "Alta",
                 ", ".join(sorted({c.get("cipher") for c in fracas}))))
    out.append(f("Cifras médias (ex: 3DES, CBC sem PFS)", SIM if medias else NAO, "Baixa",
                 ", ".join(sorted({c.get("cipher") for c in medias}))))

    hb = [h for h in test.findall("heartbleed") if h.get("vulnerable") == "1"]
    if test.findall("heartbleed"):
        out.append(f("Heartbleed (CVE-2014-0160)", SIM if hb else NAO, "Alta",
                     ", ".join(h.get("sslversion", "") for h in hb)))

    comp = test.find("compression")
    if comp is not None:
        out.append(f("Compressão TLS (CRIME)", SIM if comp.get("supported") == "1" else NAO, "Média"))

    reneg = test.find("renegotiation")
    if reneg is not None:
        insecure = reneg.get("supported") == "1" and reneg.get("secure") != "1"
        out.append(f("Renegociação insegura", SIM if insecure else NAO, "Média"))

    fb = test.find("fallback")
    if fb is not None:
        out.append(f("Sem TLS_FALLBACK_SCSV", NAO if fb.get("supported") == "1" else SIM, "Baixa"))

    cert = None
    for c in test.findall(".//certificate"):
        if c.get("type") in (None, "short"):
            cert = c
            break
    if cert is not None:
        exp = (cert.findtext("expired") or "").strip().lower() == "true"
        out.append(f("Certificado expirado", SIM if exp else NAO, "Alta",
                     cert.findtext("not-valid-after") or ""))
        ss = (cert.findtext("self-signed") or "").strip().lower() == "true"
        out.append(f("Certificado autoassinado", SIM if ss else NAO, "Média",
                     cert.findtext("issuer") or ""))
        sig = cert.findtext("signature-algorithm") or ""
        out.append(f("Assinatura fraca do certificado (MD5/SHA1)",
                     SIM if re.search(r"md5|sha1With", sig, re.I) else NAO, "Média", sig))
        pk = cert.find("pk")
        if pk is not None and pk.get("bits", "").isdigit():
            bits, typ = int(pk.get("bits")), (pk.get("type") or "").upper()
            weak = bits < (2048 if typ in ("RSA", "DSA", "") else 224)
            out.append(f("Chave do certificado fraca", SIM if weak else NAO, "Média", f"{typ} {bits} bits"))
    return out


# ---- whatweb ----------------------------------------------------------------
IGNORE_PLUGINS = {"IP", "Country", "Title", "HTTPServer", "UncommonHeaders",
                  "RedirectLocation", "Strict-Transport-Security", "X-Frame-Options",
                  "X-XSS-Protection", "Content-Security-Policy", "Cookies", "HttpOnly",
                  "Email", "Meta-Author", "Script", "HTML5", "X-UA-Compatible", "Frame"}


def parse_whatweb(alvo: str, path: Path) -> tuple[list[Finding], list[dict]]:
    data = _load_json(path) or []
    if isinstance(data, dict):
        data = [data]
    techs, versions = [], []
    seen = set()
    for entry in data:
        for name, info in (entry.get("plugins") or {}).items():
            if name in IGNORE_PLUGINS:
                continue
            ver = ", ".join(map(str, info.get("version") or []))
            det = ", ".join(map(str, info.get("string") or []))[:200]
            key = (name, ver, det)
            if key in seen:
                continue
            seen.add(key)
            techs.append({"alvo": alvo, "url": entry.get("target", ""),
                          "tecnologia": name, "versao": ver, "detalhe": det})
            if ver:
                versions.append(f"{name} {ver}")
    if not data:
        return [], []
    f = Finding(alvo, "whatweb", "Fingerprint", "Versões de software expostas",
                SIM if versions else NAO, "Baixa" if versions else "",
                "; ".join(sorted(set(versions))))
    return [f], techs


# --------------------------------------------------------------------------- #
# Consolidação
# --------------------------------------------------------------------------- #
def parse_target_dir(d: Path) -> tuple[list[Finding], list[dict]]:
    alvo = (d / "target.txt").read_text().strip() if (d / "target.txt").exists() else d.name
    findings, techs = [], []
    if (d / "wafw00f.json").exists():
        findings += parse_wafw00f(alvo, d / "wafw00f.json")
    if (d / "shcheck.json").exists():
        findings += parse_shcheck(alvo, d / "shcheck.json")
    if (d / "sslscan.xml").exists():
        findings += parse_sslscan(alvo, d / "sslscan.xml")
    if (d / "whatweb.json").exists():
        f, t = parse_whatweb(alvo, d / "whatweb.json")
        findings += f
        techs += t
    return findings, techs


FINDING_COLS = ["alvo", "ferramenta", "categoria", "verificacao", "vulneravel", "severidade", "detalhe"]
TECH_COLS = ["alvo", "url", "tecnologia", "versao", "detalhe"]


def build_matrix(findings: list[Finding]) -> tuple[list[str], list[list]]:
    """Retorna (cabeçalho, linhas) da matriz alvo x verificação."""
    checks = list(dict.fromkeys(f"[{f.ferramenta}] {f.verificacao}" for f in findings))
    alvos = list(dict.fromkeys(f.alvo for f in findings))
    grid = {a: {} for a in alvos}
    for f in findings:
        grid[f.alvo][f"[{f.ferramenta}] {f.verificacao}"] = f.vulneravel
    rows = []
    for a in alvos:
        row = [grid[a].get(c, NA) for c in checks]
        rows.append([a, row.count(SIM)] + row)
    return ["alvo", "total_vulns"] + checks, rows


def write_csvs(out_dir: Path, findings: list[Finding], techs: list[dict], delim: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    enc = "utf-8-sig"  # abre com acentos corretos no Excel

    with open(out_dir / "achados.csv", "w", newline="", encoding=enc) as fh:
        w = csv.DictWriter(fh, fieldnames=FINDING_COLS, delimiter=delim)
        w.writeheader()
        for f in findings:
            w.writerow(asdict(f))

    # matriz alvo x verificação
    header, rows = build_matrix(findings)
    with open(out_dir / "matriz.csv", "w", newline="", encoding=enc) as fh:
        w = csv.writer(fh, delimiter=delim)
        w.writerow(header)
        w.writerows(rows)

    with open(out_dir / "tecnologias.csv", "w", newline="", encoding=enc) as fh:
        w = csv.DictWriter(fh, fieldnames=TECH_COLS, delimiter=delim)
        w.writeheader()
        w.writerows(techs)


# --------------------------------------------------------------------------- #
# Relatórios HTML / Markdown
# --------------------------------------------------------------------------- #
def _summary(findings: list[Finding]) -> dict:
    alvos = list(dict.fromkeys(f.alvo for f in findings))
    vulns = [f for f in findings if f.vulneravel == SIM]
    sev = {}
    for f in vulns:
        k = f.severidade or "—"
        sev[k] = sev.get(k, 0) + 1
    return {"alvos": len(alvos), "verificacoes": len(findings), "vulneraveis": len(vulns), "sev": sev}


def _sev_order(item):
    order = {"Alta": 0, "Média": 1, "Baixa": 2, "Info": 3}
    return order.get(item[0], 9)


def _generated_at() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def write_html(out_dir: Path, findings: list[Finding], techs: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    e = lambda v: html.escape(str(v), quote=True)  # saída das ferramentas não é confiável

    def cls(v):
        return {SIM: "sim", NAO: "nao", NA: "na", INFO: "info"}.get(v, "")

    def table(header, rows, status_cols=()):
        out = ["<div class=\"wrap\"><table><thead><tr>"]
        out += [f"<th>{e(h)}</th>" for h in header]
        out.append("</tr></thead><tbody>")
        for r in rows:
            out.append("<tr>")
            for i, v in enumerate(r):
                c = cls(v) if i in status_cols else ""
                out.append(f"<td class=\"{c}\">{e(v)}</td>" if c else f"<td>{e(v)}</td>")
            out.append("</tr>")
        out.append("</tbody></table></div>")
        return "".join(out)

    s = _summary(findings)
    m_head, m_rows = build_matrix(findings)
    vi = FINDING_COLS.index("vulneravel")
    sev_txt = ", ".join(f"{k}: {v}" for k, v in sorted(s["sev"].items(), key=_sev_order)) or "—"

    doc = f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>scanfuse - relatório</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#222;background:#fff}}
h1{{margin:0 0 4px}} h2{{margin-top:32px;border-bottom:1px solid #ddd;padding-bottom:4px}}
.meta{{color:#666;font-size:.9em}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.card{{border:1px solid #ddd;border-radius:6px;padding:10px 16px;min-width:140px}}
.card b{{display:block;font-size:1.6em}}
.wrap{{overflow-x:auto}}
table{{border-collapse:collapse;font-size:.85em;width:100%}}
th,td{{border:1px solid #ddd;padding:4px 8px;text-align:left;vertical-align:top}}
th{{background:#f4f4f4;position:sticky;top:0}}
td.sim{{background:#fdd;color:#900;font-weight:600}}
td.nao{{background:#dfd;color:#060}}
td.na{{background:#eee;color:#777}}
td.info{{background:#def;color:#036}}
</style>
</head>
<body>
<h1>scanfuse - relatório</h1>
<div class="meta">Gerado em {e(_generated_at())} · scanfuse {e(__version__)}</div>
<div class="cards">
<div class="card">Alvos<b>{s['alvos']}</b></div>
<div class="card">Verificações<b>{s['verificacoes']}</b></div>
<div class="card">Vulneráveis<b>{s['vulneraveis']}</b></div>
<div class="card">Por severidade<b style="font-size:1em">{e(sev_txt)}</b></div>
</div>
<h2>Matriz</h2>
{table(m_head, m_rows, status_cols=range(2, len(m_head)))}
<h2>Achados</h2>
{table(FINDING_COLS, [[getattr(f, c) for c in FINDING_COLS] for f in findings], status_cols=(vi,))}
<h2>Tecnologias</h2>
{table(TECH_COLS, [[t.get(c, "") for c in TECH_COLS] for t in techs])}
<p class="meta">Use apenas contra alvos que você tem autorização para testar.</p>
</body>
</html>
"""
    (out_dir / "relatorio.html").write_text(doc, encoding="utf-8")


def _md_cell(v) -> str:
    """Escapa um valor para célula de tabela Markdown (saída das ferramentas não é confiável)."""
    s = html.escape(str(v), quote=False)          # & < >  -> não vira HTML no renderizador
    s = s.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`")
    s = re.sub(r"\r\n|\r|\n", "<br>", s)
    return s or " "


def _md_table(header, rows) -> str:
    lines = ["| " + " | ".join(_md_cell(h) for h in header) + " |",
             "|" + "|".join("---" for _ in header) + "|"]
    lines += ["| " + " | ".join(_md_cell(v) for v in r) + " |" for r in rows]
    return "\n".join(lines)


def write_md(out_dir: Path, findings: list[Finding], techs: list[dict]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    s = _summary(findings)
    m_head, m_rows = build_matrix(findings)
    sev_txt = ", ".join(f"{k}: {v}" for k, v in sorted(s["sev"].items(), key=_sev_order)) or "—"
    parts = [
        "# scanfuse - relatório",
        "",
        f"Gerado em {_generated_at()} · scanfuse {__version__}",
        "",
        f"- **Alvos:** {s['alvos']}",
        f"- **Verificações:** {s['verificacoes']}",
        f"- **Vulneráveis:** {s['vulneraveis']}",
        f"- **Por severidade:** {sev_txt}",
        "",
        "## Matriz",
        "",
        _md_table(m_head, m_rows) if m_rows else "_Nenhum resultado._",
        "",
        "## Achados",
        "",
        _md_table(FINDING_COLS, [[getattr(f, c) for c in FINDING_COLS] for f in findings])
        if findings else "_Nenhum achado._",
        "",
        "## Tecnologias",
        "",
        _md_table(TECH_COLS, [[t.get(c, "") for c in TECH_COLS] for t in techs])
        if techs else "_Nenhuma tecnologia detectada._",
        "",
        "> Use apenas contra alvos que você tem autorização para testar.",
        "",
    ]
    (out_dir / "relatorio.md").write_text("\n".join(parts), encoding="utf-8")


def parse_formats(value: str) -> list[str]:
    items = [x.strip().lower() for x in value.split(",") if x.strip()]
    if not items:
        raise argparse.ArgumentTypeError("informe ao menos um formato")
    if "all" in items:
        return list(FORMATS)
    alias = {"markdown": "md", "htm": "html"}
    items = [alias.get(x, x) for x in items]
    bad = [x for x in items if x not in FORMATS]
    if bad:
        raise argparse.ArgumentTypeError(
            f"formato inválido: {', '.join(bad)} (use {', '.join(FORMATS)} ou all)")
    return list(dict.fromkeys(items))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="scanfuse",
        description="Consolida wafw00f, shcheck, sslscan e whatweb em CSV/HTML/Markdown "
                    "(vulnerável SIM/NÃO).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-t", "--target", action="append", help="alvo (URL ou host). Pode repetir.")
    g.add_argument("-f", "--file", help="arquivo com um alvo por linha")
    g.add_argument("--reparse", metavar="DIR", help="só reprocessa DIR/raw sem rodar as ferramentas")
    ap.add_argument("-o", "--output", help="pasta de saída (padrão: scanfuse_<data>)")
    ap.add_argument("--threads", type=int, default=3, help="alvos em paralelo (padrão: 3)")
    ap.add_argument("--timeout", type=int, default=300, help="timeout por ferramenta em s (padrão: 300)")
    ap.add_argument("--skip", default="", help="ferramentas a pular, separadas por vírgula")
    ap.add_argument("-d", "--delimiter", default=";", help="separador do CSV (padrão: ';' p/ Excel PT-BR)")
    ap.add_argument("--format", dest="formats", type=parse_formats, default=["csv"],
                    metavar="FMT",
                    help="formatos de saída separados por vírgula: csv, html, md ou all (padrão: csv)")
    ap.add_argument("-q", "--quiet", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    log = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr, flush=True))

    if args.reparse:
        out_dir = Path(args.reparse)
    else:
        out_dir = Path(args.output or f"scanfuse_{datetime.now():%Y%m%d_%H%M%S}")
        raw = args.target or [l for l in Path(args.file).read_text().splitlines()
                              if l.strip() and not l.lstrip().startswith("#")]
        targets = []
        for v in raw:
            try:
                targets.append(parse_target(v))
            except ValueError as e:
                log(f"[!] {e}")
        missing = [t for t, n in TOOLS.items() if not find_bin(*n)]
        if missing:
            log(f"[!] ferramentas ausentes (serão puladas): {', '.join(missing)}")
        skip = {s.strip() for s in args.skip.split(",") if s.strip()}
        raw_dir = out_dir / "raw"
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futs = [ex.submit(collect, t, raw_dir, args.timeout, skip, log) for t in targets]
            for fu in as_completed(futs):
                fu.result()

    findings, techs = [], []
    for d in sorted((out_dir / "raw").glob("*")):
        if d.is_dir():
            f, t = parse_target_dir(d)
            findings += f
            techs += t

    produced = []
    if "csv" in args.formats:
        write_csvs(out_dir, findings, techs, args.delimiter)
        produced += ["achados.csv", "matriz.csv", "tecnologias.csv"]
    if "html" in args.formats:
        write_html(out_dir, findings, techs)
        produced.append("relatorio.html")
    if "md" in args.formats:
        write_md(out_dir, findings, techs)
        produced.append("relatorio.md")
    vulns = sum(f.vulneravel == SIM for f in findings)
    log(f"[+] {len(findings)} verificações, {vulns} vulneráveis -> {out_dir}/{', '.join(produced)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
