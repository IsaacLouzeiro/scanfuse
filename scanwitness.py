#!/usr/bin/env python3
"""
scanwitness - runs the standard web recon scans (wafw00f, shcheck, sslscan, whatweb)
and consolidates them into a single report (CSV, HTML and Markdown) that states,
for each target, whether each issue is present or not.

Quick usage:
    python3 scanwitness.py -t https://example.com
    python3 scanwitness.py -f targets.txt -o results --threads 4
    python3 scanwitness.py --reparse results                 # rebuild reports from raw output
    python3 scanwitness.py -t example.com --lang pt          # reports in Portuguese
    python3 scanwitness.py -t example.com --format csv       # CSV only

Outputs (in the -o folder):
    findings.csv       one row per check (target, tool, category, check, vulnerable, severity, ...)
    matrix.csv         one row per target and one column per check (YES / NO / N/A)
    technologies.csv   technology inventory (whatweb)
    report.html        full report: executive summary, findings, matrix, inventory, scope
    report.md          the same report in Markdown
    evidence/          raw console output of each tool, with command, timestamps and
                       version, plus SHA256SUMS.txt - to hand over to the client
    raw/               working files used to build the reports, per target

Only scan targets you are authorized to test.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

__version__ = "2.2.0"

# Result status of a check (internal codes; translated only when rendering).
VULN, OK, NA = "VULN", "OK", "NA"
SEVERITIES = ("high", "medium", "low", "info")
FORMATS = ("csv", "html", "md")
LANGS = ("en", "pt")


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    target: str
    tool: str
    category: str
    check: str            # check id, e.g. "header:X-Frame-Options", "protocol:SSLv3"
    status: str           # VULN / OK / NA
    severity: str = ""    # high / medium / low / info (only when status == VULN)
    evidence: str = ""    # raw tool output - never translated
    msg: str = ""         # optional translatable message key (see I18N "msg.*")


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
        raise ValueError(f"invalid target: {value}")
    return Target(raw=value, url=value, host=host, port=port, scheme=scheme)


# --------------------------------------------------------------------------- #
# Running the tools
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


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# a version like 2.1 or v2.1.4 that is not part of a longer dotted number (e.g. an IP)
VERSION_RE = re.compile(r"(?<![\d.])v?(\d+\.\d+(?:\.\d+)?)(?![\d.])")
PIP_PACKAGES = {"wafw00f": "wafw00f", "shcheck": "shcheck"}


def tool_version(tool: str, binp: str, timeout: int = 20) -> str:
    """Best-effort version of a tool: '<bin> --version', then pip metadata, else 'unknown'."""
    rc, so, se = run([binp, "--version"], timeout)
    if rc == 0:
        m = VERSION_RE.search(ANSI_RE.sub("", f"{so}\n{se}"))
        if m:
            return m.group(1)
    pkg = PIP_PACKAGES.get(tool)
    if pkg:
        try:
            from importlib.metadata import version as pkg_version
            return pkg_version(pkg)
        except Exception:
            pass
    return "unknown"


def _display_arg(arg: str, root: Path) -> str:
    """Shows output paths relative to the results folder (no local paths in the evidence)."""
    prefix = str(root) + os.sep
    return arg.replace(prefix, "") if str(root) not in ("", ".") else arg


def run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except OSError as e:
        return -1, "", str(e)


def collect(t: Target, raw_dir: Path, timeout: int, skip: set[str], log,
            versions: dict[str, str] | None = None, scanner_host: str = "") -> None:
    """Runs each tool and stores its raw output in raw/<target>/<tool>.*

    <tool>.meta.json keeps what is needed to build the evidence files: command,
    timestamps (UTC), exit code, tool version and the console output."""
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
            log(f"[!] {tool} not found in PATH, skipping")
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
            # no -q: the brief console line is kept as evidence
            cmd = [binp, "-a", "3", f"--log-json={out}", t.url]

        log(f"[*] {t.host}:{t.port} -> {tool}")
        started = datetime.now(timezone.utc)
        rc, so, se = run(cmd, timeout)
        finished = datetime.now(timezone.utc)
        if tool == "shcheck":
            out.write_text(so)
        (d / f"{tool}.log").write_text(f"$ {' '.join(cmd)}\nrc={rc}\n\n{so}\n{se}")
        meta = {
            "tool": tool,
            "version": (versions or {}).get(tool, "unknown"),
            "collector": f"scanwitness {__version__}",
            "target": t.url,
            "host": t.host,
            "port": t.port,
            "command": [Path(binp).name] + [_display_arg(a, raw_dir.parent) for a in cmd[1:]],
            "started": started.isoformat(timespec="seconds"),
            "finished": finished.isoformat(timespec="seconds"),
            "exit_code": rc,
            "scanner_host": scanner_host,
            "stdout": so,
            "stderr": se,
        }
        (d / f"{tool}.meta.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False),
                                              encoding="utf-8")
        if rc != 0 and not (out.exists() and out.stat().st_size):
            log(f"[!] {tool} failed on {t.url} (rc={rc}): {se.strip()[:200]}")


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
        # some tools print text before the JSON, or one JSON object per line
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
def parse_wafw00f(target: str, path: Path) -> list[Finding]:
    data = _load_json(path) or []
    if isinstance(data, dict):
        data = [data]
    detected = [x for x in data if isinstance(x, dict) and x.get("detected")]
    if detected:
        names = ", ".join(f"{x.get('firewall')} ({x.get('manufacturer')})" for x in detected)
        return [Finding(target, "wafw00f", "WAF", "no_waf", OK, evidence=names)]
    return [Finding(target, "wafw00f", "WAF", "no_waf", VULN, "low", msg="no_waf")]


# ---- shcheck ----------------------------------------------------------------
SEC_HEADERS = {
    # header: severity when missing
    "Strict-Transport-Security": "medium",
    "Content-Security-Policy": "medium",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
    "Cross-Origin-Opener-Policy": "low",
    "Cross-Origin-Resource-Policy": "low",
    "Cross-Origin-Embedder-Policy": "info",
}
# headers whose value is also validated (weak configuration counts as an issue)
WEAK_VALIDATED = {"Strict-Transport-Security", "Content-Security-Policy"}
HSTS_MIN_MAX_AGE = 15552000  # 180 days
DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                      "X-AspNetMvc-Version", "X-Generator", "Via"]


def parse_shcheck(target: str, path: Path) -> list[Finding]:
    data = _load_json(path)
    if isinstance(data, list):
        data = data[0] if data else None
    if not isinstance(data, dict) or not data:
        return []
    # format: {final_url: {"present": {...}, "missing": [...], "information_disclosure": {...}}}
    res = next(iter(data.values())) if "present" not in data else data
    if not isinstance(res, dict):
        return []
    present = {k.lower(): v for k, v in (res.get("present") or {}).items()}
    disclosure = {k.lower(): v for k, v in (res.get("information_disclosure") or {}).items()}

    out = []
    for h, sev in SEC_HEADERS.items():
        hl = h.lower()
        if hl in present:
            val = str(present[hl])
            status, s, ev, msg = OK, "", f"{h}: {val}", ""
            # simple checks for weak configuration
            if hl == "strict-transport-security":
                m = re.search(r"max-age=(\d+)", val)
                if not m or int(m.group(1)) < HSTS_MIN_MAX_AGE:
                    status, s, ev, msg = VULN, "low", val, "hsts_low"
            # a bare "*" source allows any origin; "*.example.com" (subdomain wildcard) is fine
            if hl == "content-security-policy" and re.search(
                    r"unsafe-inline|unsafe-eval|(?:^|[\s;])\*(?=$|[\s;])", val):
                status, s, ev, msg = VULN, "low", val[:200], "csp_weak"
        else:
            status, s, ev, msg = VULN, sev, "", "header_missing"
        out.append(Finding(target, "shcheck", "Headers", f"header:{h}", status, s, ev, msg))

    leaked = {h: disclosure.get(h.lower()) or present.get(h.lower()) for h in DISCLOSURE_HEADERS}
    leaked = {h: v for h, v in leaked.items() if v}
    out.append(Finding(
        target, "shcheck", "Headers", "info_disclosure",
        VULN if leaked else OK, "low" if leaked else "",
        "; ".join(f"{h}: {v}" for h, v in leaked.items())))
    return out


# ---- sslscan ----------------------------------------------------------------
def parse_sslscan(target: str, path: Path) -> list[Finding]:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, FileNotFoundError):
        return []
    test = root.find("ssltest")
    if test is None:
        err = (root.findtext("error") or "").strip()
        return [Finding(target, "sslscan", "TLS", "sslscan_run", NA,
                        evidence=err, msg="" if err else "no_result")]

    def f(check: str, vuln: bool, sev: str = "", ev: str = "") -> Finding:
        return Finding(target, "sslscan", "TLS", check, VULN if vuln else OK,
                       sev if vuln else "", ev)

    out = []
    protos = {f"{p.get('type', '').upper()}v{p.get('version')}": p.get("enabled") == "1"
              for p in test.findall("protocol")}
    for name, sev in (("SSLv2", "high"), ("SSLv3", "high"),
                      ("TLSv1.0", "medium"), ("TLSv1.1", "medium")):
        if name in protos:
            out.append(f(f"protocol:{name}", protos[name], sev))
    if "TLSv1.3" in protos:
        out.append(f("no_tls13", not protos["TLSv1.3"], "info"))

    ciphers = test.findall("cipher")
    weak = [c for c in ciphers if c.get("strength") in ("weak", "null", "anonymous")
            or re.search(r"RC4|(^|-)DES-CBC-|NULL|EXP-|EXPORT|ADH|AECDH|anon|MD5", c.get("cipher", ""))]
    medium = [c for c in ciphers if c not in weak
              and (c.get("strength") == "medium" or "DES-CBC3" in c.get("cipher", ""))]
    out.append(f("weak_ciphers", bool(weak), "high",
                 ", ".join(sorted({c.get("cipher", "") for c in weak}))))
    out.append(f("medium_ciphers", bool(medium), "low",
                 ", ".join(sorted({c.get("cipher", "") for c in medium}))))

    hb_all = test.findall("heartbleed")
    if hb_all:
        hb = [h for h in hb_all if h.get("vulnerable") == "1"]
        out.append(f("heartbleed", bool(hb), "high", ", ".join(h.get("sslversion", "") for h in hb)))

    comp = test.find("compression")
    if comp is not None:
        out.append(f("tls_compression", comp.get("supported") == "1", "medium"))

    reneg = test.find("renegotiation")
    if reneg is not None:
        insecure = reneg.get("supported") == "1" and reneg.get("secure") != "1"
        out.append(f("insecure_renegotiation", insecure, "medium"))

    fb = test.find("fallback")
    if fb is not None:
        out.append(f("no_fallback_scsv", fb.get("supported") != "1", "low"))

    cert = None
    for c in test.findall(".//certificate"):
        if c.get("type") in (None, "short"):
            cert = c
            break
    if cert is not None:
        expired = (cert.findtext("expired") or "").strip().lower() == "true"
        out.append(f("cert_expired", expired, "high", cert.findtext("not-valid-after") or ""))
        self_signed = (cert.findtext("self-signed") or "").strip().lower() == "true"
        out.append(f("cert_self_signed", self_signed, "medium", cert.findtext("issuer") or ""))
        sig = cert.findtext("signature-algorithm") or ""
        out.append(f("cert_weak_signature", bool(re.search(r"md5|sha1With", sig, re.I)), "medium", sig))
        pk = cert.find("pk")
        if pk is not None and pk.get("bits", "").isdigit():
            bits, typ = int(pk.get("bits")), (pk.get("type") or "").upper()
            weak_key = bits < (2048 if typ in ("RSA", "DSA", "") else 224)
            out.append(f("cert_weak_key", weak_key, "medium", f"{typ} {bits} bits".strip()))
    return out


# ---- whatweb ----------------------------------------------------------------
IGNORE_PLUGINS = {"IP", "Country", "Title", "HTTPServer", "UncommonHeaders",
                  "RedirectLocation", "Strict-Transport-Security", "X-Frame-Options",
                  "X-XSS-Protection", "Content-Security-Policy", "Cookies", "HttpOnly",
                  "Email", "Meta-Author", "Script", "HTML5", "X-UA-Compatible", "Frame"}


def parse_whatweb(target: str, path: Path) -> tuple[list[Finding], list[dict]]:
    data = _load_json(path) or []
    if isinstance(data, dict):
        data = [data]
    data = [x for x in data if isinstance(x, dict)]
    techs, versions = [], []
    seen = set()
    for entry in data:
        for name, info in (entry.get("plugins") or {}).items():
            if name in IGNORE_PLUGINS or not isinstance(info, dict):
                continue
            ver = ", ".join(map(str, info.get("version") or []))
            det = ", ".join(map(str, info.get("string") or []))[:200]
            key = (name, ver, det)
            if key in seen:
                continue
            seen.add(key)
            techs.append({"target": target, "url": entry.get("target", ""),
                          "technology": name, "version": ver, "detail": det})
            if ver:
                versions.append(f"{name} {ver}")
    if not data:
        return [], []
    f = Finding(target, "whatweb", "Fingerprint", "exposed_versions",
                VULN if versions else OK, "low" if versions else "",
                "; ".join(sorted(set(versions))))
    return [f], techs


# --------------------------------------------------------------------------- #
# Consolidation
# --------------------------------------------------------------------------- #
def parse_target_dir(d: Path) -> tuple[list[Finding], list[dict]]:
    target = (d / "target.txt").read_text().strip() if (d / "target.txt").exists() else d.name
    findings, techs = [], []
    if (d / "wafw00f.json").exists():
        findings += parse_wafw00f(target, d / "wafw00f.json")
    if (d / "shcheck.json").exists():
        findings += parse_shcheck(target, d / "shcheck.json")
    if (d / "sslscan.xml").exists():
        findings += parse_sslscan(target, d / "sslscan.xml")
    if (d / "whatweb.json").exists():
        f, t = parse_whatweb(target, d / "whatweb.json")
        findings += f
        techs += t
    return findings, techs


# --------------------------------------------------------------------------- #
# Evidence (raw tool output for the client) - always in English
# --------------------------------------------------------------------------- #
EVIDENCE_README = """Evidence - raw tool output
==========================

This folder contains the console output of every tool that scanwitness ran
against each target, as proof that the scans were actually performed.
ANSI color codes were removed and the shcheck JSON output was indented for
readability; nothing else was changed.

Each file starts with a header containing the tool and its version, the
target, the exact command line, the start and finish time (UTC) and the
exit code, followed by the tool's standard output (and standard error,
when there was any).

Layout: <host_port>/<tool>.txt

Integrity: SHA256SUMS.txt lists the SHA-256 hash of every file in this
folder. To verify them:
  Linux:    cd evidence && sha256sum -c SHA256SUMS.txt
  macOS:    cd evidence && shasum -a 256 -c SHA256SUMS.txt
  Windows:  Get-FileHash -Algorithm SHA256 <file>   (PowerShell)

Targets and tools:
"""


def _fmt_time(value: str) -> str:
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError):
        return str(value or "unknown")


def _clean_output(text: str) -> str:
    text = ANSI_RE.sub("", text or "")
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip()


def render_evidence(meta: dict) -> str:
    tool = str(meta.get("tool", ""))
    stdout = _clean_output(meta.get("stdout", ""))
    if tool == "shcheck" and stdout:
        try:
            stdout = json.dumps(json.loads(stdout), indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
    stderr = _clean_output(meta.get("stderr", ""))
    started, finished = meta.get("started", ""), meta.get("finished", "")
    try:
        secs = int((datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds())
        duration = f" ({secs}s)"
    except (TypeError, ValueError):
        duration = ""
    rc = meta.get("exit_code", "")
    command = meta.get("command") or []
    cmd_txt = shlex.join(map(str, command)) if isinstance(command, list) else str(command)

    lines = [
        f"Tool:          {tool} {meta.get('version') or 'unknown'}",
        f"Target:        {meta.get('target', '')} ({meta.get('host', '')}:{meta.get('port', '')})",
        f"Command:       {cmd_txt}",
        f"Started:       {_fmt_time(started)}",
        f"Finished:      {_fmt_time(finished)}{duration}",
        f"Exit code:     {rc}" + (" (timed out or could not be started)" if rc == -1 else ""),
    ]
    if meta.get("scanner_host"):
        lines.append(f"Scanner host:  {meta['scanner_host']}")
    lines.append(f"Collected by:  {meta.get('collector') or 'unknown'}")
    bar = "=" * 72
    lines += ["", bar, "STANDARD OUTPUT", bar, stdout or "(no output)"]
    if stderr:
        lines += ["", bar, "STANDARD ERROR", bar, stderr]
    return "\n".join(lines) + "\n"


def write_evidence(out_dir: Path, log) -> dict[str, list[tuple[str, str]]]:
    """Builds out_dir/evidence from raw/*/<tool>.meta.json.

    Returns {target: [(tool, relative path)]} for linking from the reports,
    or {} when there is no metadata (scans made with a version older than 2.1.0)."""
    metas = []
    for d in sorted((out_dir / "raw").glob("*")):
        if not d.is_dir():
            continue
        for tool in TOOLS:
            p = d / f"{tool}.meta.json"
            if not p.exists():
                continue
            try:
                meta = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                log(f"[!] invalid evidence metadata, skipping: {p}")
                continue
            if isinstance(meta, dict):
                metas.append((d.name, tool, meta))
    if not metas:
        return {}

    ev = out_dir / "evidence"
    links: dict[str, list[tuple[str, str]]] = {}
    written = []
    for slug, tool, meta in metas:
        rel = f"{slug}/{tool}.txt"
        (ev / slug).mkdir(parents=True, exist_ok=True)
        (ev / rel).write_bytes(render_evidence(meta).encode("utf-8"))
        written.append(rel)
        target = str(meta.get("target") or slug)
        links.setdefault(target, []).append((tool, f"evidence/{rel}"))

    summary = "".join(
        f"  {target} ({Path(items[0][1]).parent.name}): {', '.join(t for t, _ in items)}\n"
        for target, items in links.items())
    (ev / "README.txt").write_bytes((EVIDENCE_README + summary).encode("utf-8"))
    written.append("README.txt")

    sums = "".join(f"{hashlib.sha256((ev / r).read_bytes()).hexdigest()}  {r}\n" for r in sorted(written))
    (ev / "SHA256SUMS.txt").write_bytes(sums.encode("utf-8"))
    return links


# --------------------------------------------------------------------------- #
# Translations (reports only - the CLI itself is always in English)
# --------------------------------------------------------------------------- #
I18N: dict[str, dict[str, str]] = {
    "en": {
        # values
        "yn.VULN": "YES", "yn.OK": "NO", "yn.NA": "N/A",
        "sev.high": "High", "sev.medium": "Medium", "sev.low": "Low", "sev.info": "Info",
        "status.pass": "Pass", "status.na": "N/A", "risk.none": "None",
        # CSV columns
        "col.target": "target", "col.tool": "tool", "col.category": "category",
        "col.check": "check", "col.vulnerable": "vulnerable", "col.severity": "severity",
        "col.detail": "detail", "col.recommendation": "recommendation",
        "col.total_vulns": "total_vulns", "col.url": "url", "col.technology": "technology",
        "col.version": "version",
        # check titles
        "check.no_waf": "No WAF detected",
        "check.header": "Missing {arg} header",
        "check.header_weak": "Missing or weak {arg} header",
        "check.info_disclosure": "Information disclosure in headers",
        "check.sslscan_run": "sslscan execution",
        "check.protocol": "{arg} enabled",
        "check.no_tls13": "TLSv1.3 not supported",
        "check.weak_ciphers": "Weak cipher suites (NULL/EXPORT/RC4/DES/anon)",
        "check.medium_ciphers": "Medium-strength cipher suites (e.g. 3DES)",
        "check.heartbleed": "Heartbleed (CVE-2014-0160)",
        "check.tls_compression": "TLS compression enabled (CRIME)",
        "check.insecure_renegotiation": "Insecure renegotiation",
        "check.no_fallback_scsv": "TLS_FALLBACK_SCSV not supported",
        "check.cert_expired": "Expired certificate",
        "check.cert_self_signed": "Self-signed certificate",
        "check.cert_weak_signature": "Weak certificate signature (MD5/SHA1)",
        "check.cert_weak_key": "Weak certificate key",
        "check.exposed_versions": "Exposed software versions",
        # messages
        "msg.no_waf": "No WAF identified (an unrecognized WAF may still be present)",
        "msg.header_missing": "Header not present in the response",
        "msg.hsts_low": "max-age too low (minimum 15552000): {evidence}",
        "msg.csp_weak": "Permissive policy: {evidence}",
        "msg.no_result": "No result",
        # recommendations
        "rec.no_waf": "Consider placing the application behind a web application firewall to filter common attacks. A WAF that the tool does not recognize may already be in place; confirm before reporting.",
        "rec.header:Strict-Transport-Security": "Send Strict-Transport-Security with max-age of at least 15552000 (180 days), ideally 31536000 (1 year) with includeSubDomains.",
        "rec.header:Content-Security-Policy": "Define a restrictive Content-Security-Policy without 'unsafe-inline', 'unsafe-eval' or wildcard (*) sources.",
        "rec.header:X-Frame-Options": "Send X-Frame-Options: DENY or SAMEORIGIN (or CSP frame-ancestors) to prevent clickjacking.",
        "rec.header:X-Content-Type-Options": "Send X-Content-Type-Options: nosniff to prevent MIME type sniffing.",
        "rec.header:Referrer-Policy": "Send Referrer-Policy, for example strict-origin-when-cross-origin or no-referrer.",
        "rec.header:Permissions-Policy": "Send Permissions-Policy disabling browser features the application does not use (camera, microphone, geolocation, etc.).",
        "rec.header:Cross-Origin-Opener-Policy": "Send Cross-Origin-Opener-Policy: same-origin to isolate the browsing context.",
        "rec.header:Cross-Origin-Resource-Policy": "Send Cross-Origin-Resource-Policy: same-origin (or same-site) to block cross-origin reads of resources.",
        "rec.header:Cross-Origin-Embedder-Policy": "Send Cross-Origin-Embedder-Policy: require-corp if the application needs cross-origin isolation.",
        "rec.info_disclosure": "Remove or genericize headers that reveal software and versions (Server, X-Powered-By, X-AspNet-Version, etc.).",
        "rec.protocol": "Disable {arg} on the server and allow only TLS 1.2 and TLS 1.3.",
        "rec.no_tls13": "Enable TLS 1.3 support.",
        "rec.weak_ciphers": "Disable NULL, EXPORT, RC4, DES and anonymous cipher suites.",
        "rec.medium_ciphers": "Disable 3DES and other medium-strength suites; prefer AEAD suites with forward secrecy (ECDHE with AES-GCM or ChaCha20).",
        "rec.heartbleed": "Upgrade OpenSSL to a patched version, then revoke and reissue the certificate and rotate any credentials that may have been exposed.",
        "rec.tls_compression": "Disable TLS-level compression.",
        "rec.insecure_renegotiation": "Disable insecure renegotiation; support only secure renegotiation (RFC 5746).",
        "rec.no_fallback_scsv": "Enable TLS_FALLBACK_SCSV to prevent protocol downgrade attacks.",
        "rec.cert_expired": "Renew the certificate.",
        "rec.cert_self_signed": "Use a certificate issued by a trusted certificate authority.",
        "rec.cert_weak_signature": "Reissue the certificate with a SHA-256 (or stronger) signature.",
        "rec.cert_weak_key": "Reissue the certificate with an RSA key of at least 2048 bits (or ECDSA P-256 or stronger).",
        "rec.exposed_versions": "Hide version numbers in banners and pages, and keep the listed components up to date.",
        # report
        "report.title": "Web Security Scan Report",
        "report.generated": "Generated",
        "report.version": "Tool version",
        "report.targets": "Targets",
        "report.tools": "Tools",
        "report.contents": "Contents",
        "sec.summary": "1. Executive summary",
        "sec.findings": "2. Findings",
        "sec.passed": "3. Passed and not applicable checks",
        "sec.matrix": "4. Check matrix",
        "sec.tech": "5. Technology inventory",
        "sec.scope": "6. Scope and methodology",
        "summary.text": "{issues} potential issue(s) were identified across {targets} target(s) in {checks} automated checks.",
        "summary.none": "No issues were identified in {checks} automated checks across {targets} target(s).",
        "summary.disclaimer": "Results come from automated tools and should be manually validated before being reported as confirmed vulnerabilities.",
        "summary.overview": "Targets overview",
        "summary.empty": "No results were found.",
        "findings.none": "No issues identified for this target.",
        "passed.count": "{passed} passed, {na} not applicable",
        "passed.none": "No passed or not applicable checks for this target.",
        "matrix.legend": "Each cell shows the result of a check for a target: the severity when an issue was found, Pass when it was not, and N/A when the check did not apply or the tool did not run.",
        "tech.none": "No technologies detected.",
        "scope.targets": "Targets in scope",
        "scope.tools": "Tools used",
        "scope.na": "N/A means the check does not apply to the target (for example, TLS checks on plain HTTP) or that the tool was not available or failed for that target.",
        "scope.auth": "Only scan targets you are authorized to test.",
        "scope.evidence": "Evidence (raw tool output)",
        "scope.evidence_note": "Console output of each tool run, with the exact command, start and finish time (UTC), tool version and exit code. SHA-256 hashes of these files are listed in evidence/SHA256SUMS.txt.",
        "tool.wafw00f": "Web application firewall (WAF) detection",
        "tool.shcheck": "HTTP security headers and information disclosure",
        "tool.sslscan": "TLS protocols, cipher suites and certificate",
        "tool.whatweb": "Technology fingerprinting and exposed versions",
        "footer": "Generated by scanwitness {version}",
        # report table headers / field labels
        "th.target": "Target", "th.tool": "Tool", "th.category": "Category", "th.check": "Check",
        "th.result": "Result", "th.evidence": "Evidence", "th.severity": "Severity",
        "th.recommendation": "Recommendation", "th.count": "Count", "th.issues": "Issues",
        "th.passed": "Passed", "th.na": "N/A", "th.risk": "Overall risk", "th.url": "URL",
        "th.technology": "Technology", "th.version": "Version", "th.details": "Details",
        "th.purpose": "Purpose",
    },
    "pt": {
        "yn.VULN": "SIM", "yn.OK": "NÃO", "yn.NA": "N/A",
        "sev.high": "Alta", "sev.medium": "Média", "sev.low": "Baixa", "sev.info": "Info",
        "status.pass": "Aprovado", "status.na": "N/A", "risk.none": "Nenhum",
        "col.target": "alvo", "col.tool": "ferramenta", "col.category": "categoria",
        "col.check": "verificacao", "col.vulnerable": "vulneravel", "col.severity": "severidade",
        "col.detail": "detalhe", "col.recommendation": "recomendacao",
        "col.total_vulns": "total_vulns", "col.url": "url", "col.technology": "tecnologia",
        "col.version": "versao",
        "check.no_waf": "Sem WAF detectado",
        "check.header": "Ausência do header {arg}",
        "check.header_weak": "Ausência ou configuração fraca do header {arg}",
        "check.info_disclosure": "Divulgação de informação em headers",
        "check.sslscan_run": "Execução do sslscan",
        "check.protocol": "{arg} habilitado",
        "check.no_tls13": "TLSv1.3 não suportado",
        "check.weak_ciphers": "Cifras fracas (NULL/EXPORT/RC4/DES/anon)",
        "check.medium_ciphers": "Cifras de força média (ex: 3DES)",
        "check.heartbleed": "Heartbleed (CVE-2014-0160)",
        "check.tls_compression": "Compressão TLS habilitada (CRIME)",
        "check.insecure_renegotiation": "Renegociação insegura",
        "check.no_fallback_scsv": "Sem suporte a TLS_FALLBACK_SCSV",
        "check.cert_expired": "Certificado expirado",
        "check.cert_self_signed": "Certificado autoassinado",
        "check.cert_weak_signature": "Assinatura fraca do certificado (MD5/SHA1)",
        "check.cert_weak_key": "Chave do certificado fraca",
        "check.exposed_versions": "Versões de software expostas",
        "msg.no_waf": "Nenhum WAF identificado (pode haver WAF não reconhecido)",
        "msg.header_missing": "Header ausente na resposta",
        "msg.hsts_low": "max-age baixo (mínimo 15552000): {evidence}",
        "msg.csp_weak": "Política permissiva: {evidence}",
        "msg.no_result": "Sem resultado",
        "rec.no_waf": "Considere colocar a aplicação atrás de um firewall de aplicação web para filtrar ataques comuns. Pode já existir um WAF não reconhecido pela ferramenta; confirme antes de reportar.",
        "rec.header:Strict-Transport-Security": "Envie Strict-Transport-Security com max-age de pelo menos 15552000 (180 dias), idealmente 31536000 (1 ano) com includeSubDomains.",
        "rec.header:Content-Security-Policy": "Defina uma Content-Security-Policy restritiva, sem 'unsafe-inline', 'unsafe-eval' ou origens curinga (*).",
        "rec.header:X-Frame-Options": "Envie X-Frame-Options: DENY ou SAMEORIGIN (ou CSP frame-ancestors) para evitar clickjacking.",
        "rec.header:X-Content-Type-Options": "Envie X-Content-Type-Options: nosniff para evitar MIME sniffing.",
        "rec.header:Referrer-Policy": "Envie Referrer-Policy, por exemplo strict-origin-when-cross-origin ou no-referrer.",
        "rec.header:Permissions-Policy": "Envie Permissions-Policy desabilitando recursos do navegador que a aplicação não usa (câmera, microfone, geolocalização etc.).",
        "rec.header:Cross-Origin-Opener-Policy": "Envie Cross-Origin-Opener-Policy: same-origin para isolar o contexto de navegação.",
        "rec.header:Cross-Origin-Resource-Policy": "Envie Cross-Origin-Resource-Policy: same-origin (ou same-site) para bloquear leituras de recursos por outras origens.",
        "rec.header:Cross-Origin-Embedder-Policy": "Envie Cross-Origin-Embedder-Policy: require-corp se a aplicação precisar de isolamento entre origens.",
        "rec.info_disclosure": "Remova ou torne genéricos os headers que revelam software e versões (Server, X-Powered-By, X-AspNet-Version etc.).",
        "rec.protocol": "Desabilite {arg} no servidor e permita apenas TLS 1.2 e TLS 1.3.",
        "rec.no_tls13": "Habilite o suporte a TLS 1.3.",
        "rec.weak_ciphers": "Desabilite as suítes NULL, EXPORT, RC4, DES e anônimas.",
        "rec.medium_ciphers": "Desabilite 3DES e outras suítes de força média; prefira suítes AEAD com sigilo direto (ECDHE com AES-GCM ou ChaCha20).",
        "rec.heartbleed": "Atualize o OpenSSL para uma versão corrigida, depois revogue e reemita o certificado e troque credenciais que possam ter sido expostas.",
        "rec.tls_compression": "Desabilite a compressão no nível do TLS.",
        "rec.insecure_renegotiation": "Desabilite a renegociação insegura; permita apenas a renegociação segura (RFC 5746).",
        "rec.no_fallback_scsv": "Habilite TLS_FALLBACK_SCSV para evitar ataques de downgrade de protocolo.",
        "rec.cert_expired": "Renove o certificado.",
        "rec.cert_self_signed": "Use um certificado emitido por uma autoridade certificadora confiável.",
        "rec.cert_weak_signature": "Reemita o certificado com assinatura SHA-256 (ou mais forte).",
        "rec.cert_weak_key": "Reemita o certificado com chave RSA de pelo menos 2048 bits (ou ECDSA P-256 ou mais forte).",
        "rec.exposed_versions": "Oculte números de versão em banners e páginas e mantenha os componentes listados atualizados.",
        "report.title": "Relatório de Varredura de Segurança Web",
        "report.generated": "Gerado em",
        "report.version": "Versão da ferramenta",
        "report.targets": "Alvos",
        "report.tools": "Ferramentas",
        "report.contents": "Sumário",
        "sec.summary": "1. Resumo executivo",
        "sec.findings": "2. Achados",
        "sec.passed": "3. Verificações aprovadas e não aplicáveis",
        "sec.matrix": "4. Matriz de verificações",
        "sec.tech": "5. Inventário de tecnologias",
        "sec.scope": "6. Escopo e metodologia",
        "summary.text": "Foram identificados {issues} possível(is) problema(s) em {targets} alvo(s), a partir de {checks} verificações automatizadas.",
        "summary.none": "Nenhum problema foi identificado nas {checks} verificações automatizadas em {targets} alvo(s).",
        "summary.disclaimer": "Os resultados vêm de ferramentas automatizadas e devem ser validados manualmente antes de serem reportados como vulnerabilidades confirmadas.",
        "summary.overview": "Visão geral dos alvos",
        "summary.empty": "Nenhum resultado encontrado.",
        "findings.none": "Nenhum problema identificado para este alvo.",
        "passed.count": "{passed} aprovada(s), {na} não aplicável(is)",
        "passed.none": "Nenhuma verificação aprovada ou não aplicável para este alvo.",
        "matrix.legend": "Cada célula mostra o resultado de uma verificação para um alvo: a severidade quando há problema, Aprovado quando não há e N/A quando a verificação não se aplica ou a ferramenta não rodou.",
        "tech.none": "Nenhuma tecnologia detectada.",
        "scope.targets": "Alvos no escopo",
        "scope.tools": "Ferramentas utilizadas",
        "scope.na": "N/A significa que a verificação não se aplica ao alvo (por exemplo, verificações de TLS em HTTP sem criptografia) ou que a ferramenta não estava disponível ou falhou para aquele alvo.",
        "scope.auth": "Use apenas contra alvos que você tem autorização para testar.",
        "scope.evidence": "Evidências (saída bruta das ferramentas)",
        "scope.evidence_note": "Saída de terminal de cada execução das ferramentas, com o comando exato, horário de início e fim (UTC), versão da ferramenta e código de saída. Os hashes SHA-256 desses arquivos estão em evidence/SHA256SUMS.txt.",
        "tool.wafw00f": "Detecção de firewall de aplicação web (WAF)",
        "tool.shcheck": "Headers de segurança HTTP e divulgação de informação",
        "tool.sslscan": "Protocolos TLS, suítes de cifras e certificado",
        "tool.whatweb": "Identificação de tecnologias e versões expostas",
        "footer": "Gerado pelo scanwitness {version}",
        "th.target": "Alvo", "th.tool": "Ferramenta", "th.category": "Categoria", "th.check": "Verificação",
        "th.result": "Resultado", "th.evidence": "Evidência", "th.severity": "Severidade",
        "th.recommendation": "Recomendação", "th.count": "Quantidade", "th.issues": "Problemas",
        "th.passed": "Aprovadas", "th.na": "N/A", "th.risk": "Risco geral", "th.url": "URL",
        "th.technology": "Tecnologia", "th.version": "Versão", "th.details": "Detalhes",
        "th.purpose": "Finalidade",
    },
}


def tr(lang: str, key: str, **kw) -> str:
    return I18N[lang][key].format(**kw)


def check_title(check: str, lang: str) -> str:
    base, _, arg = check.partition(":")
    key = "check.header_weak" if base == "header" and arg in WEAK_VALIDATED else f"check.{base}"
    return tr(lang, key, arg=arg)


def recommendation(check: str, lang: str) -> str:
    base, _, arg = check.partition(":")
    for key in (f"rec.{check}", f"rec.{base}"):
        if key in I18N[lang]:
            return tr(lang, key, arg=arg)
    return ""


def detail_text(f: Finding, lang: str) -> str:
    return tr(lang, f"msg.{f.msg}", evidence=f.evidence) if f.msg else f.evidence


def sev_label(sev: str, lang: str) -> str:
    return tr(lang, f"sev.{sev}") if sev in SEVERITIES else ""


def sev_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def _generated_at() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z").strip()


# --------------------------------------------------------------------------- #
# Shared data for all outputs
# --------------------------------------------------------------------------- #
def check_matrix(findings: list[Finding]):
    """Returns (checks, targets, grid): checks = [(tool, check)], grid[target][(tool, check)] = Finding."""
    checks = list(dict.fromkeys((f.tool, f.check) for f in findings))
    targets = list(dict.fromkeys(f.target for f in findings))
    grid: dict[str, dict] = {t: {} for t in targets}
    for f in findings:
        grid[f.target][(f.tool, f.check)] = f
    return checks, targets, grid


def report_model(findings: list[Finding], techs: list[dict]) -> dict:
    targets = list(dict.fromkeys([f.target for f in findings] + [t["target"] for t in techs]))
    per = {t: {"issues": [], "passed": [], "na": [], "techs": [],
               "counts": {s: 0 for s in SEVERITIES}} for t in targets}
    for f in findings:
        bucket = {VULN: "issues", OK: "passed"}.get(f.status, "na")
        per[f.target][bucket].append(f)
        if f.status == VULN and f.severity in SEVERITIES:
            per[f.target]["counts"][f.severity] += 1
    for t in techs:
        per[t["target"]]["techs"].append(t)

    n = 0
    totals = {s: 0 for s in SEVERITIES}
    for t in targets:
        issues = sorted(per[t]["issues"], key=lambda f: sev_rank(f.severity))  # stable sort
        numbered = []
        for f in issues:
            n += 1
            numbered.append((f"F-{n:02d}", f))
        per[t]["issues"] = numbered
        for s in SEVERITIES:
            totals[s] += per[t]["counts"][s]
        per[t]["risk"] = next((s for s in SEVERITIES if per[t]["counts"][s]), "")

    tools = [tool for tool in TOOLS if any(f.tool == tool for f in findings)]
    return {"targets": targets, "per": per, "totals": totals, "issues": n,
            "checks": len(findings), "tools": tools}


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #
FINDING_COLS = ["target", "tool", "category", "check", "vulnerable", "severity", "detail",
                "recommendation"]
TECH_COLS = ["target", "url", "technology", "version", "detail"]


def write_csvs(out_dir: Path, findings: list[Finding], techs: list[dict], delim: str,
               lang: str = "en") -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    enc = "utf-8-sig"  # so Excel opens accented characters correctly

    with open(out_dir / "findings.csv", "w", newline="", encoding=enc) as fh:
        w = csv.writer(fh, delimiter=delim)
        w.writerow([tr(lang, f"col.{c}") for c in FINDING_COLS])
        for f in findings:
            w.writerow([f.target, f.tool, f.category, check_title(f.check, lang),
                        tr(lang, f"yn.{f.status}"), sev_label(f.severity, lang),
                        detail_text(f, lang),
                        recommendation(f.check, lang) if f.status == VULN else ""])

    checks, targets, grid = check_matrix(findings)
    with open(out_dir / "matrix.csv", "w", newline="", encoding=enc) as fh:
        w = csv.writer(fh, delimiter=delim)
        w.writerow([tr(lang, "col.target"), tr(lang, "col.total_vulns")]
                   + [f"[{tool}] {check_title(c, lang)}" for tool, c in checks])
        for t in targets:
            cells = [grid[t].get(k) for k in checks]
            statuses = [x.status if x else NA for x in cells]
            w.writerow([t, statuses.count(VULN)] + [tr(lang, f"yn.{s}") for s in statuses])

    with open(out_dir / "technologies.csv", "w", newline="", encoding=enc) as fh:
        w = csv.writer(fh, delimiter=delim)
        w.writerow([tr(lang, f"col.{c}") for c in TECH_COLS])
        for t in techs:
            w.writerow([t.get(c, "") for c in TECH_COLS])


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
HTML_CSS = """
:root{--ink:#1d2939;--muted:#667085;--line:#e4e7ec;--bg:#f9fafb;--card:#fff;--accent:#1f3a5f;
--high:#b42318;--high-bg:#fef3f2;--medium:#c4320a;--medium-bg:#fff6ed;--low:#a15c07;--low-bg:#fefbe8;
--info:#175cd3;--info-bg:#eff8ff;--pass:#067647;--pass-bg:#ecfdf3;--na:#475467;--na-bg:#f2f4f7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.page{max-width:1080px;margin:0 auto;padding:32px 24px 48px}
.cover{background:var(--accent);color:#fff;border-radius:10px;padding:28px 32px;margin-bottom:24px}
.cover .eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:12px;opacity:.75}
.cover h1{margin:6px 0 18px;font-size:28px;line-height:1.2}
.cover dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px 24px;margin:0}
.cover dt{font-size:12px;text-transform:uppercase;letter-spacing:.06em;opacity:.7}
.cover dd{margin:2px 0 0;font-weight:600;word-break:break-word}
nav.toc{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 24px;margin-bottom:24px}
nav.toc h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:0 0 8px;border:0;padding:0}
nav.toc ol{margin:0;padding-left:0;list-style:none;columns:2;column-gap:32px}
nav.toc a{color:var(--accent);text-decoration:none}
nav.toc a:hover{text-decoration:underline}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:24px 28px;margin-bottom:24px}
h2{font-size:20px;margin:0 0 16px;padding-bottom:10px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:24px 0 12px;word-break:break-all}
h3:first-of-type{margin-top:8px}
p{margin:0 0 12px}
.lead{font-size:16px}
.note{color:var(--muted);font-size:13px}
.sev-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:16px 0}
.sev-card{border-radius:8px;padding:12px 16px;border:1px solid transparent}
.sev-card span{display:block;font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
.sev-card b{display:block;font-size:30px;line-height:1.2}
.sev-card.high{background:var(--high-bg);color:var(--high);border-color:#fecdca}
.sev-card.medium{background:var(--medium-bg);color:var(--medium);border-color:#fed7aa}
.sev-card.low{background:var(--low-bg);color:var(--low);border-color:#fde68a}
.sev-card.info{background:var(--info-bg);color:var(--info);border-color:#b2ddff}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:var(--bg);font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);font-weight:600}
td.num,th.num{text-align:center}
td.target{word-break:break-all;font-weight:600}
td.ev{word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;color:#344054}
.badge,.pill{display:inline-block;padding:1px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.sev-high{background:var(--high-bg);color:var(--high)}
.sev-medium{background:var(--medium-bg);color:var(--medium)}
.sev-low{background:var(--low-bg);color:var(--low)}
.sev-info{background:var(--info-bg);color:var(--info)}
.pill.pass{background:var(--pass-bg);color:var(--pass)}
.pill.na,.sev-none{background:var(--na-bg);color:var(--na)}
.finding{border:1px solid var(--line);border-left:4px solid var(--na);border-radius:8px;padding:14px 18px;margin:0 0 12px;break-inside:avoid}
.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)}
.finding.low{border-left-color:var(--low)}
.finding.info{border-left-color:var(--info)}
.finding header{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px}
.finding .fid{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--muted)}
.finding h4{margin:0;font-size:15px}
.finding dl{display:grid;grid-template-columns:150px 1fr;gap:6px 16px;margin:0;font-size:14px}
.finding dt{color:var(--muted)}
.finding dd{margin:0;word-break:break-word}
.finding dd.ev{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;background:var(--bg);border-radius:4px;padding:2px 6px}
.matrix td,.matrix th{white-space:nowrap}
.matrix td:first-child{white-space:normal;min-width:260px}
.matrix th.t{white-space:normal;word-break:break-all;min-width:120px;text-transform:none;letter-spacing:0}
.empty{color:var(--muted);font-style:italic}
ul.evidence li{margin-bottom:4px;word-break:break-all}
ul.evidence a{color:var(--accent)}
footer{text-align:center;color:var(--muted);font-size:12px;margin-top:8px}
@media (max-width:720px){.sev-cards{grid-template-columns:repeat(2,1fr)}nav.toc ol{columns:1}
.finding dl{grid-template-columns:1fr}.page{padding:16px}section{padding:18px}}
@media print{body{background:#fff}.page{max-width:none;padding:0}nav.toc{display:none}
section,.cover{border:0;border-radius:0;padding:0 0 16px;break-inside:auto}
.cover{background:#fff;color:var(--ink);border-bottom:3px solid var(--accent)}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
"""


def write_html(out_dir: Path, findings: list[Finding], techs: list[dict], lang: str = "en",
               evidence: dict[str, list[tuple[str, str]]] | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    def e(v) -> str:  # tool output is untrusted: always escape
        return html.escape(str(v), quote=True)

    def T(key: str, **kw) -> str:
        return e(tr(lang, key, **kw))

    def badge(sev: str) -> str:
        if sev not in SEVERITIES:
            return f'<span class="badge sev-none">{T("risk.none")}</span>'
        return f'<span class="badge sev-{sev}">{e(sev_label(sev, lang))}</span>'

    def thead(*keys: str, num=()) -> str:
        return "<thead><tr>" + "".join(
            f'<th class="num">{T(k)}</th>' if k in num else f"<th>{T(k)}</th>" for k in keys
        ) + "</tr></thead>"

    m = report_model(findings, techs)
    per, targets, totals = m["per"], m["targets"], m["totals"]
    sections = [("summary", "sec.summary"), ("findings", "sec.findings"), ("passed", "sec.passed"),
                ("matrix", "sec.matrix"), ("tech", "sec.tech"), ("scope", "sec.scope")]
    h: list[str] = []
    a = h.append

    a(f'<!doctype html>\n<html lang="{"pt-BR" if lang == "pt" else "en"}">\n<head>\n'
      '<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
      f"<title>{T('report.title')}</title>\n<style>{HTML_CSS}</style>\n</head>\n<body>\n<div class=\"page\">\n")

    # cover
    a('<header class="cover"><div class="eyebrow">scanwitness</div>'
      f"<h1>{T('report.title')}</h1><dl>"
      f"<div><dt>{T('report.generated')}</dt><dd>{e(_generated_at())}</dd></div>"
      f"<div><dt>{T('report.targets')}</dt><dd>{len(targets)}</dd></div>"
      f"<div><dt>{T('report.tools')}</dt><dd>{e(', '.join(m['tools'])) or '—'}</dd></div>"
      f"<div><dt>{T('report.version')}</dt><dd>scanwitness {e(__version__)}</dd></div>"
      "</dl></header>\n")

    # table of contents
    a(f'<nav class="toc"><h2>{T("report.contents")}</h2><ol>')
    for sid, key in sections:
        a(f'<li><a href="#{sid}">{T(key)}</a></li>')
    a("</ol></nav>\n")

    # 1. executive summary
    a(f'<section id="summary"><h2>{T("sec.summary")}</h2>')
    if not targets:
        a(f'<p class="empty">{T("summary.empty")}</p>')
    else:
        key = "summary.text" if m["issues"] else "summary.none"
        a(f'<p class="lead">{T(key, issues=m["issues"], targets=len(targets), checks=m["checks"])}</p>')
        a('<div class="sev-cards">')
        for s in SEVERITIES:
            a(f'<div class="sev-card {s}"><span>{e(sev_label(s, lang))}</span><b>{totals[s]}</b></div>')
        a("</div>")
        a(f'<p class="note">{T("summary.disclaimer")}</p>')
        a(f'<h3>{T("summary.overview")}</h3><div class="wrap"><table>')
        a("<thead><tr>" + f"<th>{T('th.target')}</th>"
          + "".join(f'<th class="num">{e(sev_label(s, lang))}</th>' for s in SEVERITIES)
          + f'<th class="num">{T("th.issues")}</th><th class="num">{T("th.passed")}</th>'
          + f'<th class="num">{T("th.na")}</th><th>{T("th.risk")}</th></tr></thead><tbody>')
        for t in targets:
            p = per[t]
            a(f'<tr><td class="target">{e(t)}</td>'
              + "".join(f'<td class="num">{p["counts"][s]}</td>' for s in SEVERITIES)
              + f'<td class="num"><b>{len(p["issues"])}</b></td><td class="num">{len(p["passed"])}</td>'
              + f'<td class="num">{len(p["na"])}</td><td>{badge(p["risk"])}</td></tr>')
        a("</tbody></table></div>")
    a("</section>\n")

    # 2. findings
    a(f'<section id="findings"><h2>{T("sec.findings")}</h2>')
    if not targets:
        a(f'<p class="empty">{T("summary.empty")}</p>')
    for t in targets:
        a(f"<h3>{e(t)}</h3>")
        if not per[t]["issues"]:
            a(f'<p class="empty">{T("findings.none")}</p>')
        for fid, f in per[t]["issues"]:
            detail = detail_text(f, lang)
            rec = recommendation(f.check, lang)
            a(f'<article class="finding {e(f.severity)}"><header><span class="fid">{e(fid)}</span>'
              f"{badge(f.severity)}<h4>{e(check_title(f.check, lang))}</h4></header><dl>"
              f"<dt>{T('th.tool')}</dt><dd>{e(f.tool)}</dd>"
              f"<dt>{T('th.category')}</dt><dd>{e(f.category)}</dd>")
            if detail:
                a(f'<dt>{T("th.evidence")}</dt><dd class="ev">{e(detail)}</dd>')
            if rec:
                a(f"<dt>{T('th.recommendation')}</dt><dd>{e(rec)}</dd>")
            a("</dl></article>")
    a("</section>\n")

    # 3. passed / not applicable
    a(f'<section id="passed"><h2>{T("sec.passed")}</h2>')
    if not targets:
        a(f'<p class="empty">{T("summary.empty")}</p>')
    for t in targets:
        p = per[t]
        a(f'<h3>{e(t)}</h3><p class="note">{T("passed.count", passed=len(p["passed"]), na=len(p["na"]))}</p>')
        rows = p["passed"] + p["na"]
        if not rows:
            a(f'<p class="empty">{T("passed.none")}</p>')
            continue
        a('<div class="wrap"><table>' + thead("th.check", "th.tool", "th.result", "th.evidence") + "<tbody>")
        for f in rows:
            res = (f'<span class="pill pass">{T("status.pass")}</span>' if f.status == OK
                   else f'<span class="pill na">{T("status.na")}</span>')
            a(f"<tr><td>{e(check_title(f.check, lang))}</td><td>{e(f.tool)}</td><td>{res}</td>"
              f'<td class="ev">{e(detail_text(f, lang))}</td></tr>')
        a("</tbody></table></div>")
    a("</section>\n")

    # 4. matrix (checks as rows, targets as columns)
    checks, mtargets, grid = check_matrix(findings)
    a(f'<section id="matrix"><h2>{T("sec.matrix")}</h2><p class="note">{T("matrix.legend")}</p>')
    if not checks:
        a(f'<p class="empty">{T("summary.empty")}</p>')
    else:
        a('<div class="wrap"><table class="matrix"><thead><tr>'
          f"<th>{T('th.check')}</th><th>{T('th.tool')}</th>"
          + "".join(f'<th class="t">{e(t)}</th>' for t in mtargets) + "</tr></thead><tbody>")
        for tool, c in checks:
            cells = []
            for t in mtargets:
                f = grid[t].get((tool, c))
                if f is not None and f.status == VULN:
                    cells.append(f"<td>{badge(f.severity)}</td>")
                elif f is not None and f.status == OK:
                    cells.append(f'<td><span class="pill pass">{T("status.pass")}</span></td>')
                else:
                    cells.append(f'<td><span class="pill na">{T("status.na")}</span></td>')
            a(f"<tr><td>{e(check_title(c, lang))}</td><td>{e(tool)}</td>{''.join(cells)}</tr>")
        a("</tbody></table></div>")
    a("</section>\n")

    # 5. technology inventory
    a(f'<section id="tech"><h2>{T("sec.tech")}</h2>')
    if not techs:
        a(f'<p class="empty">{T("tech.none")}</p>')
    for t in targets:
        tt = per[t]["techs"]
        if not tt:
            continue
        show_url = any(x.get("url", "").rstrip("/") != t.rstrip("/") for x in tt)
        a(f"<h3>{e(t)}</h3><div class=\"wrap\"><table>"
          + (thead("th.technology", "th.version", "th.details", "th.url") if show_url
             else thead("th.technology", "th.version", "th.details")) + "<tbody>")
        for x in tt:
            a(f"<tr><td><b>{e(x.get('technology', ''))}</b></td><td>{e(x.get('version', ''))}</td>"
              f'<td class="ev">{e(x.get("detail", ""))}</td>'
              + (f'<td class="ev">{e(x.get("url", ""))}</td>' if show_url else "") + "</tr>")
        a("</tbody></table></div>")
    a("</section>\n")

    # 6. scope and methodology
    a(f'<section id="scope"><h2>{T("sec.scope")}</h2><h3>{T("scope.targets")}</h3>')
    if targets:
        a("<ul>" + "".join(f"<li>{e(t)}</li>" for t in targets) + "</ul>")
    else:
        a(f'<p class="empty">{T("summary.empty")}</p>')
    a(f'<h3>{T("scope.tools")}</h3><div class="wrap"><table>' + thead("th.tool", "th.purpose") + "<tbody>")
    for tool in TOOLS:
        a(f"<tr><td><b>{e(tool)}</b></td><td>{T('tool.' + tool)}</td></tr>")
    a(f'</tbody></table></div><p class="note" style="margin-top:12px">{T("scope.na")}</p>')
    if evidence:
        a(f'<h3>{T("scope.evidence")}</h3><p class="note">{T("scope.evidence_note")}</p><ul class="evidence">')
        for target, items in evidence.items():
            links = " · ".join(f'<a href="{e(rel)}">{e(tool)}</a>' for tool, rel in items)
            a(f"<li><b>{e(target)}</b>: {links}</li>")
        a("</ul>")
    a(f'<p class="note">{T("summary.disclaimer")} {T("scope.auth")}</p></section>\n')

    a(f"<footer>{T('footer', version=__version__)}</footer>\n</div>\n</body>\n</html>\n")
    (out_dir / "report.html").write_text("".join(h), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Markdown report
# --------------------------------------------------------------------------- #
def md(v, cell: bool = False) -> str:
    """Escapes text for Markdown (tool output is untrusted: no raw HTML, no formatting)."""
    s = html.escape(str(v), quote=False)
    s = re.sub(r"([\\`*_\[\]|#~])", r"\\\1", s)
    return re.sub(r"\r\n|\r|\n", "<br>" if cell else " ", s)


def md_table(header: list[str], rows: list[list[str]]) -> str:
    """Builds a table from cells that are already escaped."""
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(c if c else " " for c in r) + " |" for r in rows]
    return "\n".join(out)


def write_md(out_dir: Path, findings: list[Finding], techs: list[dict], lang: str = "en",
             evidence: dict[str, list[tuple[str, str]]] | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    def T(key: str, **kw) -> str:
        return md(tr(lang, key, **kw))

    def sev(s: str) -> str:
        return f"**{md(sev_label(s, lang))}**" if s in SEVERITIES else T("risk.none")

    m = report_model(findings, techs)
    per, targets, totals = m["per"], m["targets"], m["totals"]
    L: list[str] = []
    a = L.append

    a(f"# {T('report.title')}\n")
    a(md_table([T("report.generated"), T("report.targets"), T("report.tools"), T("report.version")],
               [[md(_generated_at()), str(len(targets)), md(", ".join(m["tools"])) or "—",
                 f"scanwitness {md(__version__)}"]]) + "\n")

    # 1. executive summary
    a(f"## {T('sec.summary')}\n")
    if not targets:
        a(f"_{T('summary.empty')}_\n")
    else:
        key = "summary.text" if m["issues"] else "summary.none"
        a(T(key, issues=m["issues"], targets=len(targets), checks=m["checks"]) + "\n")
        a(md_table([T("th.severity"), T("th.count")],
                   [[sev(s), str(totals[s])] for s in SEVERITIES]) + "\n")
        a(f"> {T('summary.disclaimer')}\n")
        a(f"### {T('summary.overview')}\n")
        a(md_table([T("th.target")] + [md(sev_label(s, lang)) for s in SEVERITIES]
                   + [T("th.issues"), T("th.passed"), T("th.na"), T("th.risk")],
                   [[md(t, True)] + [str(per[t]["counts"][s]) for s in SEVERITIES]
                    + [f"**{len(per[t]['issues'])}**", str(len(per[t]["passed"])),
                       str(len(per[t]["na"])), sev(per[t]["risk"])] for t in targets]) + "\n")

    # 2. findings
    a(f"## {T('sec.findings')}\n")
    if not targets:
        a(f"_{T('summary.empty')}_\n")
    for t in targets:
        a(f"### {md(t)}\n")
        if not per[t]["issues"]:
            a(f"_{T('findings.none')}_\n")
        for fid, f in per[t]["issues"]:
            a(f"#### {md(fid)} · {md(check_title(f.check, lang))}\n")
            a(f"- **{T('th.severity')}:** {md(sev_label(f.severity, lang))}")
            a(f"- **{T('th.tool')}:** {md(f.tool)} · **{T('th.category')}:** {md(f.category)}")
            detail = detail_text(f, lang)
            if detail:
                a(f"- **{T('th.evidence')}:** {md(detail)}")
            rec = recommendation(f.check, lang)
            if rec:
                a(f"- **{T('th.recommendation')}:** {md(rec)}")
            a("")

    # 3. passed / not applicable
    a(f"## {T('sec.passed')}\n")
    if not targets:
        a(f"_{T('summary.empty')}_\n")
    for t in targets:
        p = per[t]
        a(f"### {md(t)}\n")
        a(f"{T('passed.count', passed=len(p['passed']), na=len(p['na']))}\n")
        rows = p["passed"] + p["na"]
        if not rows:
            a(f"_{T('passed.none')}_\n")
            continue
        a(md_table([T("th.check"), T("th.tool"), T("th.result"), T("th.evidence")],
                   [[md(check_title(f.check, lang), True), md(f.tool, True),
                     T("status.pass") if f.status == OK else T("status.na"),
                     md(detail_text(f, lang), True)] for f in rows]) + "\n")

    # 4. matrix
    checks, mtargets, grid = check_matrix(findings)
    a(f"## {T('sec.matrix')}\n")
    a(f"{T('matrix.legend')}\n")
    if not checks:
        a(f"_{T('summary.empty')}_\n")
    else:
        rows = []
        for tool, c in checks:
            row = [md(check_title(c, lang), True), md(tool, True)]
            for t in mtargets:
                f = grid[t].get((tool, c))
                if f is not None and f.status == VULN:
                    row.append(sev(f.severity))
                elif f is not None and f.status == OK:
                    row.append(T("status.pass"))
                else:
                    row.append(T("status.na"))
            rows.append(row)
        a(md_table([T("th.check"), T("th.tool")] + [md(t, True) for t in mtargets], rows) + "\n")

    # 5. technology inventory
    a(f"## {T('sec.tech')}\n")
    if not techs:
        a(f"_{T('tech.none')}_\n")
    for t in targets:
        tt = per[t]["techs"]
        if not tt:
            continue
        show_url = any(x.get("url", "").rstrip("/") != t.rstrip("/") for x in tt)
        header = [T("th.technology"), T("th.version"), T("th.details")] + ([T("th.url")] if show_url else [])
        a(f"### {md(t)}\n")
        a(md_table(header, [[f"**{md(x.get('technology', ''), True)}**" if x.get("technology") else "",
                             md(x.get("version", ""), True), md(x.get("detail", ""), True)]
                            + ([md(x.get("url", ""), True)] if show_url else []) for x in tt]) + "\n")

    # 6. scope and methodology
    a(f"## {T('sec.scope')}\n")
    a(f"### {T('scope.targets')}\n")
    a("\n".join(f"- {md(t)}" for t in targets) + "\n" if targets else f"_{T('summary.empty')}_\n")
    a(f"### {T('scope.tools')}\n")
    a(md_table([T("th.tool"), T("th.purpose")],
               [[f"**{md(tool, True)}**", T("tool." + tool)] for tool in TOOLS]) + "\n")
    a(f"{T('scope.na')}\n")
    if evidence:
        a(f"### {T('scope.evidence')}\n")
        a(f"{T('scope.evidence_note')}\n")
        a("\n".join(f"- **{md(target)}**: " + ", ".join(f"[{md(tool)}]({rel})" for tool, rel in items)
                    for target, items in evidence.items()) + "\n")
    a(f"> {T('summary.disclaimer')} {T('scope.auth')}\n")
    a("---\n")
    a(f"_{T('footer', version=__version__)}_\n")
    (out_dir / "report.md").write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_formats(value: str) -> list[str]:
    items = [x.strip().lower() for x in value.split(",") if x.strip()]
    if not items:
        raise argparse.ArgumentTypeError("at least one format is required")
    if "all" in items:
        return list(FORMATS)
    alias = {"markdown": "md", "htm": "html"}
    items = [alias.get(x, x) for x in items]
    bad = [x for x in items if x not in FORMATS]
    if bad:
        raise argparse.ArgumentTypeError(
            f"invalid format: {', '.join(bad)} (use {', '.join(FORMATS)} or all)")
    return list(dict.fromkeys(items))


def parse_lang(value: str) -> str:
    v = value.strip().lower().replace("_", "-")
    v = {"pt-br": "pt", "ptbr": "pt", "en-us": "en", "en-gb": "en"}.get(v, v)
    if v not in LANGS:
        raise argparse.ArgumentTypeError(f"invalid language: {value} (use {' or '.join(LANGS)})")
    return v


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="scanwitness",
        description="Runs wafw00f, shcheck, sslscan and whatweb and consolidates the results "
                    "into CSV, HTML and Markdown reports (vulnerable YES/NO per target).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-t", "--target", action="append", help="target (URL or host); can be repeated")
    g.add_argument("-f", "--file", help="file with one target per line (# starts a comment)")
    g.add_argument("--reparse", metavar="DIR", help="only rebuild the reports from DIR/raw, without scanning")
    ap.add_argument("-o", "--output", help="output folder (default: scanwitness_<date>)")
    ap.add_argument("--threads", type=int, default=3, help="targets scanned in parallel (default: 3)")
    ap.add_argument("--timeout", type=int, default=300, help="timeout per tool in seconds (default: 300)")
    ap.add_argument("--skip", default="", help="comma-separated tools to skip")
    ap.add_argument("--format", dest="formats", type=parse_formats, default=list(FORMATS), metavar="FMT",
                    help="comma-separated output formats: csv, html, md or all (default: all)")
    ap.add_argument("--lang", type=parse_lang, default="en", metavar="LANG",
                    help="language of the generated reports: en or pt (default: en)")
    ap.add_argument("-d", "--delimiter", default=None,
                    help="CSV delimiter (default: ',' for --lang en, ';' for --lang pt)")
    ap.add_argument("--no-evidence", action="store_true",
                    help="do not create the evidence/ folder with the raw tool output")
    ap.add_argument("--evidence-host", action="store_true",
                    help="include this machine's hostname in the evidence headers")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args(argv)

    if args.delimiter is not None and len(args.delimiter) != 1:
        ap.error("--delimiter must be a single character")
    delim = args.delimiter or ("," if args.lang == "en" else ";")
    log = (lambda *_: None) if args.quiet else (lambda m: print(m, file=sys.stderr, flush=True))

    if args.reparse:
        out_dir = Path(args.reparse)
        if not (out_dir / "raw").is_dir():
            ap.error(f"raw results folder not found: {out_dir / 'raw'}")
    else:
        out_dir = Path(args.output or f"scanwitness_{datetime.now():%Y%m%d_%H%M%S}")
        if args.file and not Path(args.file).is_file():
            ap.error(f"targets file not found: {args.file}")
        raw = args.target or [l for l in Path(args.file).read_text().splitlines()
                              if l.strip() and not l.lstrip().startswith("#")]
        targets = []
        for v in raw:
            try:
                targets.append(parse_target(v))
            except ValueError as e:
                log(f"[!] {e}")
        if not targets:
            ap.error("no valid targets")
        skip = {s.strip() for s in args.skip.split(",") if s.strip()}
        missing = [t for t, n in TOOLS.items() if not find_bin(*n)]
        if missing:
            log(f"[!] missing tools (will be skipped): {', '.join(missing)}")
        versions = {t: tool_version(t, find_bin(*n)) for t, n in TOOLS.items()
                    if t not in skip and t not in missing}
        scanner_host = socket.gethostname() if args.evidence_host else ""
        raw_dir = out_dir / "raw"
        with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
            futs = [ex.submit(collect, t, raw_dir, args.timeout, skip, log, versions, scanner_host)
                    for t in targets]
            for fu in as_completed(futs):
                fu.result()

    findings, techs = [], []
    for d in sorted((out_dir / "raw").glob("*")):
        if d.is_dir():
            f, t = parse_target_dir(d)
            findings += f
            techs += t

    produced = []
    evidence = {}
    if not args.no_evidence:
        evidence = write_evidence(out_dir, log)
        if evidence:
            produced.append("evidence/")
        elif findings:
            log("[!] no evidence metadata in raw/ (scan made with a version older than 2.1.0); "
                "evidence/ was not created")
    if "csv" in args.formats:
        write_csvs(out_dir, findings, techs, delim, args.lang)
        produced += ["findings.csv", "matrix.csv", "technologies.csv"]
    if "html" in args.formats:
        write_html(out_dir, findings, techs, args.lang, evidence)
        produced.append("report.html")
    if "md" in args.formats:
        write_md(out_dir, findings, techs, args.lang, evidence)
        produced.append("report.md")
    vulns = sum(f.status == VULN for f in findings)
    log(f"[+] {len(findings)} checks, {vulns} vulnerable -> {out_dir}/{', '.join(produced)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
