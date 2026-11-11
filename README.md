# scanfuse

Runs the standard web recon scans of a pentest and consolidates them into **one report**: an HTML report, a Markdown report and CSV files. For each target, it tells you whether each issue is present (`YES`) or not (`NO`), with severity, evidence and a recommendation.

| Tool | What it checks |
|---|---|
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | presence or absence of a WAF |
| [shcheck](https://github.com/santoru/shcheck) | missing or weak security headers (short HSTS max-age, CSP with `unsafe-inline`/`unsafe-eval`/`*`), headers that leak versions (`Server`, `X-Powered-By`, ...) |
| [sslscan](https://github.com/rbsec/sslscan) | SSLv2/v3, TLS 1.0/1.1, missing TLS 1.3, weak/medium cipher suites, Heartbleed, CRIME, insecure renegotiation, TLS_FALLBACK_SCSV, expired/self-signed/SHA1/short-key certificate |
| [whatweb](https://github.com/urbanadventurer/WhatWeb) | technology fingerprinting, with exposed versions |

A tool missing from `PATH` is skipped with a warning; the others still run.

## Installation

```bash
pip install -r requirements.txt     # wafw00f + shcheck
brew install sslscan                # or: apt install sslscan
apt install whatweb                 # Kali/Debian; on macOS: git clone the official repository
```

The script itself only uses the Python 3.9+ standard library.

## Usage

```bash
python3 scanfuse.py -t https://target.com
python3 scanfuse.py -t target1.com -t https://target2.com:8443
python3 scanfuse.py -f targets.txt -o results --threads 4 --timeout 300
python3 scanfuse.py -f targets.txt --skip whatweb,wafw00f
python3 scanfuse.py --reparse results              # rebuild the reports from results/raw without scanning again
python3 scanfuse.py -t target.com --lang pt        # reports in Portuguese (Brazil)
python3 scanfuse.py -t target.com --format html    # only the HTML report
```

| Option | Description |
|---|---|
| `-t`, `--target` | target URL or host (can be repeated) |
| `-f`, `--file` | file with one target per line (`#` starts a comment) |
| `--reparse DIR` | only rebuild the reports from `DIR/raw` |
| `-o`, `--output` | output folder (default: `scanfuse_<date>`) |
| `--format` | `csv`, `html`, `md` (comma-separated) or `all`; **default: all** |
| `--lang` | language of the generated reports: `en` or `pt`; **default: `en`** |
| `-d`, `--delimiter` | CSV delimiter (default: `,` for `en`, `;` for `pt`, so it opens directly in Excel) |
| `--threads` | targets scanned in parallel (default: 3) |
| `--timeout` | timeout per tool, in seconds (default: 300) |
| `--skip` | comma-separated tools to skip |
| `--no-evidence` | do not create the `evidence/` folder |
| `--evidence-host` | include this machine's hostname in the evidence headers (off by default) |
| `-q`, `--quiet` | suppress progress messages |

The command line and its messages are always in English; `--lang` only changes the content of the generated reports.

## Outputs

```
results/
├── report.html        full report, single self-contained file (print-friendly)
├── report.md          the same report in Markdown (GitHub, Obsidian, wikis...)
├── findings.csv       target,tool,category,check,vulnerable,severity,detail,recommendation
├── matrix.csv         target,total_vulns,[sslscan] TLSv1.0 enabled,[shcheck] Missing ... header,...
├── technologies.csv   target,url,technology,version,detail
├── evidence/          raw tool output to hand over to the client (see below)
│   ├── README.txt
│   ├── SHA256SUMS.txt
│   └── <host_port>/<tool>.txt
└── raw/<host_port>/   working files used to build the reports
```

The HTML and Markdown reports are organized like a pentest report:

1. **Executive summary** – issues by severity (High / Medium / Low / Info) and an overview per target with its overall risk.
2. **Findings** – one entry per issue, per target, sorted from most to least severe, with an ID (`F-01`, ...), severity, tool, evidence and recommendation.
3. **Passed and not applicable checks** – what was checked and found OK, with evidence.
4. **Check matrix** – every check (rows) against every target (columns).
5. **Technology inventory** – technologies and versions detected by whatweb.
6. **Scope and methodology** – targets, tools used and how to read `N/A`.

Values of `vulnerable` in the CSVs: `YES`, `NO`, `N/A` (the check does not apply or the tool did not run for that target). With `--lang pt`: `SIM`, `NÃO`, `N/A`, and the column names are in Portuguese.

All tool output is escaped before going into the HTML and Markdown reports, since it comes from the scanned target.

## Evidence for the client

`evidence/` proves that the scans were actually run. Each `<host_port>/<tool>.txt` starts with a header and then shows the tool's console output:

```
Tool:          sslscan 2.1.4
Target:        https://target.com (target.com:443)
Command:       sslscan --no-colour --xml=raw/target.com_443/sslscan.xml target.com:443
Started:       2026-11-12 10:31:05 UTC
Finished:      2026-11-12 10:31:19 UTC (14s)
Exit code:     0
Collected by:  scanfuse 2.1.0

========================================================================
STANDARD OUTPUT
========================================================================
...
```

- ANSI color codes are removed and the shcheck JSON is indented; nothing else is changed.
- Paths in the command line are relative to the results folder, so no local paths from your machine end up in the evidence.
- `SHA256SUMS.txt` lets the client check that the files were not modified (`cd evidence && sha256sum -c SHA256SUMS.txt`).
- The **Scope and methodology** section of the reports links to each evidence file, so send the whole results folder (or at least the reports together with `evidence/`).
- `--reparse` rebuilds `evidence/` from `raw/`. Scans made before 2.1.0 did not record timestamps and versions, so no evidence is generated for them.
- The raw output can include internal details of the target (IP addresses, banners). Review it before sending.

## Tests

```bash
python3 -m unittest discover tests -v
```

## Upgrading from 1.x

Version 2.0 renamed the output files (`achados.csv` → `findings.csv`, `matriz.csv` → `matrix.csv`, `tecnologias.csv` → `technologies.csv`, `relatorio.*` → `report.*`) and generates reports in English by default. Use `--lang pt` for Portuguese reports (it also keeps `;` as the CSV delimiter, as in 1.x).

> Only scan targets you are authorized to test.
