# Changelog

All notable changes to this project are documented here. Versions follow [Semantic Versioning](https://semver.org/).

## [2.2.2] - 2026-11-13

### Changed

- No code changes. Polished the PyPI/GitHub listing: badges in the README (PyPI version, supported Python versions, tests, license), per-version Python classifiers (3.10–3.13), a `Changelog` project link, a couple of extra search keywords (`vulnerability-scanner`, `owasp`) and marked the project `Production/Stable`.

## [2.2.1] - 2026-11-12

### Fixed

- Tools installed by `pipx` (wafw00f and shcheck) are now found. `pipx` keeps them inside scanwitness's own virtualenv, which is not on `PATH`, so they were skipped and the report came out almost empty. `find_bin` now looks next to the running interpreter first, then falls back to `PATH`.
- `Strict-Transport-Security` is reported as `N/A` on plain HTTP targets, since browsers ignore HSTS there. A target that redirects to HTTPS is still checked on the final URL.
- Renamed the WAF check to "Missing web application firewall (WAF)" so a detected WAF reads correctly as `Pass`. The check id (`no_waf`) is unchanged, so `--reparse` of older results still works.

## [2.2.0] - 2026-11-12

First release on PyPI, under the new name `scanwitness` (previously `scanfuse`).

### Added

- `evidence/` folder with the raw console output of every tool run (command, UTC timestamps, tool version, exit code) and `SHA256SUMS.txt`, ready to hand over to the client.
- Reports in English (default) or Portuguese (`--lang pt`).

### Changed

- HTML and Markdown reports redesigned: executive summary by severity, numbered findings with evidence and recommendations, passed checks, check matrix, technology inventory, scope and methodology.
- CLI and docs are in English; output files renamed (`achados.csv` → `findings.csv`, `matriz.csv` → `matrix.csv`, `tecnologias.csv` → `technologies.csv`, `relatorio.*` → `report.*`).

[2.2.2]: https://github.com/IsaacLouzeiro/scanwitness/releases/tag/v2.2.2
[2.2.1]: https://github.com/IsaacLouzeiro/scanwitness/releases/tag/v2.2.1
[2.2.0]: https://github.com/IsaacLouzeiro/scanwitness/releases/tag/v2.2.0
