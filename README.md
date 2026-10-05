# WP Hunter

<p align="center">
  <img src="assets/branding/wp-hunter-logo.png" alt="WP Hunter logo" width="180">
</p>

<p align="center">
  <a href="https://github.com/Aryoksss/wp-hunter/releases/latest"><img src="https://img.shields.io/github/v/release/Aryoksss/wp-hunter?label=release" alt="Latest release"></a>
  <a href="https://github.com/Aryoksss/wp-hunter/actions/workflows/ci.yml"><img src="https://github.com/Aryoksss/wp-hunter/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
</p>

WP Hunter is a bilingual command-line toolkit for collecting WordPress.org and
Patchstack VDP targets, downloading verified plugin archives, and running
fail-safe Semgrep triage.

[Dokumentasi Bahasa Indonesia](README.id.md)

## Install

Python 3.10 or newer is required. `pipx` keeps the command isolated from other
Python projects.

Install the latest release wheel:

```bash
pipx install https://github.com/Aryoksss/wp-hunter/releases/latest/download/wp_hunter-2.1.1-py3-none-any.whl
wp-hunter --version
wp-hunter doctor
```

Or from a source checkout:

```bash
git clone https://github.com/Aryoksss/wp-hunter.git
cd wp-hunter
pipx install .
wp-hunter --version
wp-hunter doctor
```

For local development:

```bash
python -m pip install -e ".[dev]"
```

Semgrep is optional for downloads and required only by `wp-hunter scan`:

```bash
pipx inject wp-hunter semgrep
```


## Quick start

Run the compact interactive menu:

```bash
wp-hunter
```

Use explicit commands for repeatable workflows:

```bash
# Exact WordPress.org 10K install tier
wp-hunter download wporg --installs 10K

# Plugins with at least 100K installs
wp-hunter download wporg --installs 100K --minimum

# Preview without downloading
wp-hunter download wporg --installs 50K --preview

# Patchstack VDP plugins with a boost of at least 25%
wp-hunter download patchstack --min-boost 25

# Report-only Semgrep scan; no plugin folders are deleted
wp-hunter scan ./wp_plugins_10K

# Explicit live cleanup, protected by exact-path and final confirmations
wp-hunter scan ./wp_plugins_10K --delete-no-findings
```

Use `--lang id` or persist the language:

```bash
wp-hunter --lang id status
wp-hunter config set language id
```

The interactive download menu asks for a download limit. Use `0` for all
matching targets, or persist a default such as 500:

```bash
wp-hunter config set download_limit 500
```

Command and option names remain English in both languages.

## Commands

| Command | Purpose |
| --- | --- |
| `wp-hunter download wporg` | Collect exact tiers or minimum-install targets |
| `wp-hunter download patchstack` | Collect Patchstack VDP plugins and themes |
| `wp-hunter scan DIR` | Run report-only or explicitly confirmed Semgrep triage |
| `wp-hunter status [DIR]` | Summarize downloads, removed releases, reviews, and scan results |
| `wp-hunter doctor` | Check Python, requests, Semgrep, rules, and disk space |
| `wp-hunter preset ...` | List, inspect, run, or delete workflow presets |
| `wp-hunter config ...` | Show, update, or reset user preferences |

Run `wp-hunter COMMAND --help` for every option.

## Presets

Two immutable presets are included:

- `wporg-10k`: exact 10K tier, popular browse, 50 pages, two-year update window.
- `patchstack-vdp`: all plugin-only VDP entries with a two-year update window.

```bash
wp-hunter preset list
wp-hunter preset run wporg-10k --preview

# Save only non-destructive download/filter options
wp-hunter download wporg --installs 10K --minimum \
  --save-preset fresh-10k --preview
wp-hunter preset run fresh-10k
```

`force`, cache reset, output adoption, preview state, and deletion permissions are
never stored in presets.

## State and migration

Each output root contains a `.wp-hunter-root` marker and versioned state:

```text
wp_plugins_10K/
├── .wp-hunter-root
├── downloaded_slugs.json
├── reviewed_slugs.json
├── triage_results.json
├── vuln_report.txt
├── vuln_plugins.txt
└── plugin-slug/
    ├── plugin.version.zip
    └── plugin_info.json
```

Opening a v1 output root migrates unversioned manifest, review, and triage JSON
to schema v2. Migration uses an atomic sibling file and does not create backup
files. If validation or replacement fails, the original file remains untouched
and the operation stops.

When a downloaded plugin folder is removed, WP Hunter records the release in
`reviewed_slugs.json`. The unchanged version is skipped on later runs; a newer
WordPress.org version becomes eligible automatically. Use `--revisit-reviewed`
only when that behavior should be bypassed.

## Safety model

- Download redirects must remain on trusted HTTPS WordPress.org hosts.
- ZIP paths, links, duplicate names, member sizes, MD5, and SHA-256 are checked.
- Output roots are marked and broad/project roots cannot be adopted implicitly.
- A Semgrep error, timeout, missing source, unknown date, or any finding retains
  the plugin for manual review.
- Scanning is report-only by default. Live cleanup requires
  `--delete-no-findings`, an exact-path confirmation, and a final candidate-list
  confirmation.
- “No Semgrep candidate matched” is not a security guarantee.

## Development

```bash
ruff check wp_hunter tests
ruff format --check wp_hunter tests
mypy wp_hunter
python -m compileall -q wp_hunter tests
python -m unittest discover -s tests -v
python -m build
```

The package is organized into a thin `cli`/`cli_menu`/`config`/`i18n` front end,
application `services`, a `triage/` package (`engine`, `report`, `runner`), and
focused support modules for state and migration, archive safety, Semgrep
adaptation, path/security helpers, download and export, and source collectors
under a shared pooled HTTP client. Comments are intentionally limited to public
contracts and non-obvious security rationale.

### Releasing

Run the release script from a clean `main` checkout. It runs every gate, bumps
the version everywhere (including the wheel URL in both READMEs), builds the
wheel and sdist, then commits, tags, pushes, and opens the GitHub release with
the artifacts attached.

```bash
scripts/release.sh 2.2.0
```

## License

[MIT](LICENSE)
