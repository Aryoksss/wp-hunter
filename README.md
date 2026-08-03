# WP Hunter 🎯

**WordPress Plugin Hunter** - Automated bulk downloader for WordPress plugins by active install tiers. Built for bug bounty researchers targeting the Wordfence vulnerability disclosure program.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Cross-platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)](https://github.com/Aryoksss/wp-hunter)

---

## 🚀 Quick Start

```bash
# Interactive mode (guided setup)
python wp_plugin_hunter.py

# One-liner: download plugins in the exact 10K wp.org tier
python wp_plugin_hunter.py --installs 10K

# Download plugins with at least 10K installs within the pages scanned
python wp_plugin_hunter.py --min-installs 10K

# Preview what would be downloaded
python wp_plugin_hunter.py --installs 50K --preview

# Download from Patchstack VDP (bounty programs)
python wp_plugin_hunter.py --patchstack --min-boost 25
```

---

## ✨ Features

- 🎯 **Smart targeting** - Exact wp.org tiers or minimum-install thresholds
- 🏆 **Patchstack VDP** - Fetch plugins from Patchstack vulnerability disclosure programs
- ⚡ **Fast parallel downloads** - Multi-threaded with retry logic
- 📊 **Date filtering** - Focus on recently updated plugins
- 🔍 **Search & tag filtering** - Narrow down to specific plugin types
- 💾 **Smart caching** - Skip already-downloaded plugins
- 🛡️ **Verified archives** - Validate redirects, ZIP structure, size, MD5, and SHA-256
- 📝 **Manifest tracking** - JSON manifest of all downloads
- 🎨 **Beautiful CLI** - Interactive wizard with color output
- 🔄 **Update detection** - Re-download when newer versions exist
- 🧭 **Semgrep triage** - Local PHP + JavaScript candidate filtering with repository rules

---

## 📋 Requirements

### Core (Download Only)
- **Python 3.10+**
- **requests** library

```bash
python -m pip install -r requirements.txt
```

### Optional Dependencies
```bash
# For memory-aware worker limits
python -m pip install -r requirements-optional.txt

# Optional: local Semgrep engine for triage
python -m pip install semgrep
# or: pipx install semgrep
```

> **Note**: Semgrep is optional. Downloading works with only `requests`. The
> guided wizard checks Semgrep before the final confirmation and, when it is
> unavailable, offers to continue in download-only mode. CLI triage commands
> stop safely with an installation hint. Triage results are candidates for
> manual review, not proof that a plugin is vulnerable or safe.

Before a triage batch starts, WP Hunter validates the complete local rule file.
An invalid rule stops the batch once, before any plugin scan or deletion, and
prints the failing rule diagnostic.

---

## 🛠️ Installation

```bash
git clone https://github.com/Aryoksss/wp-hunter.git
cd wp-hunter
pip install -r requirements.txt
```

---

## 📖 Usage

### Interactive Mode (Recommended for First-Time Users)

```bash
python wp_plugin_hunter.py
```

The wizard will guide you through:
1. Choosing an action: download, scan an existing folder, or check setup
2. Source selection (wp.org or Patchstack VDP)
3. Filtering options (exact tier or minimum installs, Patchstack themes, date range, limits)
4. Output directory and safe triage mode

Use the `↑`/`↓` arrow keys and press `Enter` to select menu options. In
terminals that do not support raw keyboard input, numeric choices or the
action name remain available as a fallback. No flags are needed for the
normal workflow.

### Command-Line Mode

#### Download by Install Tier

```bash
# Plugins in the exact 10K active-install bucket
python wp_plugin_hunter.py --installs 10K

# Plugins with at least 10K installs within the pages scanned
python wp_plugin_hunter.py --min-installs 10K

# Tier options: 500, 1K, 2K, 3K, 5K, 10K, 50K, 100K, 1M, 5M
python wp_plugin_hunter.py --installs 100K --pages 20
```

#### Patchstack VDP Programs

```bash
# All Patchstack VDP plugins
python wp_plugin_hunter.py --patchstack

# Filter by minimum bounty boost %
python wp_plugin_hunter.py --patchstack --min-boost 25

# Only plugins with 35%+ boost
python wp_plugin_hunter.py --patchstack --min-boost 35

# Include Patchstack themes and use the wp.org theme API for downloads
python wp_plugin_hunter.py --patchstack --include-themes
```

#### Advanced Filtering

```bash
# Search by keyword
python wp_plugin_hunter.py --installs 5K --search "security"

# Filter by tag
python wp_plugin_hunter.py --installs 10K --tag "ecommerce"

# Only plugins updated in last 2 years
python wp_plugin_hunter.py --installs 10K --min-updated-years 2

# Limit downloads
python wp_plugin_hunter.py --installs 50K --limit 100
```

#### Preview & Dry-Run

```bash
# Preview what would be downloaded (no actual downloads)
python wp_plugin_hunter.py --installs 10K --preview

# Collect plugin list without downloading
python wp_plugin_hunter.py --installs 10K --no-download
```

#### Update & Re-download

```bash
# Check for newer versions and re-download
python wp_plugin_hunter.py --installs 10K --update-check

# Force re-download all (ignore manifest)
python wp_plugin_hunter.py --installs 10K --force

# Reset a tier's manifest (safe default is cancel)
python wp_plugin_hunter.py --installs 10K --reset-manifest
```

---

## 📁 Output Structure

```
wp_plugins_10K/
├── downloaded_slugs.json          # Manifest of all downloads
├── plugins_10K.json               # Full metadata JSON
├── plugins_10K.csv                # Full metadata CSV
├── vuln_report.txt                # Human-readable triage candidates
├── vuln_plugins.txt               # Candidate plugin names
├── triage_results.json            # Machine-readable triage state
├── deleted_plugins.txt            # Dry-run/live deletion record
├── akismet/
│   ├── akismet.5.3.3.zip          # Downloaded plugin
│   └── plugin_info.json           # Metadata
├── jetpack/
│   ├── jetpack.13.9.zip
│   └── plugin_info.json
└── ...
```

### Manifest Format

`downloaded_slugs.json` tracks all downloads:

```json
{
  "akismet": {
    "filename": "akismet.5.3.3.zip",
    "size_kb": 523,
    "version": "5.3.3",
    "sha256": "...",
    "downloaded_at": "2024-01-15 14:23:45"
  }
}
```

---

## 🎛️ All Options

```
Usage: python wp_plugin_hunter.py [OPTIONS]

Source Selection:
  --installs TIER         Exact active-install tier (500, 1K, 5K, 10K, 100K, 1M)
  --min-installs N        Minimum active installs (threshold mode)
  --patchstack            Download from Patchstack VDP directory
  --min-boost N           Patchstack: minimum bounty boost % (default: 0)
  --include-themes        Patchstack: include themes (default: plugins only)

Filtering:
  --browse MODE           Sort: popular | new | updated | top-rated
  --search KEYWORD        Search by keyword
  --tag TAG               Filter by tag
  --pages N               Max API pages to fetch (100 plugins/page, default: 50)
  --limit N               Max plugins to download
  --min-updated-years N   Only plugins updated in last N years (default: 2)
  --since YYYY-MM-DD      Only plugins updated since date

Output:
  --output DIR            Output directory (default: ./wp_plugins_<tier>)
  --adopt-output-root     Reuse a non-empty legacy folder (CLI asks for its exact path)

Download Control:
  --workers N             Parallel download threads (default: 3, max: 5)
  --api-workers N         Parallel API fetchers (default: 5)
  --max-download-mb N     Maximum size of one downloaded archive (default: 512)
  --preview               Show what would download without downloading
  --no-download           Skip download (collect metadata only)
  --update-check          Re-download if newer version exists
  --force                 Re-download all (ignore cache)
  --no-global-dedup       Disable deduplication across sibling hunter folders
  --reset-manifest        Clear download history

Triage Safety:
  --auto-triage            Scan and preview folders with no Semgrep candidate
  --confirm-delete         Allow live deletion after the confirmation prompt
  --triage-only DIR        Triage an existing marked folder
  --allow-unmarked-triage  Preview a legacy/unmarked folder after verification
  --triage-dry-run         Preview triage deletion candidates
  --triage-workers N       Parallel Semgrep workers (default: 2)
  --triage-timeout N       Per-plugin timeout in seconds (default: 120)
  --triage-mem-mb N        Worker-sizing memory budget (default: 1024 MB)
  --semgrep PATH           Semgrep executable (auto-detected from PATH)
  --semgrep-rules PATH     Rule file (default: rules/wordpress-triage.yml)
  --keep-extracted         Keep extracted source folders after triage

Display:
  --quiet                 Suppress table output, show only progress
  --check                 Verify dependencies and exit
```

---

## 🎯 Use Cases for Bug Bounty

### 1. High-Priority Targets (Popular Plugins)

```bash
# Focus on plugins with at least 100K installs
python wp_plugin_hunter.py --min-installs 100K
```

### 2. Patchstack VDP Bonuses

```bash
# Target plugins with bounty boosts
python wp_plugin_hunter.py --patchstack --min-boost 35
```

### 3. Fresh Targets (Recently Updated)

```bash
# Plugins updated since an explicit date
python wp_plugin_hunter.py --installs 10K --since 2026-01-01
```


### 4. Niche Categories

```bash
# Security plugins (high impact vulns)
python wp_plugin_hunter.py --installs 5K --search "security"

# File management plugins (common vuln class)
python wp_plugin_hunter.py --installs 10K --search "file manager"

# E-commerce (IDOR, payment vulns)
python wp_plugin_hunter.py --installs 10K --tag "ecommerce"
```

---

## 📊 Example Workflow

```bash
# 1. Check setup
python wp_plugin_hunter.py --check

# 2. Preview targets
python wp_plugin_hunter.py --installs 50K --preview

# 3. Download (interactive mode for confirmation)
python wp_plugin_hunter.py --installs 50K

# 4. Export list for tracking
ls wp_plugins_50K/ > downloaded_list.txt

# 5. Optional: triage locally with the repository's Semgrep rules
python wp_plugin_hunter.py --triage-only ./wp_plugins_50K --triage-dry-run
# Review vuln_report.txt, vuln_plugins.txt, and triage_results.json
```

Triage deletes only folders whose successful Semgrep scan returned no candidate
matches. Outdated plugins, missing source, ambiguous findings, and every scan
error are retained. Live deletion additionally requires `--confirm-delete` and
an interactive confirmation whose safe default is **no**. In the guided wizard,
an older WP Hunter output folder can be registered once with the arrow-key menu;
the wizard recommends a dedicated subfolder when the selected location appears
to be a general-purpose folder. CLI adoption with `--adopt-output-root` still
requires exact-path confirmation. An unmarked triage root can only be previewed
until adopted. The phrase “no Semgrep candidate matched” is not a security guarantee.

Dry-run never deletes plugin folders. Extracted scan copies are temporary and
are cleaned after both dry and live scans unless `--keep-extracted` is set.
For an explicitly allowed but still-unmarked root, preview mode preserves all
`extracted/` directories as an additional safeguard.

---

## 🔧 Troubleshooting

### API Rate Limiting

The script spaces WordPress.org API request starts by at least 0.3 seconds. If you encounter 429 errors:

```bash
# Reduce API workers
python wp_plugin_hunter.py --installs 10K --api-workers 2
```


### Download Failures

```bash
# Force retry all failed downloads
python wp_plugin_hunter.py --installs 10K --force

# Check manifest for partial downloads
cat wp_plugins_10K/downloaded_slugs.json
```

### Memory Issues (Large Batches)

```bash
# Reduce workers
python wp_plugin_hunter.py --installs 100K --workers 2

# Or download in smaller chunks
python wp_plugin_hunter.py --installs 100K --pages 10 --limit 1000
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

This tool is for **security research and bug bounty purposes only**. Use responsibly:


- ✅ Download plugins for local security auditing
- ✅ Participate in responsible disclosure programs
- ❌ Do NOT use for malicious purposes
- ❌ Do NOT redistribute plugin files commercially

---

## 🔗 Resources

- **Wordfence Bug Bounty**: https://www.wordfence.com/researcher-dashboard
- **Patchstack VDP**: https://patchstack.com/database/vdp
- **WordPress Plugin API**: https://codex.wordpress.org/WordPress.org_API
- **WPScan Database**: https://wpscan.com/

---

## 📈 Stats & Performance

Performance depends on WordPress.org response times, archive sizes, Semgrep,
and local disk speed. API request starts are spaced by 0.3 seconds globally;
use fewer `--api-workers`, download workers, or triage workers if the remote
service or your machine is under pressure.

---

## 🙏 Credits

Built for the WordPress security research community.

Special thanks to:
- Wordfence team for their vulnerability disclosure program
- Patchstack for the VDP platform
- All security researchers making WordPress safer

---

## 📞 Support

- **Issues**: https://github.com/Aryoksss/wp-hunter/issues
- **Discussions**: https://github.com/Aryoksss/wp-hunter/discussions

---

**Happy Hunting! 🎯🔍**
