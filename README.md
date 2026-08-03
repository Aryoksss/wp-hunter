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

# One-liner: download all 10K+ plugins
python wp_plugin_hunter.py --installs 10K

# Preview what would be downloaded
python wp_plugin_hunter.py --installs 50K --preview

# Download from Patchstack VDP (bounty programs)
python wp_plugin_hunter.py --patchstack --min-boost 25
```

---

## ✨ Features

- 🎯 **Smart targeting** - Download by active install tiers (1K, 10K, 100K, 1M+)
- 🏆 **Patchstack VDP** - Fetch plugins from Patchstack vulnerability disclosure programs
- ⚡ **Fast parallel downloads** - Multi-threaded with retry logic
- 📊 **Date filtering** - Focus on recently updated plugins
- 🔍 **Search & tag filtering** - Narrow down to specific plugin types
- 💾 **Smart caching** - Skip already-downloaded plugins
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
pip install requests
```

### Optional Dependencies
```bash
# For memory-aware worker limits
pip install psutil

# Optional: local Semgrep engine for triage
python -m pip install semgrep
# or: pipx install semgrep
```

> **Note**: Semgrep is optional. Downloading works with only `requests`; `--auto-triage` and `--triage-only` stop safely with an install hint when Semgrep is unavailable. Triage results are candidates for manual review, not proof that a plugin is vulnerable or clean.

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
3. Filtering options (install tier, date range, limits)
4. Output directory and safe triage mode

You can use numeric choices (`1`–`4`) or type the action name. No flags are
needed for the normal workflow.

### Command-Line Mode

#### Download by Install Tier

```bash
# All plugins with 10K+ active installs
python wp_plugin_hunter.py --installs 10K

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

# Reset manifest (forget all previous downloads)
python wp_plugin_hunter.py --reset-manifest
```

---

## 📁 Output Structure

```
wp_plugins_10K/
├── downloaded_slugs.json          # Manifest of all downloads
├── plugin_list.csv                # Full metadata CSV
├── plugin_slugs.txt               # Simple slug list
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
    "downloaded_at": "2024-01-15 14:23:45"
  }
}
```

---

## 🎛️ All Options

```
Usage: python wp_plugin_hunter.py [OPTIONS]

Source Selection:
  --installs TIER         Active install tier (500, 1K, 5K, 10K, 50K, 100K, 1M)
  --patchstack            Download from Patchstack VDP directory
  --min-boost N           Patchstack: minimum bounty boost % (default: 0)

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

Download Control:
  --workers N             Parallel download threads (default: 3, max: 5)
  --api-workers N         Parallel API fetchers (default: 5)
  --max-download-mb N     Maximum size of one downloaded archive (default: 512)
  --preview               Show what would download without downloading
  --no-download           Skip download (collect metadata only)
  --update-check          Re-download if newer version exists
  --force                 Re-download all (ignore cache)
  --reset-manifest        Clear download history

Triage Safety:
  --auto-triage            Scan and preview folders with no Semgrep candidate
  --confirm-delete         Allow live deletion after the confirmation prompt
  --triage-only DIR        Triage an existing marked folder
  --allow-unmarked-triage  Explicitly allow a legacy folder after verification
  --triage-dry-run         Preview triage deletion candidates
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
# Focus on 100K+ installs (higher bounties)
python wp_plugin_hunter.py --installs 100K
```

### 2. Patchstack VDP Bonuses

```bash
# Target plugins with bounty boosts
python wp_plugin_hunter.py --patchstack --min-boost 35
```

### 3. Fresh Targets (Recently Updated)

```bash
# Plugins updated in last 6 months
python wp_plugin_hunter.py --installs 10K --min-updated-years 0.5
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
an interactive confirmation. The phrase “no Semgrep candidate matched” is not a
security guarantee.

---

## 🔧 Troubleshooting

### API Rate Limiting

The script includes built-in rate limiting (0.3s between requests). If you encounter 429 errors:

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

**Typical Performance** (on 100 Mbps connection):
- **API Collection**: ~5-10 plugins/second
- **Download Speed**: ~3-5 plugins/second (with 3 workers)
- **10K+ tier**: ~500 plugins → ~5-10 minutes total
- **100K+ tier**: ~50 plugins → ~1-2 minutes total

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
