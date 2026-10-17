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
pipx install https://github.com/Aryoksss/wp-hunter/releases/latest/download/wp_hunter-2.3.0-py3-none-any.whl
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
| `wp-hunter watch` | Watch popular plugins for version updates and notify Telegram |
| `wp-hunter bot` | Answer Telegram commands (`/time`, `/status`, `/run`) from your chat |
| `wp-hunter doctor` | Check Python, requests, Semgrep, rules, and disk space |
| `wp-hunter preset ...` | List, inspect, run, or delete workflow presets |
| `wp-hunter config ...` | Show, update, or reset user preferences |

Run `wp-hunter COMMAND --help` for every option.

## Watch for plugin updates

`wp-hunter watch` polls the WordPress.org popular listings, compares each
plugin's current version against the last one it recorded, and reports the ones
that changed. State lives in `watch_state.json` under the WP Hunter config
directory, so repeated runs only report real changes.

If a listing page fails, `watch` reports a partial scan, keeps every version it
had already recorded (nothing is pruned for plugins it never saw), and exits
non-zero so cron and systemd surface the failure instead of logging a green run.

```bash
# One pass over the top ~500 popular plugins, Telegram on changes
wp-hunter watch --limit 5

# Only plugins with at least 100K installs
wp-hunter watch --installs 100K --limit 5

# See what changed without recording state or notifying (dry runs never notify)
wp-hunter watch --dry-run

# Also alert on known vulnerabilities (needs a free WPScan token)
wp-hunter watch --vuln
```

### Change how often it checks

`--every` takes minutes or hours (`30m`, `2h`, `1h30m`); a bare number means
minutes. It drives both the resident `--daemon` loop and the systemd timer.
`--interval` still takes seconds for compatibility, and `--every` wins over it.

```bash
# Resident daemon, re-check every 2 hours
wp-hunter watch --daemon --every 2h --limit 10

# Persist the default, so a plain `wp-hunter watch` uses it
wp-hunter config set watch_every 45m

# Write /etc/systemd/system/wp-hunter-watch.{service,timer} for this interval,
# then daemon-reload + enable + restart (needs root)
sudo wp-hunter watch --install-timer --every 2h --limit 10
```

`--install-timer` creates `/etc/wp-hunter/watch.env` at mode `600` when it is
missing, backs up existing units to `*.bak`, and schedules with
`OnBootSec` + `OnUnitActiveSec`, so any interval works — not only divisors of an
hour.

### Change the cadence from Telegram

`wp-hunter bot` long-polls the same bot and answers **only** messages from your
`TELEGRAM_CHAT_ID`; anything from another chat is ignored. It never scans an
output root — `/run` only refreshes the update watch.

```bash
# Install and start the bot service (root; reads /etc/wp-hunter/watch.env)
sudo wp-hunter bot --install-service

# Or run it in the foreground / process queued commands once
wp-hunter bot
wp-hunter bot --once
```

Commands: `/time` shows the interval, `/time 2h` changes it (and re-arms the
timer when the bot runs as root), `/status` reports tracked plugins, the
interval, pages per run and the next run. `/run` checks the configured pages and
sends the digest; `/run 100` checks 100 pages (~10,000 plugins) and `/run all`
walks the whole directory (capped at 600 pages). Set the default with
`wp-hunter config set watch_pages 100`.

Only one process may poll a bot token at a time. If a webhook is configured for
the bot, `getUpdates` fails with a 409 — delete it first with
`https://api.telegram.org/bot<TOKEN>/deleteWebhook`.

### Vulnerability alerts (optional)

With `--vuln`, `watch` also queries the [WPScan](https://wpscan.com/) database
for known vulnerabilities and flags plugins whose **current** version is
affected (an advisory with no published fix counts for every version). A free
WPScan API token is required; set it in the environment:

```bash
export WPSCAN_API_TOKEN="your-token"
wp-hunter watch --vuln --limit 5
```

WPScan's free tier has a daily request quota; when it runs out, `watch` stops
further checks and reports it instead of failing. Without a token, `--vuln`
prints a warning and continues with update checks only.

### Telegram notifications

Credentials come from the environment; nothing is written to the config file:

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="987654321"
```

Create a bot with [@BotFather](https://t.me/BotFather) to get the token. To find
your chat ID, send the bot a message and read
`https://api.telegram.org/bot<TOKEN>/getUpdates`. When either variable is unset,
`watch` prints the digest to stderr instead of failing.

Keep the values out of unit files. On a server, start from
[`.env.example`](.env.example), put the file at `/etc/wp-hunter/watch.env` with
mode `600`, and load it with `EnvironmentFile=` as the service examples below
do. For local use, copy `.env.example` to `.env` (git-ignored) and export it
with `set -a; . ./.env; set +a`.

### Deploy 24/7 on a VPS

**Option 1 — cron (simplest).** Run one pass every 30 minutes:

```cron
*/30 * * * * TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... /usr/local/bin/wp-hunter watch --limit 10 >>/var/log/wp-hunter-watch.log 2>&1
```

**Option 2 — systemd service.** The daemon stays resident and re-checks every
`--interval` seconds, and stops cleanly on `SIGTERM`.

`/etc/systemd/system/wp-hunter-watch.service`:

```ini
[Unit]
Description=WP Hunter plugin update watcher
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/wp-hunter/watch.env
ExecStart=/usr/local/bin/wp-hunter watch --limit 10 --daemon --interval 3600
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wp-hunter-watch
systemctl status wp-hunter-watch
journalctl -u wp-hunter-watch -f
```

`--interval` is in seconds (minimum 60). The daemon also stops on Ctrl+C when
run in a foreground terminal. Add `--vuln` and `WPSCAN_API_TOKEN` to a service
or cron line if you also want vulnerability alerts.

**Option 3 — systemd timer.** For a single scheduled pass (no resident
process), pair a oneshot service with a timer. Shortcut: `sudo wp-hunter watch
--install-timer --every 30m` writes both files, reloads systemd, and arms the
timer for you.

`/etc/systemd/system/wp-hunter-watch.service`:

```ini
[Unit]
Description=WP Hunter plugin update watcher (one pass)

[Service]
Type=oneshot
EnvironmentFile=/etc/wp-hunter/watch.env
ExecStart=/usr/local/bin/wp-hunter watch --limit 10
```

`/etc/systemd/system/wp-hunter-watch.timer`:

```ini
[Unit]
Description=Run WP Hunter plugin watcher every 30 minutes

[Timer]
OnCalendar=*:0/30
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wp-hunter-watch.timer
systemctl list-timers wp-hunter-watch.timer
journalctl -u wp-hunter-watch.service -f
```

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

The package is organized into a thin `cli` entrypoint that registers focused
command modules (`cli_download`, `cli_commands`, `cli_presets`, `cli_config`,
`cli_watch`) over a shared `cli_context`, plus `cli_menu`/`config`/`i18n`
front-end modules, application `services`, a `triage/` package (`engine`,
`report`, `runner`), and focused support modules for state and migration,
archive safety, Semgrep adaptation, path/security helpers, download and export,
plugin update watching with optional WPScan vulnerability alerts and Telegram
delivery, and source collectors under a shared pooled HTTP client.
Comments are intentionally limited to public contracts and non-obvious security
rationale.

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
