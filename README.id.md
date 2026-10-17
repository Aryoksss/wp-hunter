# WP Hunter

<p align="center">
  <img src="assets/branding/wp-hunter-logo.png" alt="Logo WP Hunter" width="180">
</p>

<p align="center">
  <a href="https://github.com/Aryoksss/wp-hunter/releases/latest"><img src="https://img.shields.io/github/v/release/Aryoksss/wp-hunter?label=release" alt="Rilis terbaru"></a>
  <a href="https://github.com/Aryoksss/wp-hunter/actions/workflows/ci.yml"><img src="https://github.com/Aryoksss/wp-hunter/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="Lisensi: MIT"></a>
</p>

WP Hunter adalah toolkit command-line bilingual untuk mengumpulkan target dari
WordPress.org dan Patchstack VDP, mengunduh arsip plugin terverifikasi, serta
menjalankan triage Semgrep secara fail-safe.

[English documentation](README.md)

## Instalasi

Gunakan Python 3.10 atau lebih baru. `pipx` menjaga instalasi tetap terisolasi.

Instal wheel dari rilis terbaru:

```bash
pipx install https://github.com/Aryoksss/wp-hunter/releases/latest/download/wp_hunter-2.3.1-py3-none-any.whl
wp-hunter --version
wp-hunter doctor
```

Atau dari source checkout:

```bash
git clone https://github.com/Aryoksss/wp-hunter.git
cd wp-hunter
pipx install .
wp-hunter --version
wp-hunter doctor
```

Untuk development lokal:

```bash
python -m pip install -e ".[dev]"
```

Semgrep bersifat opsional untuk download dan hanya diperlukan oleh proses scan:

```bash
pipx inject wp-hunter semgrep
```


## Mulai cepat

Jalankan menu interaktif ringkas:

```bash
wp-hunter
```

Gunakan command eksplisit untuk workflow yang dapat diulang:

```bash
# Tier instalasi tepat 10K
wp-hunter download wporg --installs 10K

# Minimal 100K instalasi aktif
wp-hunter download wporg --installs 100K --minimum

# Pratinjau tanpa mengunduh
wp-hunter download wporg --installs 50K --preview

# Program Patchstack VDP dengan boost minimal 25%
wp-hunter download patchstack --min-boost 25

# Scan report-only; tidak ada folder plugin yang dihapus
wp-hunter scan ./wp_plugins_10K

# Cleanup live dengan konfirmasi path dan daftar kandidat
wp-hunter scan ./wp_plugins_10K --delete-no-findings
```

Aktifkan Bahasa Indonesia per perintah atau secara permanen:

```bash
wp-hunter --lang id status
wp-hunter config set language id
```

Menu download interaktif meminta batas jumlah download. Gunakan `0` untuk semua
target yang cocok, atau simpan batas default, misalnya 500:

```bash
wp-hunter config set download_limit 500
```

Nama command dan flag tetap menggunakan English pada kedua bahasa.

## Command utama

| Command | Fungsi |
| --- | --- |
| `wp-hunter download wporg` | Mengumpulkan tier tepat atau minimal instalasi |
| `wp-hunter download patchstack` | Mengumpulkan plugin/theme Patchstack VDP |
| `wp-hunter scan DIR` | Triage Semgrep report-only atau cleanup terkonfirmasi |
| `wp-hunter status [DIR]` | Ringkasan download, review, penghapusan, dan hasil scan |
| `wp-hunter watch` | Memantau update versi plugin populer dan notifikasi ke Telegram |
| `wp-hunter bot` | Menjawab perintah Telegram (`/time`, `/status`, `/run`) dari chat Anda |
| `wp-hunter doctor` | Memeriksa Python, requests, Semgrep, rule, dan disk |
| `wp-hunter preset ...` | Melihat, menjalankan, atau menghapus preset workflow |
| `wp-hunter config ...` | Melihat dan mengubah preferensi pengguna |

Gunakan `wp-hunter COMMAND --help` untuk melihat seluruh opsi.

## Pantau update plugin

`wp-hunter watch` memeriksa daftar plugin populer WordPress.org, membandingkan
versi tiap plugin dengan versi terakhir yang dicatat, lalu melaporkan yang
berubah. State disimpan di `watch_state.json` di folder config WP Hunter,
sehingga run berikutnya hanya melaporkan perubahan nyata.

Bila satu halaman daftar gagal, `watch` melaporkan pemindaian tidak lengkap,
mempertahankan semua versi yang sudah tercatat (tidak ada yang dipangkas untuk
plugin yang tidak terlihat), dan keluar dengan kode non-nol agar cron dan
systemd menandainya, bukan mencatat run hijau.

```bash
# Sekali jalan untuk ~500 plugin populer teratas, kirim ke Telegram bila berubah
wp-hunter watch --limit 5

# Hanya plugin dengan minimal 100K instalasi
wp-hunter watch --installs 100K --limit 5

# Lihat perubahan tanpa mencatat state dan tanpa notifikasi (dry-run tidak pernah mengirim notifikasi)
wp-hunter watch --dry-run

# Sekaligus beri alert kerentanan yang diketahui (butuh token WPScan gratis)
wp-hunter watch --vuln
```

### Mengatur seberapa sering pengecekan

`--every` menerima menit atau jam (`30m`, `2h`, `1h30m`); angka tanpa satuan
berarti menit. Nilai ini dipakai oleh loop `--daemon` maupun timer systemd.
`--interval` tetap tersedia dalam detik untuk kompatibilitas, dan `--every`
menang atasnya.

```bash
# Daemon resident, cek ulang tiap 2 jam
wp-hunter watch --daemon --every 2h --limit 10

# Simpan sebagai default, sehingga `wp-hunter watch` biasa memakainya
wp-hunter config set watch_every 45m

# Tulis /etc/systemd/system/wp-hunter-watch.{service,timer} untuk interval ini,
# lalu daemon-reload + enable + restart (butuh root)
sudo wp-hunter watch --install-timer --every 2h --limit 10
```

`--install-timer` membuat `/etc/wp-hunter/watch.env` mode `600` bila belum ada,
membackup unit lama ke `*.bak`, dan menjadwalkan dengan `OnBootSec` +
`OnUnitActiveSec`, jadi interval apa pun bisa dipakai — bukan hanya pembagi 60
menit. Unit yang dihasilkan sudah di-harden (`NoNewPrivileges`, `PrivateTmp`,
`ProtectKernel*`); watcher juga berjalan dengan `ProtectSystem=strict` dan hanya
boleh menulis folder config-nya sendiri.

### Mengubah jadwal dari Telegram

`wp-hunter bot` melakukan long-poll pada bot yang sama dan hanya menjawab pesan
dari `TELEGRAM_CHAT_ID` Anda; pesan dari chat lain diabaikan. Bot ini tidak
pernah memindai folder output — `/run` hanya menyegarkan pemantauan update.

```bash
# Pasang dan jalankan service bot (root; membaca /etc/wp-hunter/watch.env)
sudo wp-hunter bot --install-service

# Atau jalankan di foreground / proses perintah yang mengantre sekali saja
wp-hunter bot
wp-hunter bot --once
```

Perintah: `/time` menampilkan interval, `/time 2h` mengubahnya (dan mengaktifkan
ulang timer bila bot berjalan sebagai root), `/status` melaporkan plugin
terlacak, interval, halaman per run, dan jadwal berikutnya. `/run` memeriksa
halaman sesuai konfigurasi lalu mengirim digest; `/run 100` memeriksa 100
halaman (~10.000 plugin) dan `/run all` menelusuri seluruh direktori (dibatasi
600 halaman). Atur defaultnya dengan `wp-hunter config set watch_pages 100`.

Hanya satu proses yang boleh melakukan polling pada satu token bot. Bila webhook
aktif untuk bot tersebut, `getUpdates` gagal dengan 409 — hapus dulu lewat
`https://api.telegram.org/bot<TOKEN>/deleteWebhook`.

`/run` berjalan di latar belakang, jadi `/status` dan `/time` tetap menjawab
saat pemindaian 600 halaman sedang berjalan; digest dikirim setelah scan selesai.
Watcher dan bot memakai satu lock file, sehingga pass terjadwal dan run manual
tidak menulis watch state bersamaan.

### Alert kerentanan (opsional)

Dengan `--vuln`, `watch` juga menanyakan database [WPScan](https://wpscan.com/)
untuk kerentanan yang diketahui, lalu menandai plugin yang **versi saat ini**
terdampak (advisory tanpa perbaikan dianggap berlaku untuk semua versi). Butuh
token API WPScan gratis; set di environment:

```bash
export WPSCAN_API_TOKEN="token-anda"
wp-hunter watch --vuln --limit 5
```

Tier gratis WPScan punya kuota harian; bila habis, `watch` menghentikan
pemeriksaan lanjutan dan melaporkannya, bukan gagal. Tanpa token, `--vuln`
mencetak peringatan dan lanjut hanya dengan cek update.

### Notifikasi Telegram

Kredensial diambil dari environment variable; tidak ada yang ditulis ke file config:

```bash
export TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="987654321"
```

Buat bot lewat [@BotFather](https://t.me/BotFather) untuk mendapat token. Untuk
mencari chat ID, kirim pesan ke bot lalu buka
`https://api.telegram.org/bot<TOKEN>/getUpdates`. Bila salah satu variable belum
diset, `watch` mencetak ringkasan ke stderr, bukan gagal.

Jangan simpan nilainya di file unit. Di server, mulai dari
[`.env.example`](.env.example), letakkan file di `/etc/wp-hunter/watch.env`
dengan mode `600`, lalu muat lewat `EnvironmentFile=` seperti contoh service di
bawah. Untuk pemakaian lokal, salin `.env.example` ke `.env` (diabaikan git) dan
ekspor dengan `set -a; . ./.env; set +a`.

### Deploy 24/7 di VPS

**Opsi 1 — cron (paling sederhana).** Jalankan sekali tiap 30 menit:

```cron
*/30 * * * * TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=... /usr/local/bin/wp-hunter watch --limit 10 >>/var/log/wp-hunter-watch.log 2>&1
```

**Opsi 2 — service systemd.** Daemon tetap hidup dan memeriksa ulang tiap
`--interval` detik, serta berhenti bersih saat menerima `SIGTERM`.

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

`--interval` dalam detik (minimum 60). Daemon juga berhenti dengan Ctrl+C saat
dijalankan di terminal. Tambahkan `--vuln` dan `WPSCAN_API_TOKEN` ke service
atau cron bila juga ingin alert kerentanan.

**Opsi 3 — timer systemd.** Untuk satu pass terjadwal (tanpa proses yang terus
hidup), pasangkan service oneshot dengan timer. Cara cepat: `sudo wp-hunter
watch --install-timer --every 30m` menulis kedua file, reload systemd, dan
mengaktifkan timer untuk Anda.

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
Description=Jalankan WP Hunter plugin watcher tiap 30 menit

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

## Preset

Tersedia dua preset bawaan yang tidak dapat diubah:

- `wporg-10k`: tier tepat 10K, popular, 50 halaman, update maksimal dua tahun.
- `patchstack-vdp`: seluruh plugin VDP dengan update maksimal dua tahun.

```bash
wp-hunter preset list
wp-hunter preset run wporg-10k --preview

wp-hunter download wporg --installs 10K --minimum \
  --save-preset fresh-10k --preview
wp-hunter preset run fresh-10k
```

Opsi destruktif seperti `force`, reset cache, adopsi output, dan izin penghapusan
tidak pernah disimpan ke dalam preset.

## Migrasi data

Folder output lama tetap dapat dibuka. Manifest, review ledger, dan hasil triage
tanpa versi akan dimigrasikan otomatis ke schema v2 menggunakan penulisan
atomik. Tidak ada file backup yang dibuat. Jika validasi atau replace gagal,
file lama tetap utuh dan proses dihentikan.

Jika folder plugin yang pernah diunduh dihapus, rilis tersebut dicatat dalam
`reviewed_slugs.json`. Versi yang sama tidak akan diunduh lagi, sedangkan versi
baru tetap otomatis masuk antrean. Gunakan `--revisit-reviewed` hanya jika ingin
mengulang rilis tanpa perubahan.

## Keamanan

- Redirect download dibatasi ke host HTTPS WordPress.org terpercaya.
- Path ZIP, symlink, nama duplikat, ukuran, MD5, dan SHA-256 divalidasi.
- Root output diberi marker dan folder luas tidak diadopsi secara diam-diam.
- Error/timeout Semgrep, source hilang, tanggal tidak diketahui, atau temuan apa
  pun membuat plugin tetap disimpan untuk review manual.
- Scan selalu report-only secara default. Cleanup live membutuhkan
  `--delete-no-findings`, konfirmasi path lengkap, dan konfirmasi daftar akhir.
- “Tidak ada kandidat Semgrep” bukan jaminan plugin aman.

## Development

```bash
ruff check wp_hunter tests
ruff format --check wp_hunter tests
mypy wp_hunter
python -m compileall -q wp_hunter tests
python -m unittest discover -s tests -v
python -m build
```

Paket dipecah menjadi entrypoint `cli` tipis yang mendaftarkan modul command
terfokus (`cli_download`, `cli_commands`, `cli_presets`, `cli_config`,
`cli_watch`) di atas `cli_context` bersama, ditambah modul front end
`cli_menu`/`config`/`i18n`, lapisan `services`, paket `triage/` (`engine`,
`report`, `runner`), serta modul pendukung terfokus untuk state dan migrasi,
keamanan arsip, adaptor Semgrep, helper path/keamanan, download dan export,
pemantauan update plugin dengan alert kerentanan WPScan opsional dan pengiriman
Telegram, dan kolektor sumber di atas HTTP client terpool. Komentar sengaja
dibatasi pada kontrak publik dan alasan keamanan yang tidak jelas dari kodenya.

### Rilis

Jalankan skrip rilis dari checkout `main` yang bersih. Skrip menjalankan semua
gate, menaikkan versi di semua tempat (termasuk URL wheel di kedua README),
membangun wheel dan sdist, lalu commit, tag, push, dan membuka rilis GitHub
dengan artifact terlampir.

```bash
scripts/release.sh 2.2.0
```

## Lisensi

[MIT](LICENSE)
