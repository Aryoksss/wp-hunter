# WP Hunter

WP Hunter adalah toolkit command-line bilingual untuk mengumpulkan target dari
WordPress.org dan Patchstack VDP, mengunduh arsip plugin terverifikasi, serta
menjalankan triage Semgrep secara fail-safe.

[English documentation](README.md)

## Instalasi

Gunakan Python 3.10 atau lebih baru. `pipx` menjaga instalasi tetap terisolasi.

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
| `wp-hunter doctor` | Memeriksa Python, requests, Semgrep, rule, dan disk |
| `wp-hunter preset ...` | Melihat, menjalankan, atau menghapus preset workflow |
| `wp-hunter config ...` | Melihat dan mengubah preferensi pengguna |

Gunakan `wp-hunter COMMAND --help` untuk melihat seluruh opsi.

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
python -m compileall -q wp_hunter tests
python -m unittest discover -s tests -v
python -m build --wheel
```

## Lisensi

[MIT](LICENSE)
