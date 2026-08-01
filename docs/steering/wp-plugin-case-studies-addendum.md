---
inclusion: always
---

# WordPress Plugin Audit — Addendum: File Upload Bypass Patterns

### Pattern 3: Double-Extension MIME Bypass via `strpos()` pada Filter `wp_check_filetype_and_ext` (Blocksy Companion Pro, CVSS 9.8, Juli 2026)

**Konteks**: Blocksy Companion Pro (premium, bukan versi gratis wordpress.org) — Unauthenticated Arbitrary File Upload via parameter `blc-review-images[]`. Published Wordfence 1 Juli 2026. Researcher: Nguyen Ba Khanh. Patch di 2.1.47.

**Root Cause**: Extension "Custom Fonts" mendaftarkan filter `wp_check_filetype_and_ext` untuk approve upload font `.woff2`/`.ttf`. Validasinya salah pakai `strpos()` (cek substring ada di mana saja) bukan `pathinfo($filename, PATHINFO_EXTENSION)` (cek ekstensi terakhir). Fungsi upload lain di extension berbeda (`save_attachments` di WooCommerce Extra > Advanced Reviews, unauthenticated — form review produk) memakai filter global ini untuk validasi MIME.

```php
// VULNERABLE PATTERN
add_filter('wp_check_filetype_and_ext', function($data, $file, $filename, $mimes) {
    if (strpos($filename, '.woff2') !== false || strpos($filename, '.ttf') !== false) {
        // approve sebagai font valid -- SALAH, tidak cek posisi ekstensi
        $data['ext'] = 'woff2';
        $data['type'] = 'font/woff2';
    }
    return $data;
}, 10, 4);

// Attacker upload: shell.woff2.php
// strpos("shell.woff2.php", ".woff2") !== false -> TRUE -> lolos validasi
// Ekstensi eksekusi asli tetap .php -> RCE
```

**Kondisi Eksploitasi (conditional, tapi tetap Critical)**:
- Hanya premium/pro plugin, hanya jika **dua extension aktif bersamaan** (di sini: WooCommerce Extra Advanced Reviews + Custom Fonts) — extension yang inject filter global berbahaya dan extension yang punya entrypoint unauthenticated adalah **file/modul berbeda**. Selalu cek filter `wp_check_filetype_and_ext` / `upload_mimes` yang didaftarkan SATU modul lalu dipakai modul LAIN yang punya entrypoint unauth.
- Versi gratis (non-Pro) biasanya TIDAK mengandung code path premium ini — jangan asumsikan vuln di plugin gratis tanpa verifikasi source.

**Grep Pattern Hunt — Double-Extension / Substring MIME Bypass**:
```
wp_check_filetype_and_ext
add_filter.*upload_mimes
strpos\(.*\$filename
strpos\(.*\$file_name
strpos\(.*\.(php|phtml|phar|woff2|ttf|svg)
pathinfo\(.*PATHINFO_EXTENSION   # cara BENAR, bandingkan dengan strpos yang salah
wp_handle_upload
wp_check_filetype\(
sanitize_file_name
```

**Cara Exploit Konseptual (PoC)**:
1. Identifikasi entrypoint upload unauthenticated (form review, contact form, dsb) yang panggil `wp_handle_upload()` atau `media_handle_upload()`.
2. Cek SEMUA filter yang teregister ke `wp_check_filetype_and_ext` / `upload_mimes` di seluruh plugin/theme aktif — bukan cuma di file yang sama dengan entrypoint. Filter WordPress bersifat GLOBAL, jadi extension A bisa melonggarkan validasi yang dipakai entrypoint di extension B.
3. Baca logic validasi: apakah pakai `strpos()`/`stripos()`/`preg_match` tanpa anchor akhir (`$`), atau `in_array` tanpa `strict=true`, atau cek ekstensi dari `explode('.', $filename)[0]` (ambil elemen pertama, bukan terakhir)?
4. Kalau ditemukan longgar, susun nama file double-extension yang mengandung substring yang di-whitelist DI TENGAH nama file, dengan ekstensi eksekusi asli DI AKHIR:
   - `shell.woff2.php`, `shell.ttf.phtml`, `shell.svg.php5`, `payload.jpg.phar`
5. Upload via multipart/form-data ke endpoint unauthenticated tersebut dengan `Content-Type` yang sesuai whitelist longgar (misal `font/woff2`, `image/svg+xml`) — banyak validator cuma cek `Content-Type` header dari klien tanpa verifikasi magic byte asli.
6. Kalau lolos, cari lokasi upload (biasanya `wp-content/uploads/YYYY/MM/` atau folder custom plugin) — nama file WordPress kadang di-random/hash, jadi cek response JSON/HTML untuk URL file hasil upload.
7. Akses file hasil upload langsung via HTTP — kalau server (Apache/Nginx+PHP-FPM) mengeksekusi berdasarkan ekstensi TERAKHIR (`.php`), maka `shell.woff2.php` dieksekusi sebagai PHP meski "terlihat" seperti font.

**Kenapa bypass ini bekerja secara teknis**:
- Web server menentukan handler eksekusi dari ekstensi PALING KANAN pada nama file (`.php` di `shell.woff2.php`), bukan dari keseluruhan nama.
- Validator WordPress yang salah menentukan "jenis file" dari SUBSTRING di mana saja (`strpos`), bukan dari ekstensi paling kanan (`pathinfo(..., PATHINFO_EXTENSION)`).
- Ketidakcocokan antara "cara web server menentukan tipe eksekusi" vs "cara validator menentukan tipe file" itulah gap yang dieksploitasi — pattern ini sama dengan classic `shell.php.jpg` / `shell.phtml.png` yang sudah lama dikenal, cuma di sini whitelist-nya font (`.woff2`/`.ttf`) bukan image.

**Checklist Wajib Saat Audit Fitur Upload (Update)**:
- [ ] Apakah ada filter custom di `wp_check_filetype_and_ext` / `upload_mimes` selain default WordPress? Grep di SELURUH plugin/theme, bukan cuma modul yang punya entrypoint.
- [ ] Apakah filter itu pakai `strpos`/`stripos`/regex tanpa anchor akhir untuk cocokkan ekstensi?
- [ ] Apakah ada 2+ extension/modul yang saling pakai filter global yang sama — satu melonggarkan whitelist, satu punya entrypoint unauthenticated?
- [ ] Coba nama file: `shell.<whitelisted-ext>.php`, `shell.<whitelisted-ext>.phtml`, `shell.<whitelisted-ext>.phar`
- [ ] Cek apakah server target treat `.phtml`/`.phar`/`.php5`/`.pht` sebagai executable (tergantung config Apache/Nginx) — kalau `.php` diblokir coba varian lain.
- [ ] Setelah lolos validasi PHP-side, cek juga apakah ada `.htaccess` di folder upload yang blokir eksekusi PHP (banyak plugin taruh `deny from all` atau `php_flag engine off` di folder uploads-nya) — kalau ada, coba path traversal ke folder lain atau cari folder upload plugin lain yang tidak protected.

**Scope Wordfence**: Unauthenticated Arbitrary File Upload = selalu Tier 1 Critical in-scope, TIDAK PEDULI apakah conditional (butuh extension/fitur tertentu aktif) — tetap dilaporkan dengan catatan kondisi aktivasinya secara jelas di bagian "Required Access"/prerequisite.

**Referensi**: https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/blocksy-companion/blocksy-companion-2146-unauthenticated-arbitrary-file-upload-via-blc-review-images-parameter

---

### Pattern 4: WordPress Core 7.0 `kses` Rewrite (HTML API) — Cara Cepat Bedakan "Plugin Beneran XSS" vs "Sanitasi Custom Plugin yang Lemah"

**Konteks**: WordPress Core 7.0 "Armstrong" (Mei 2026) me-rewrite `wp_kses_hair()` (parsing atribut HTML di dalam `wp_kses()`/`wp_kses_post()`/`wp_kses_attr()`) dari regex lama ke `WP_HTML_Tag_Processor` (HTML API resmi, `@since 7.0.0 Reliably parses HTML via the HTML API`). `wp_kses_split()` (deteksi boundary tag terluar) TETAP regex, tidak diubah.

**Hasil investigasi langsung** (diverifikasi via standalone PHP harness yang load `wp-includes/kses.php` + `wp-includes/html-api/*` asli dari core 7.0, bukan asumsi baca kode): rewrite ini **memperkuat** sanitasi, TIDAK ditemukan bypass, setelah ~20 test case meliputi:
- Attribute-name quote injection (nama atribut mengandung `"` mentah) -> nama "kotor" gagal match allowlist, ter-strip
- `javascript:`/`data:` protocol (plain, tab/newline evasion, case variation, HTML-entity-encoded `&#106;avascript:`) -> semua konsisten di-strip
- `style` attribute CSS injection (`url(javascript:...)`) -> di-drop total via `safecss_filter_attr`
- Disallowed tag unwrap (`<script><img onerror>`), SVG/foreignObject smuggle, comment-based smuggling -> semua ter-strip/ter-escape
- Backtick quote quirk (legacy IE) -> tidak dianggap quote delimiter oleh tokenizer HTML5
- **Unclosed quote** (`<img src="x onerror="alert(1)">`) -> behave sesuai spek HTML5 (menelan sampai closing quote yang sama ditemukan, TIDAK desync dengan cara browser parse)
- **Duplicate attribute** (`href` didaftarkan 2x) -> atribut PERTAMA yang menang, sesuai spek HTML5 (parser lama regex kadang beda perilaku di titik ini -- ini yang paling penting dicek ulang tiap ada rewrite parser)

**Kesimpulan praktis untuk audit plugin ke depan**:

1. **Kalau ketemu XSS di plugin yang HTML-nya lewat `wp_kses()`/`wp_kses_post()`/`wp_kses_attr()` dengan `$allowed_html` yang wajar** -> kemungkinan besar BUKAN bug di core kses (sudah teruji robust di 7.0), curigai malah:
   - Plugin override `$allowed_html` dengan tag/atribut berbahaya (`<script>`, `onXXX`, `<iframe>` tanpa `sandbox`) yang sengaja/tidak sengaja di-whitelist sendiri
   - Plugin escape output SETELAH `wp_kses()` tapi sebelum render (double-processing yang justru un-escape balik)
   - Plugin sama sekali TIDAK memanggil `wp_kses()` di titik yang benar (baca dulu bahwa itu dipanggil di path yang benar sebelum asumsi "core protect otomatis")
   - Data user disimpan RAW dulu (tanpa sanitasi saat input), lalu di-`wp_kses()` cuma saat render admin tapi TIDAK saat render ke publik/user lain (atau sebaliknya) -- celah second-order

2. **Kalau plugin bikin fungsi sanitasi HTML SENDIRI** (regex manual, `str_replace('<script>', '', ...)`, `strip_tags()` tanpa allowlist ketat) -- INI yang harus dicurigai duluan, BUKAN core. `wp_kses()` core sudah battle-tested; regex custom plugin developer hampir selalu lebih lemah.

3. **`wp_kses_post()` vs `wp_kses_data()` vs `wp_kses($x, array())`** -- cek context yang dipakai plugin. `esc_html()` polos (bukan `wp_kses`) tidak punya allowlist tag sama sekali (full-escape), beda kelas dengan `wp_kses_post()` yang punya allowlist tag "post-like" (`<a>`, `<img>`, `<strong>`, dst). Kalau plugin salah pakai `esc_html()` di tempat yang seharusnya `wp_kses_post()` (atau sebaliknya: pakai `wp_kses_post()` di tempat yang seharusnya full-escape, misal atribut `title`/`alt`), itu jadi bug si plugin, bukan bug core.

4. **Jangan asumsikan "WordPress 7.0 makin ketat jadi plugin lama otomatis attribute-nya kena strip"** -- filter kses HANYA berjalan di titik plugin benar-benar MEMANGGIL fungsi itu. WP 7.0 tidak menambah global auto-sanitization ke semua output; ini murni internal rewrite dari regex ke HTML API di FUNGSI yang sudah ada. Kalau plugin punya XSS karena tidak pernah panggil sanitasi apapun, WP 7.0 tidak akan "menyelamatkan" itu.

**Grep Pattern Hunt -- Bedakan Core-safe vs Plugin-custom Sanitization**:
```
wp_kses_post\(|wp_kses\(|wp_kses_data\(|wp_kses_attr\(     # pakai core kses = kemungkinan aman kalau allowed_html benar
strip_tags\(                                                # lemah, tidak escape atribut event handler dalam tag yang tersisa
str_replace\(\s*array\(.*script.*\)                         # blacklist manual = red flag, gampang di-bypass
preg_replace\(.*<script                                     # regex custom anti-XSS = red flag
esc_html\(|esc_attr\(|esc_url\(                              # full-escape, bukan allowlist -- cek context-nya benar/salah
echo \$.*without any esc_/wp_kses                           # RED FLAG paling jelas
```

**Cara verifikasi cepat kalau ragu core kses ter-bypass atau bukan** (standalone tanpa perlu WP penuh):
```php
<?php
define('ABSPATH', '/path/to/wordpress/');
function __( $s ) { return $s; }
function esc_html( $s ) { return htmlspecialchars($s, ENT_QUOTES); }
function _doing_it_wrong(...$a) {}
function apply_filters($tag,$value,...$r){ return $value; }
function did_action($tag){ return true; }
function wp_allowed_protocols(){ return array('http','https','mailto', /* ... */); }
require_once ABSPATH.'wp-includes/class-wp-token-map.php';
require_once ABSPATH.'wp-includes/html-api/class-wp-html-decoder.php';
require_once ABSPATH.'wp-includes/html-api/class-wp-html-token.php';
require_once ABSPATH.'wp-includes/html-api/class-wp-html-span.php';
require_once ABSPATH.'wp-includes/html-api/class-wp-html-text-replacement.php';
require_once ABSPATH.'wp-includes/html-api/class-wp-html-attribute-token.php';
require_once ABSPATH.'wp-includes/html-api/class-wp-html-unsupported-exception.php';
require_once ABSPATH.'wp-includes/html-api/html5-named-character-references.php';
require_once ABSPATH.'wp-includes/html-api/class-wp-html-tag-processor.php';
require_once ABSPATH.'wp-includes/kses.php';

echo wp_kses( '<PAYLOAD_YANG_DICURIGAI>', array( /* allowed_html plugin */ ) );
```
Pakai ini untuk cepat cek: "apakah payload XSS yang saya temukan di plugin ini SURVIVE lewat `wp_kses()` versi core yang dipakai plugin itu, atau plugin-nya yang bocor sebelum/sesudah panggil `wp_kses()`?" Kalau payload mati di `wp_kses()` core -> bug ada di LOGIC PLUGIN (titik panggil salah, allowed_html terlalu permisif, atau ada jalur lain yang skip sanitasi), bukan di core.

**Referensi audit yang menghasilkan pattern ini**: Audit WordPress Core 7.0 built-in (bukan plugin), Juli 2026 -- dicari kemungkinan bypass kses rewrite sebagai kandidat vuln, hasil negatif (tidak ada bypass ditemukan) tapi menghasilkan metodologi verifikasi yang reusable untuk audit plugin berikutnya.
