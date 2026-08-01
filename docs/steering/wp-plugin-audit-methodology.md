---
inclusion: always
---

# WordPress Plugin Audit — Deep Dive Methodology

## Layer 1 — Pemetaan Attack Surface Lengkap

Sebelum analisis sink, **wajib** peta SEMUA entrypoint terlebih dahulu:

1. Grep paralel semua entrypoint sekaligus (jangan sequential)
2. Baca SEMUA file PHP — jangan skip file kecil. Bug sering ada di helper/utility class
3. Trace data flow end-to-end: Input → Sanitasi → Storage → Retrieval → Output

## Layer 2 — Analisis Mendalam per Entrypoint

### A. Capability Check Analysis
- Cek apakah `current_user_can()` ada **sebelum** operasi berbahaya
- Waspadai: capability check di `permission_callback` REST tapi tidak di body callback (defense-in-depth bypass)
- Waspadai: `current_user_can('edit_posts')` vs `current_user_can('manage_options')` — beda level

### B. Nonce Analysis
- Nonce tanpa capability check = CSRF protection saja, bukan auth
- Cek apakah nonce bocor ke low-priv user via `wp_localize_script` di halaman yang bisa mereka akses
- `wp_create_nonce('wp_rest')` bocor ke semua logged-in user via REST API header

### C. Input Sanitization Depth Check
- `sanitize_text_field()` — strip HTML tags, tapi tidak lindungi SQLi di ORDER BY/LIMIT
- `absint()` / `intval()` — aman untuk integer
- `wp_kses()` — cek allowlist-nya, apakah mengizinkan `<script src>`, `<iframe>`, event handler (onload, onerror)
- `esc_url()` — tidak mencegah `javascript:` di beberapa konteks lama
- `sanitize_text_field()` pada data yang masuk ke ORDER BY / LIMIT = **tidak aman**

### D. Output Escaping Verification
- Cek setiap `echo` / `print` / `printf` / `wp_send_json` yang outputnya bisa sampai ke browser
- `wp_send_json_success($data)` — jika JS-nya pakai `.html()` atau `innerHTML` untuk render response → XSS
- Template/view file: cek setiap variabel yang di-echo, pastikan ada `esc_html()` / `esc_attr()` / `esc_url()`

## Layer 3 — Second-Order & Stored Vulnerability Hunting

1. **Second-order SQLi**: Data disimpan dari low-priv user (dengan sanitasi), lalu digunakan di query admin tanpa sanitasi ulang
2. **Stored XSS via admin display**: Low-priv user menyimpan data, admin menampilkan tanpa escaping
3. **Type juggling**: PHP `==` vs `===`. `"0" == false`, `"php" == 0`. Cek di auth check / token comparison
4. **Mass assignment**: Plugin yang menerima array dari `$_POST` langsung pass ke `wp_update_user()`, `update_post_meta()` tanpa whitelist field

## Layer 4 — JavaScript / Frontend Analysis

1. Baca semua `.js` file di `assets/js/` — cari:
   - `.html()`, `innerHTML`, `document.write()` dengan data dari server response
   - `eval()`, `Function()` dengan data dari server
   - `location.href =` dengan data dari URL parameter
2. Cek `wp_localize_script` di PHP — data apa yang di-pass ke JS? Ada nonce yang bocor ke role rendah?
3. REST API response di JS: Jika JS fetch REST dan render hasilnya ke DOM via `.html()` → Stored XSS

## Layer 5 — Dependency & Third-Party Code

1. Cek folder `vendor/` — library pihak ketiga sering punya gadget chain untuk PHP Object Injection
2. Cek `composer.json` / `package.json` — identifikasi versi library, cek CVE
3. Bundled library (jQuery, Chart.js, dll) — cek versi, apakah ada known XSS/RCE

## Layer 6 — Edge Case & Bypass Techniques

### Capability Check Bypass
- Apakah plugin grant custom capability ke role rendah?
- Apakah ada `add_role()` / `add_cap()` yang bisa di-trigger oleh low-priv?

### Nonce Bypass
- Apakah nonce di-generate di halaman yang bisa diakses low-priv?
- Apakah ada endpoint yang return nonce tanpa auth?

### Whitelist Bypass
- `in_array($value, $whitelist)` tanpa `strict=true` → type juggling bypass
- Whitelist extension file tapi tidak cek MIME type → upload bypass

### Path Traversal Bypass
- `str_replace('../', '', $path)` → bypass dengan `....//`
- `basename($path)` — aman untuk nama file, tapi tidak untuk path lengkap

## Layer 7 — Checklist Akhir Sebelum Declare "Clean"

- [ ] Semua file PHP sudah dibaca (termasuk file helper kecil)
- [ ] Semua `wp_ajax_nopriv_` di-trace ke sink
- [ ] Semua `permission_callback => '__return_true'` di-trace
- [ ] Semua `$wpdb->query/get_results/get_var/get_row` dicek ada `prepare()` atau tidak
- [ ] Semua `echo` di template ada `esc_html()`/`esc_attr()`
- [ ] JS files dicek untuk DOM XSS
- [ ] `vendor/` dicek untuk gadget chain (jika ada unserialize)
- [ ] File standalone SHORTINIT dicek
- [ ] Tidak ada `__return_true` di permission_callback yang reach sink berbahaya

## Tanda-tanda Plugin Berpotensi Vulnerable (Red Flags)

- `permission_callback => '__return_true'` + operasi write/delete
- `wp_ajax_nopriv_` + operasi yang tidak trivial
- `$wpdb->query()` tanpa `prepare()` di dekatnya
- `echo $_GET[...]` / `echo $_POST[...]` tanpa escaping
- `include($path)` / `require($path)` dengan `$path` dari user
- `unserialize($_COOKIE[...])` / `unserialize($_POST[...])`
- `wp_update_user(array('role' => $_POST['role']))`
- `file_get_contents($_GET['url'])` / `wp_remote_get($_POST['url'])`
- `move_uploaded_file` tanpa validasi extension + MIME
- Nonce di `wp_localize_script` yang di-load di halaman frontend

## Detail Pattern per Kelas Vulnerability

### Arbitrary File Upload
- `wp_ajax_nopriv_*` + `move_uploaded_file` / `file_put_contents` / `wp_handle_upload`
- MIME check berbasis extension saja (bypass: `.phar`, `.pht`, `.phtml`, `.hta`, double extension `.php.jpg`)
- `wp_check_filetype` tanpa `wp_check_filetype_and_ext` (bypass via magic byte)
- SVG upload tanpa sanitasi `<script>` / event handler → Stored XSS
- Zip extraction → path traversal via zipslip

### SQL Injection
- `$wpdb->query("WHERE id=" . $_GET['id'])` tanpa prepare
- `ORDER BY` / `LIMIT` dengan input user (prepare tidak lindungi context ini!)
- `LIKE '%{$_POST['q']}%'` tanpa prepare
- `meta_query` / `tax_query` key dari user

### Privilege Escalation to Admin
- `update_user_meta($id, 'wp_capabilities', ...)` di handler low-priv
- `wp_insert_user` / `wp_update_user` dengan `role` dari `$_POST`
- Mass assignment `$_POST` langsung ke `wp_insert_user`

### Authentication Bypass to Admin
- `wp_set_auth_cookie($id)` dengan `$id` dari input user
- Token generation lemah: `md5(time())`, `uniqid()` tanpa entropy
- IDOR user ID saat reset password / OTP verify

### RCE
- `eval` / `assert` / `create_function` dengan input user
- `system` / `exec` / `shell_exec` / `passthru` / `popen` / `proc_open` tanpa `escapeshellarg`
- `include`/`require` dengan path dari `$_GET`/`$_POST`
- `unserialize` dengan input user → cek `vendor/` untuk gadget chain

## SHORTINIT Pattern — SQLi yang Selalu Exploitable

```php
// File standalone yang bypass WordPress bootstrap:
define('SHORTINIT', true);   // wp_magic_quotes() TIDAK dipanggil!
require_once 'wp-load.php';  // Input mentah = SQLi fully exploitable
```

Ketika `SHORTINIT = true`, WordPress hanya load koneksi database dan options. `wp-settings.php` **tidak dieksekusi**, sehingga `wp_magic_quotes()` **tidak dipanggil**. Input dari `$_GET`/`$_POST` tiba mentah tanpa escaping apapun.

| Kondisi | SQLi via admin-ajax.php | SQLi via SHORTINIT file |
|---|---|---|
| wp_magic_quotes aktif | Ya — quote di-escape | Tidak — tidak dipanggil |
| Exploitable default MySQL | Tidak | Ya |
| Exploitable NO_BACKSLASH_ESCAPES | Ya | Ya |
| Nilai bounty | Medium (kondisional) | High (unconditional) |
