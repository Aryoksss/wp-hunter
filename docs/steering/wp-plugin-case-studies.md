---
inclusion: always
---

# WordPress Plugin Audit — CVE Patterns & Case Studies

## Referensi CVE Patterns Kritis

### Pattern 1: "Support Backdoor" Feature (WP Maps Pro CVE-2026-8732)

**Konteks**: CVE-2026-8732 (CVSS 9.8) — WP Maps Pro ~15.000 sales Envato Market.
Wordfence memblokir 2.858 exploitation attempts dalam 24 jam setelah disclosure.
Researcher: David Brown. Patch di versi 6.1.1 (20 Mei 2026).

**Root Cause**: Fitur "Temporary Access" untuk support staff FlipperCode:
- Handler terdaftar sebagai `wp_ajax_nopriv_` → unauthenticated
- Hanya nonce check, TANPA `current_user_can()`
- Nonce `wpgmp_temp_access_nonce` di-embed ke **setiap halaman frontend** via `wp_localize_script`
- Handler melakukan `wp_create_user` + `wp_update_user` dengan role `administrator`
- Attacker: ambil nonce dari HTML → POST admin-ajax.php → dapat akun admin baru

**Attack Chain PoC (Konseptual)**:
```
Step 1: GET https://target.com/ → ambil wpgmp_local.wpgmp_temp_access_nonce dari HTML
Step 2: POST /wp-admin/admin-ajax.php
        action=wpgmp_temp_access_ajax&security=<nonce>
        → Response: {"success":true,"data":{"login_url":"https://target.com/?token=xxx"}}
Step 3: GET https://target.com/?token=xxx → wp_set_auth_cookie() → admin session aktif
```

**Grep Pattern Hunt "Support Backdoor"**:
```
wp_ajax_nopriv_.*temp
wp_ajax_nopriv_.*support
wp_ajax_nopriv_.*access
wp_ajax_nopriv_.*login
wp_create_user
wp_insert_user
wp_update_user.*administrator
role.*=>.*administrator
role.*=>.*admin
wp_set_auth_cookie
generate.*login.*url
magic.*login
auto.*login
```

**Pelajaran**:
1. Nonce bocor via `wp_localize_script` di frontend = nonce tidak berguna sebagai auth
2. `wp_verify_nonce()` hanya lindungi CSRF, bukan autentikasi
3. Script di-enqueue via `wp_enqueue_scripts` (frontend) → bocor ke semua user
4. Script di-enqueue via `admin_enqueue_scripts` + gate `manage_options` → aman
5. Plugin komersial Envato/CodeCanyon tidak punya peer review WordPress.org → justru lebih berbahaya

**Scope**: Fitur "temp access" / "support login" via `wp_ajax_nopriv_` = **langsung Tier 1 Critical, in-scope**

---

### Pattern 2: Authentication Bypass via External Connection (UpdraftPlus Juni 2026)

**Konteks**: Critical Unauthenticated Authentication Bypass di UpdraftPlus — 3 juta+ active installs.
Dipublish Wordfence 10 Juni 2026. Submission diterima 2 Juni 2026.
**Hanya exploitable di sites yang pernah connect ke UpdraftCentral**.

**Pola Auth Bypass yang Umum di Plugin dengan Fitur External Connection**:

```php
// Pattern 1: Token dari user langsung set auth
$key = $_POST['connection_key'];
$user_id = $wpdb->get_var("SELECT user_id FROM ... WHERE key = '$key'");
wp_set_auth_cookie($user_id);  // VULNERABLE jika key bisa diprediksi/leaked

// Pattern 2: Verifikasi tidak dicek return value-nya
$token = $_GET['token'];
$user = verify_token($token);  // bisa return null/false
wp_set_current_user($user->ID);  // VULNERABLE jika tidak cek $user dulu

// Pattern 3: Logic flaw — kondisi salah urutan
if ($this->is_authenticated || $this->verify_key($_POST['key'])) {
    $this->authenticate_user();
}

// Pattern 4: Weak token generation
$token = md5($user_id . time());     // predictable!
$token = substr(md5(rand()), 0, 8);  // brute-forceable
$token = uniqid();                    // microsecond timestamp
```

**Grep Pattern Hunt Auth Bypass**:
```
wp_set_auth_cookie
wp_set_current_user
wp_signon
wp_create_user
wp_insert_user
set_logged_in_cookie
authenticate
md5.*time\(\)
md5.*rand\(\)
uniqid\(\)
substr.*md5
```

**Checklist Plugin dengan Fitur External Connection** (backup cloud, OAuth, SSO, remote management):
- [ ] Cek semua code path yang memanggil `wp_set_auth_cookie()` — siapa yang bisa trigger?
- [ ] Cek semua code path yang memanggil `wp_set_current_user()` — validasi identitas dilakukan sebelumnya?
- [ ] Cek token/key generation — apakah `wp_generate_password(32, false)` atau `md5(time())`/`uniqid()`?
- [ ] Cek apakah ada `admin_action_*` / `init` hook yang memproses connection callback tanpa nonce
- [ ] Cek endpoint yang menerima callback dari service eksternal — validasi asal request?
- [ ] Cek `add_action('wp_loaded')` / `add_action('init')` yang memproses `$_GET['token']`

**Pelajaran**:
1. Plugin besar bukan berarti lebih aman — 3 juta installs tetap punya critical vulnerability
2. Fitur opsional = attack surface tambahan — code path yang hanya aktif jika fitur diaktifkan sering luput dari review
3. Conditional exploitability bukan OOS — meski hanya exploitable di site yang pernah connect, Wordfence tetap assign Critical karena dampaknya full admin takeover

---

## Catatan Analisis Plugin Sebelumnya

### WP File Manager 8.0.4 (Apr 2026)
- Sudah ter-hardening (CVE-2020-25213 fix sejak 6.9), tidak ada `connector.minimal.php`
- Semua AJAX handler cek `manage_options` + nonce, REST API backup butuh `fm_key` 25 char random + admin
- **Tidak ada vulnerability in-scope**

### Brevo (mailin) 3.3.4 (Mei 2026)
- Grant `view_custom_menu` ke Editor — editor bisa harvest nonce `ajax_sib_admin_nonce`
- Banyak AJAX admin hanya cek nonce tanpa `current_user_can('manage_options')`
- `SIB_ATTRIBUTE` allowlist `wp_kses` mengizinkan `<script src>` dan `<iframe src>`
- Editor bisa replace Brevo API key → intercept outbound `wp_mail` termasuk password reset admin
- **Editor-only path → OOS** (Editor high-privilege di Wordfence policy)
- **Tidak ada vulnerability in-scope**

### Presto Player 4.1.3 (Mei 2026)
- 100K+ install, semua REST controller cek capability — no bypass
- AJAX nopriv: hanya benign (progress tracking, view counter capped 100)
- AJAX auth: cek nonce + capability, atau nonce action tidak pernah dibuat (dead code)
- Shortcodes semua output via `esc_attr` / `esc_url` / `wp_json_encode`
- **Tidak ada vulnerability in-scope**

### Bookero Plugin 2.3 (Mei 2026)
- Zero AJAX, zero REST, zero database operations, zero file operations
- Semua shortcode attributes di-cast ke `(int)`, `esc_js()` untuk string output
- **Tidak ada vulnerability in-scope**

### CatFolders Lite 2.5.4 (Mei 2026)
- 100K+ install, semua REST gated `upload_files` (Author minimum)
- Real bug (OOS): Stored SQLi Author+ via `sortFile` ORDER BY tanpa prepare
- Author SQLi = OOS Wordfence policy
- **Tidak ada vulnerability in-scope**

### AI Share & Summarize 1.9.2 (Mei 2026)
- Unauth REST `/aiss/v1/track` — hanya click counter, platform whitelist, `sanitize_text_field()` sebelum insert
- Semua `$wpdb` query pakai `$wpdb->prepare()` dengan `%s`/`%d`
- **Tidak ada vulnerability in-scope**

### Ads.txt File Manager By Magicbid 2.2.2 (Mei 2026)
- Nonce di-localize hanya di halaman admin gated `manage_options` — tidak bocor ke Subscriber
- `wp_ajax_create_*` dan `wp_ajax_restore_*`: nonce check ada, tanpa cap check, sink `file_put_contents` — OOS karena nonce tidak reachable dari Subscriber
- `wp_ajax_mb_plgn_ads_dismiss_review_notice`: tanpa nonce/cap check — sink `update_option(benign)` — OOS
- **Tidak ada vulnerability in-scope**

### Manage User Columns 1.0.6
- `ajax-functions.php` concat `$_POST['q']` langsung ke LIKE query tanpa `prepare()`
- Kode salah, tapi tidak exploitable di environment WP standar karena `wp_magic_quotes()` sudah escape quote
- Tetap valid secara CWE-89 untuk dilaporkan, catat caveat exploitability

### GPTranslate (contoh SHORTINIT pattern)
- `ajax-handler.php` menggunakan `define('SHORTINIT', true)` + `require wp-load.php`
- `$_GET['language']` masuk ke query tanpa magic quotes mitigation
- SQLi confirmed exploitable di semua konfigurasi default → **fully in-scope**

### WP-DraftsForFriends 1.0.2 (Juni 2026)
- Tidak ada `wp_ajax_nopriv_`, tidak ada REST, tidak ada shortcode
- `echo $shared_draft->post_title` tanpa `esc_html` — Author Stored XSS = OOS
- `can_view()`: hash masuk ke `$wpdb->prepare()` — aman dari SQLi
- **Tidak ada vulnerability in-scope**

### GD bbPress Tools 4.0.1 (Juni 2026)
- Plugin bbPress addon: BBCode, signature, quote, tweaks, views
- Zero AJAX, zero REST, zero standalone SHORTINIT, zero file operations, zero $wpdb queries
- Admin settings gated `activate_plugins` + nonce — OOS
- Signature save: `personal_options_update` / `edit_user_profile_update` — WP handle nonce/permission internal
- `format_signature()` via `wp_filter_post_kses()` sebelum `update_user_meta` — sanitasi saat save, bukan render
- BBCode `_tag()` render attribute via `esc_attr()` — XSS dicegah
- CSS injection via `[color]` / `[size]` BBCode — `esc_attr()` block attribute escape, pure CSS injection OOS
- JS `front.js`: quote masuk ke `.val()` textarea bukan DOM innerHTML — bukan DOM XSS
- Changelog v4.0: "Fix: XSS vulnerability related to BBCodes processing" — sudah di-patch
- **Tidak ada vulnerability in-scope**

## Referensi
- elFinder plugin: CVE-2020-25213 (WP File Manager 6.0-6.8 RCE via `connector.minimal.php`)
- Wordfence vulnerability database: https://www.wordfence.com/threat-intel/vulnerabilities
- WP Maps Pro CVE-2026-8732: https://www.wordfence.com/blog/2026/05/15000-wordpress-sites-affected-by-administrator-account-creation-vulnerability-in-wp-maps-pro-wordpress-plugin/
- UpdraftPlus Auth Bypass: https://www.wordfence.com/blog/2026/06/critical-unauthenticated-authentication-bypass-vulnerability-patched-in-updraftplus-wordpress-plugin/
- PHPGGC gadget chains untuk WordPress: https://github.com/ambionics/phpggc
