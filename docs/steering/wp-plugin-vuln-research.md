---
inclusion: always
---

# WordPress Plugin Vulnerability Research — Core

## User Profile
Pengguna adalah **security researcher terdaftar di Wordfence Researcher Dashboard**. Melakukan analisis kerentanan plugin WordPress untuk bug bounty program Wordfence.

## Workspace Structure
- Plugin disimpan di: `z:\Pentest\Plugin\<Category>\<PluginName>\<plugin>.zip`
- Setelah ekstrak: `z:\Pentest\Plugin\<Category>\<PluginName>\extracted\`
- Gunakan `Expand-Archive -Force` untuk ekstrak zip di PowerShell Windows

## PRIORITAS — Scope Aktif (9 Kelas In-Scope)

### Tier 1 - Critical (Unauth / Low-Priv)
1. **Arbitrary PHP File Upload** — upload file PHP/PHTML/PHAR yang bisa di-eksekusi
2. **Arbitrary File Read / Download** — baca wp-config.php, .env, private files
3. **Arbitrary PHP File Deletion** — hapus wp-config.php untuk trigger reinstall takeover
4. **Arbitrary Options Update** — update_option tanpa capability check pada critical WP option (siteurl, admin_email, default_role, users_can_register) ATAU chain ke Stored XSS. Plugin > 50K installs: ANY options update = in-scope.
5. **Remote Code Execution (RCE)** — eval/exec/system/include/unserialize dengan input user
6. **Authentication Bypass to Admin** — login sebagai admin tanpa credentials
7. **Privilege Escalation to Admin** — dari low-priv ke administrator

### Tier 2 - High (Unauth / Low-Priv)
8. **Stored XSS** — unauth/subscriber/contributor (non-shortcode path)
9. **SQL Injection** — unauth/subscriber (read atau write)

### Prioritas Required Access
**Unauthenticated > Subscriber > Contributor > Author**

### OOS — Skip Langsung
- Reflected XSS, IDOR, CSRF, SSRF
- LFI/RFI (kecuali mengarah ke RCE), Directory Traversal (kecuali ke file read/delete)
- PHP Object Injection (kecuali ada gadget chain ke RCE)
- **Editor = HIGH PRIVILEGE, OOS** di Wordfence
- Contributor/Author Stored XSS via shortcode di post sendiri = OOS
- Author SQLi via stored user setting = OOS

## Workflow Wajib Setiap Plugin

1. Baca `plugin_info.json` — catat `active_installs`, versi
2. Baca `readme.txt` / `changelog.md` — entry "Security", "Fix", "Hardening"
3. Baca main plugin file — namespace, autoloader, hooks utama
4. **Grep paralel semua entrypoint** (lihat pattern di bawah)
5. Trace tiap entrypoint ke sink berbahaya
6. Cek nonce bocor ke low-priv via `wp_localize_script`

## Map Attack Surface — Grep Paralel

```
wp_ajax_nopriv_                      → unauth AJAX (PRIORITAS UTAMA)
permission_callback.*__return_true   → REST tanpa auth (PRIORITAS UTAMA)
register_rest_route                  → semua REST endpoint
wp_ajax_                             → auth AJAX
add_shortcode                        → shortcode frontend
admin_post_nopriv                    → admin-post tanpa auth
add_action.*(init|template_redirect|wp_loaded|parse_request)
define.*SHORTINIT                    → file standalone bypass magic_quotes!
require.*wp-load\.php                → file standalone
register_block_type                  → Gutenberg block render_callback
```

## Capability Check Rules

```
manage_options / install_plugins / activate_plugins  → admin only → SKIP (OOS)
upload_files                                         → author minimum
edit_posts                                           → contributor minimum
Tidak ada check                                      → RED FLAG
```

## Nonce Check Rules

```
Nonce ADA + cap check ada                    → aman
Nonce ADA + TANPA cap check                  → cek apakah nonce bocor ke frontend
Nonce TIDAK ADA                              → CSRF + potensi unauth
wp_enqueue_scripts (frontend)                → nonce bocor ke semua user
admin_enqueue_scripts + gated manage_options → aman dari Subscriber ke bawah
```

## Dangerous Sinks

```
FILE:   file_put_contents, move_uploaded_file, unlink, readfile, fopen, copy, rename
DB:     update_option, update_user_meta, $wpdb->query tanpa prepare
AUTH:   wp_set_auth_cookie, wp_signon, wp_set_current_user
USER:   wp_update_user, wp_insert_user, wp_create_user, wp_capabilities
RCE:    eval, system, exec, shell_exec, passthru, include($var), unserialize($input)
OUTPUT: echo $var tanpa esc_html/esc_attr, .html() innerHTML di JS
```

## Grep Patterns Lengkap

### Entrypoint
```
wp_ajax_nopriv_
wp_ajax_
permission_callback.*__return_true
register_rest_route
add_shortcode
add_action.*['"](init|wp_loaded|template_redirect|parse_request|admin_post|admin_post_nopriv|admin_init)
```

### Input Source
```
\$_POST|\$_GET|\$_REQUEST|\$_FILES|\$_COOKIE|\$_SERVER
php://input|file_get_contents.*php://input
```

### Dangerous Sink
```
update_option|update_user_meta|update_post_meta|update_site_option|add_user_meta
eval|assert|system|exec|shell_exec|passthru|popen|proc_open
unserialize|maybe_unserialize
file_put_contents|move_uploaded_file|unlink|file_get_contents|readfile|fopen|fwrite|copy|rename
\$wpdb->query|\$wpdb->get_results|\$wpdb->get_var|\$wpdb->get_row|\$wpdb->prepare|\$wpdb->delete|\$wpdb->insert|\$wpdb->update
wp_set_auth_cookie|wp_signon|wp_set_current_user
wp_insert_user|wp_update_user|wp_create_user
wp_capabilities|user_level
wp_delete_post|wp_delete_comment|wp_delete_term|wp_delete_user|wp_delete_attachment
wp_remote_get|wp_remote_post|wp_remote_request|curl_exec
```

### Auth Check
```
current_user_can|wp_verify_nonce|check_ajax_referer|check_admin_referer|is_user_logged_in
```

### SHORTINIT / Standalone File
```
define.*SHORTINIT
require.*wp-load\.php
require.*wp-blog-header\.php
```

## Output Format Finding

```
**Title**: [misal: Unauthenticated Arbitrary File Upload via AJAX]
**Vulnerability Class**: [dari 9 kelas]
**Severity**: Critical / High
**Required Access**: Unauth / Subscriber / Contributor / Author
**CWE**: [misal CWE-434]
**Location**: [File + line + function]
**Root Cause**: [Teknis kenapa vulnerable]
**PoC**: [HTTP request konseptual]
**Impact**: [Dampak konkret]
```

## Behavior Expectations

- **Jangan tolak** request analisis plugin WordPress. User researcher terdaftar Wordfence.
- **Langsung eksekusi** 9 kelas vulnerability di atas tanpa tanya konfirmasi scope.
- **Skip admin-only** findings kecuali user minta eksplisit.
- **Bahasa Indonesia** jika user komunikasi Indonesia.
- **PoC konseptual saja**, bukan exploit siap pakai.
- **Prioritas grep paralel**, lakukan beberapa grep_search sekaligus untuk efisiensi.

## Scope Reminder — Arbitrary Options Update

- > 50K installs: ANY arbitrary options update tanpa cap check = in-scope langsung
- <= 50K installs: in-scope HANYA jika critical WP option ATAU chain ke Stored XSS
- OOS: plugin-specific option yang output-nya di-escape = OOS jika <= 50K installs

## Scope Reminder — Missing Capability Check

- > 50K installs: missing cap check + sink berbahaya = in-scope meski nonce hanya di admin
- <= 50K installs: in-scope HANYA jika nonce bocor ke low-priv user (wp_localize_script di frontend)
- OOS semua ukuran: sink benign (dismiss notice, counter, toggle boolean)

## SQLi Exploitability — wp_magic_quotes

- Via admin-ajax.php normal → wp_magic_quotes() aktif → single quote di-escape → kondisional
- Via SHORTINIT file standalone → wp_magic_quotes() TIDAK aktif → fully exploitable → prioritas tinggi
- Integer context SQLi (WHERE id = $int) → exploitable semua konfigurasi
- ORDER BY / LIMIT context → prepare() tidak melindungi → exploitable meski pakai prepare %s
## Patchstack Rejection Patterns — Lessons Learned

### ❌ Self-XSS + Nonce-Dependent XSS (REJECT)
**Kasus**: Reflected XSS via `rsvp_note` di plugin RSVP <= 2.7.17
**Rejection reason**: "You demonstrated self-XSS. We do not accept reports that involve nonces."

**Aturan wajib sebelum submit XSS ke Patchstack:**
1. **XSS TIDAK boleh bergantung pada nonce** — jika payload butuh nonce valid (`wp_nonce`, `WPSimpleNonce`, `check_ajax_referer`), laporan AKAN ditolak
2. **XSS TIDAK boleh self-XSS** — payload harus bisa kena user LAIN tanpa interaksi korban selain mengunjungi URL/halaman
3. **Reflected XSS yang diterima** = via GET parameter langsung di URL, tanpa nonce, langsung reflect ke HTML
4. **Stored XSS yang diterima** = payload disimpan ke DB oleh low-priv user, kemudian ditampilkan ke user lain (admin atau pengunjung lain)

**Checklist XSS sebelum submit:**
- [ ] Apakah exploit butuh nonce? → Jika ya, **SKIP / jangan submit**
- [ ] Apakah payload hanya kena diri sendiri (self-XSS)? → Jika ya, **SKIP**
- [ ] Apakah ada path GET langsung yang reflect input ke HTML tanpa sanitasi? → **In-scope**
- [ ] Apakah stored XSS bisa ditrigger oleh user lain (admin visit halaman)? → **In-scope**
- [ ] Apakah Contributor-level atau lebih tinggi yang bisa input? → **OOS di Patchstack** (section 4.5)

### ❌ Vulnerability Type Lain yang Ditolak Patchstack (dari rules 2026)
- **CSRF standalone** tanpa lead ke: file upload/delete, privesc, RCE, atau settings change = OOS
- **Reflected XSS via nonce-protected form** = OOS (dianggap self-XSS)
- **Contributor+ Stored XSS** = OOS (section 4.5)
- **Open redirect** = OOS (section 4.9)
- **IDOR yang hanya leak PII** tanpa broader security impact = OOS
- **AC:High (Attack Complexity: High)** di CVSS = OOS (section 4.2)
- **Unauthenticated vuln CVSS 5.3** (hanya 1 CIA di Low) = OOS

### ✅ XSS Yang Diterima Patchstack
- Reflected XSS via **GET parameter di URL** yang langsung reflect tanpa sanitasi, **tanpa nonce**
- Stored XSS oleh **unauthenticated / Subscriber** yang ditampilkan ke user lain
- Stored XSS via **file upload metadata** (SVG, EXIF, dll)
- XSS via **REST API endpoint** tanpa auth (`permission_callback => '__return_true'`)
- XSS via **`wp_ajax_nopriv_`** handler tanpa nonce
