# WordPress Plugin Audit — Steering Docs

Koleksi metodologi, case studies, dan template laporan untuk WordPress plugin vulnerability research (Wordfence bug bounty program).

## 📚 File Index

| File | Deskripsi |
|------|-----------|
| [wp-plugin-vuln-research.md](wp-plugin-vuln-research.md) | **Core methodology** — 9 kelas vuln in-scope, grep patterns, capability check rules, scope reminders |
| [wp-plugin-audit-methodology.md](wp-plugin-audit-methodology.md) | **Deep dive methodology** — Layer 1-7 audit checklist, data flow analysis, bypass techniques |
| [wp-plugin-case-studies.md](wp-plugin-case-studies.md) | **CVE case studies** — WP Maps Pro, UpdraftPlus, dan plugin yang sudah dianalisis (clean/vuln) |
| [wp-plugin-case-studies-addendum.md](wp-plugin-case-studies-addendum.md) | **File upload bypass patterns** — Double-extension MIME bypass, WordPress 7.0 kses rewrite |
| [wordfence-report-template.md](wordfence-report-template.md) | **Report template** — Format submission Wordfence yang diterima |
| [pentest-capability.md](pentest-capability.md) | **Pentest capability** — Tools dan teknik yang digunakan |
| [bug-hunting-persistence.md](bug-hunting-persistence.md) | **Persistence rules** — Jangan berhenti sebelum habis metodologi |
| [exhaustive-analysis.md](exhaustive-analysis.md) | **Exhaustive code analysis** — Coverage tracking, anti-pattern, workflow wajib |

## 🎯 Quick Reference

### Entrypoint Grep (Paralel)
```
wp_ajax_nopriv_
permission_callback.*__return_true
register_rest_route
wp_ajax_
add_shortcode
add_action.*(init|wp_loaded|template_redirect|admin_post_nopriv)
```

### Priority Vulnerability Classes
1. Arbitrary PHP File Upload
2. Arbitrary File Read / Download
3. Arbitrary PHP File Deletion
4. Arbitrary Options Update
5. Remote Code Execution
6. Authentication Bypass to Admin
7. Privilege Escalation to Admin
8. Stored XSS (unauth/subscriber)
9. SQL Injection (unauth/subscriber)

### Required Access Priority
`Unauthenticated > Subscriber > Contributor > Author`

### Out of Scope
- Editor-only findings
- Reflected XSS
- CSRF standalone
- Admin-only (`manage_options`)
- Contributor/Author Stored XSS via shortcode
