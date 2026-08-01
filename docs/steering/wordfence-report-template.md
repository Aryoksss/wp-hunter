---
inclusion: auto
description: Template format wajib untuk Wordfence vulnerability report submission
---

# Wordfence Report Template

Setiap kali user minta buat report.md untuk vulnerability WordPress plugin, WAJIB gunakan format berikut persis. Jangan ubah struktur heading atau urutan section.

## Template Format Wajib

# Wordfence Vulnerability Report

## Vulnerability Details
**Vulnerability Type:** [Tipe vulnerability lengkap]
**Common Weakness (CWE) Type:** CWE-XXX: [Nama CWE lengkap] *(Note: tambahan jika ada originating CWE)*
**Software/Plugin Name:** [Nama plugin]
**Plugin Slug:** [slug]
**Version Affected:** <= [versi]
**Authentication Level Required:** [Unauthenticated / Subscriber / Contributor / Author]
**CVSS Score:** [skor] ([severity])
**CVSS Vector:** CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X

### References to Affected Code
- [Deskripsi lokasi kode]: [URL ke plugins.trac.wordpress.org atau file+line]

### References
- [Link referensi relevan]

---

## Description
[Paragraf deskripsi. Bahasa Inggris formal.]

## Root Cause Analysis
[Numbered list tiap flaw. Sertakan code snippet.]

## Proof of Concept (PoC)

**Prerequisites:**
* [Syarat exploit]

**Proof of Concept (PoC) Script:**
[Deskripsi + script Python lengkap]

**Usage Example:**
[Command bash]


## How to Reproduce (Manual)

**Step-by-step manual reproduction using browser or Burp Suite:**

**Step 1 — [Deskripsi langkah pertama]**
```
METHOD /path HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

param=value
```
Expected: [Apa yang diharapkan dari response]

**Step 2 — [Deskripsi langkah kedua]**
```
METHOD /path HTTP/1.1
Host: target.com

param=PAYLOAD
```
Expected: [Apa yang muncul di response / browser]

**Result:** [Deskripsi hasil akhir yang membuktikan vulnerability]
## Remediation / Suggested Fix
[Numbered list saran perbaikan teknis]

## Rules
- Selalu bahasa Inggris untuk report
- Sertakan CVSS vector lengkap
- Link ke plugins.trac.wordpress.org jika bisa
- PoC script Python runnable
- Root Cause Analysis detail dengan code snippet
- Sertakan section **How to Reproduce (Manual)** dengan step-by-step Burp/browser, raw HTTP request per step
- Jangan tambah section lain di luar template (no Timeline, no Impact terpisah)

## Wordfence Vulnerability Type Reference (Dashboard Select Options)

Saat menulis report, gunakan **Vulnerability Type** yang PERSIS sesuai daftar berikut. Ini adalah opsi yang tersedia di Wordfence Researcher Dashboard:

### Authentication & Authorization
| ID | Type |
|----|------|
| 3 | Account Takeover (Admin) |
| 4 | Account Takeover (Limited/User) |
| 1 | Authentication Bypass (Admin) |
| 2 | Authentication Bypass (Non-Admin) |
| 12 | Insecure Direct Object Reference (IDOR) with Availability Impact |
| 10 | Insecure Direct Object Reference (IDOR) with Confidentiality Impact |
| 11 | Insecure Direct Object Reference (IDOR) with Integrity Impact |
| 9 | Missing Authorization with Availability Impact |
| 7 | Missing Authorization with Confidentiality Impact |
| 8 | Missing Authorization with Integrity Impact |
| 5 | Privilege Escalation (Admin) |
| 6 | Privilege Escalation (Non-Admin) |

### Business Logic & Financial Abuse
| ID | Type |
|----|------|
| 46 | Business Logic Abuse (Non-Payment) |
| 45 | Payment / Checkout Manipulation |

### Content & Configuration Manipulation
| ID | Type |
|----|------|
| 39 | Arbitrary Content Deletion |
| 38 | Arbitrary Content Modification |
| 41 | Plugin / Theme Installation or Activation |
| 40 | Settings / Configuration Changes |

### Cross-Site Vulnerabilities
| ID | Type |
|----|------|
| 24 | Cross-Site Request Forgery (CSRF) with Availability Impact |
| 22 | Cross-Site Request Forgery (CSRF) with Confidentiality Impact |
| 23 | Cross-Site Request Forgery (CSRF) with Integrity Impact |
| 21 | Reflected Cross-Site Scripting (XSS) |
| 20 | Stored Cross-Site Scripting (XSS) |

### Data Exposure & Information Disclosure
| ID | Type |
|----|------|
| 35 | Content Disclosure (Private Content) |
| 37 | Credential / Secret Disclosure |
| 36 | General Information Disclosure |
| 34 | Unauthorized Data Access (PII / User Data) |

### File System Access
| ID | Type |
|----|------|
| 32 | Arbitrary File Deletion (Non-PHP) |
| 31 | Arbitrary File Deletion (PHP Included) |
| 28 | Arbitrary File Read / Download (Non-PHP) |
| 27 | Arbitrary File Read / Download (PHP Included) |
| 25 | Arbitrary File Upload (Leading to RCE) |
| 30 | Arbitrary File Write / Overwrite (Non-PHP) |
| 29 | Arbitrary File Write / Overwrite (PHP Included) |
| 33 | Directory Traversal |
| 26 | Limited File Upload (Non-RCE Impact) |

### Injection & Code Execution
| ID | Type |
|----|------|
| 48 | Arbitrary Shortcode Execution |
| 49 | IP Spoofing |
| 17 | Local File Inclusion (LFI) - Arbitrary |
| 18 | Local File Inclusion (LFI) - PHP Files Only |
| 16 | PHP Object Injection |
| 15 | Remote Code Execution / Code Injection |
| 19 | Remote File Inclusion (RFI) |
| 14 | SQL Injection (Full Access - DB Read/Write) |
| 13 | SQL Injection (Standard DB Read) |

### Malicious Developer Behavior
| ID | Type |
|----|------|
| 47 | Intentional Backdoors Accessible by Threat Actors |

### Server & Network Abuse
| ID | Type |
|----|------|
| 44 | Denial of Service (DoS) |
| 43 | Open Redirect / Phishing |
| 42 | Server-Side Request Forgery (SSRF) |

## Mapping Rules
- Untuk report, field **Vulnerability Type** harus PERSIS salah satu dari daftar di atas
- Jika vulnerability cocok multiple type, pilih yang paling spesifik/primary impact
- Contoh mapping:
  - Path traversal yang hapus file .zip = **Arbitrary File Deletion (Non-PHP)** (ID 32)
  - Path traversal yang bisa hapus .php = **Arbitrary File Deletion (PHP Included)** (ID 31)
  - SQLi yang bisa baca data = **SQL Injection (Standard DB Read)** (ID 13)
  - Missing auth yang hapus content = **Missing Authorization with Availability Impact** (ID 9)
  - Missing auth yang bisa write file = **Missing Authorization with Integrity Impact** (ID 8)

## Impact Statement Field
- Tambahkan field **Impact Statement** di Vulnerability Details section, setelah CVSS Vector
- Format: **Impact Statement:** [satu kalimat, maksimal 200 karakter]
- Contoh: "Unauthenticated users can upload image files."
- Harus ringkas, satu kalimat, menjelaskan siapa bisa melakukan apa
- Pattern: "[Role]-level users can [action] via [method]."
## OWASP 2021 Field Rules
- Tambahkan 2 field **OWASP 2021 Class** dan **OWASP 2021 Type** di Vulnerability Details section, setelah CWE line
- **OWASP 2021 Class** = kategori OWASP Top 10 2021 yang paling relevan (format: `A0X:2021 – Nama`)
- **OWASP 2021 Type** = nama vulnerability type spesifik dalam kategori tersebut

### OWASP Top 10 2021 Reference
| Class | Nama | Contoh Type |
|-------|------|-------------|
| A01:2021 | Broken Access Control | Missing Authorization, IDOR, Privilege Escalation |
| A02:2021 | Cryptographic Failures | Weak Nonce, Insecure Token Generation |
| A03:2021 | Injection | SQL Injection, XSS, Command Injection |
| A04:2021 | Insecure Design | Business Logic Flaw, Missing Rate Limit |
| A05:2021 | Security Misconfiguration | Default Credentials, Verbose Error, Open CORS |
| A06:2021 | Vulnerable and Outdated Components | Outdated Library, Known CVE Dependency |
| A07:2021 | Identification and Authentication Failures | Weak Session Token, Auth Bypass |
| A08:2021 | Software and Data Integrity Failures | PHP Object Injection, Unverified Update |
| A09:2021 | Security Logging and Monitoring Failures | Missing Audit Log |
| A10:2021 | Server-Side Request Forgery (SSRF) | SSRF, Blind SSRF |

### OWASP Mapping Examples
- Reflected/Stored XSS    → **A03:2021 – Injection** / Cross-Site Scripting (XSS)
- SQLi                    → **A03:2021 – Injection** / SQL Injection
- Missing cap check       → **A01:2021 – Broken Access Control** / Missing Authorization
- Auth bypass             → **A07:2021 – Identification and Authentication Failures** / Authentication Bypass
- PHP Object Injection    → **A08:2021 – Software and Data Integrity Failures** / PHP Object Injection
- SSRF                    → **A10:2021 – Server-Side Request Forgery** / SSRF
- Weak nonce / token      → **A02:2021 – Cryptographic Failures** / Insecure Token Generation