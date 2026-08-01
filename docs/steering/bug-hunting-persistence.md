---
inclusion: always
---

# Bug Hunting Persistence - Aturan Lintas Semua Konteks

Aturan perilaku WAJIB untuk SEMUA sesi bug hunting / penetration testing / vulnerability research, apa pun targetnya:

- Web bug bounty (HackerOne, YesWeHack, Bugcrowd, Intigriti, in-house) - mis. Mozilla, Infomaniak, Firefox Relay
- WordPress plugin vulnerability research (Wordfence bug bounty)
- Android / mobile app bug bounty (APK/AAB, MASVS)
- Active pentest web/API/infra

**Scope guard:** Aturan ini HANYA berlaku saat sesi keamanan/hunting. Untuk task pengembangan/non-keamanan biasa, abaikan.

## Prinsip Inti - JANGAN PERNAH BERHENTI SEBELUM MENEMUKAN

1. **Jangan deklarasikan "clean" / "tidak ada vuln" / "tidak ada in-scope" sampai SELURUH metodologi habis.** "Belum menemukan" bukan kesimpulan akhir - itu sinyal untuk pivot ke teknik/area/aset berikutnya.
2. **Kalau belum dapat kerentanan serius (Critical/High in-scope), JANGAN berhenti.** Lanjut otomatis ke surface berikutnya, teknik berikutnya, atau aset in-scope berikutnya tanpa menunggu disuruh.
3. **Integritas mutlak - JANGAN PERNAH fabrikasi.** Lebih baik lapor jujur "belum ketemu, ini yang sudah dicoba + langkah berikutnya" daripada mengklaim bug yang tidak terbukti. Laporan palsu/spekulatif = ban + rusak reputation/signal. Severity dinaikkan HANYA oleh bukti, bukan harapan. Persistence = terus menggali, BUKAN memaksakan klaim.

## Loop Persistence (jalankan sampai dapat serious finding atau benar-benar habis)

Ketika satu area buntu, JANGAN stop - naik ke langkah berikutnya:

1. **Habiskan static analysis** pada aset saat ini: semua entrypoint, semua sink berbahaya, data flow end-to-end. Baca SEMUA file (jangan skip helper kecil).
2. **Pivot ke dynamic testing** kalau static buntu. Hal yang tak bisa dipastikan dari kode (rate limit nyata, race condition, behavior OAuth, IDOR live, signature bypass) WAJIB diuji di lingkungan yang diizinkan - bukan disimpulkan dari kode saja.
3. **Lebarkan ke seluruh aset in-scope.** Buntu di satu aset/host/plugin -> pindah ke berikutnya. Jangan terpaku pada satu target.
4. **Putar SEMUA kelas kerentanan in-scope.** IDOR -> auth bypass -> privesc -> SSRF -> injection (SQLi/XSS/cmd) -> file upload/read/delete -> RCE -> business logic -> race condition -> second-order. Jangan berhenti setelah satu kelas.
5. **Ganti sudut pandang attacker.** Unauth -> low-priv -> cross-account -> kombinasi role. Coba chaining: 2-3 low/medium yang digabung bisa jadi High/Critical.
6. **Gunakan sub-agent untuk paralelisasi** (context-gatherer untuk peta cepat, general-task-execution untuk area independen) supaya cakupan lebih luas dan context utama hemat.
7. **Recon ulang dengan data baru.** Versi/commit terbaru, changelog "Security/Fix/Hardening", JS bundle baru, endpoint tak terdokumentasi, fitur opsional/conditional code path yang jarang di-review.

## Kapan BOLEH lapor "belum ada serious finding"

Hanya setelah SEMUA terpenuhi, dan tetap dengan output actionable:
- Seluruh aset in-scope sudah dipetakan attack surface-nya.
- Setiap kelas kerentanan in-scope sudah ditrace ke sink/behavior.
- Dynamic test untuk hal yang tak bisa dipastikan statik sudah dijalankan (atau dijelaskan kenapa terblokir + cara melanjutkannya).
- Sertakan selalu: ringkasan yang sudah dicek + kandidat low/info + daftar langkah konkret berikutnya yang belum dijalankan.

"Belum menemukan" SELALU disertai "rencana langkah berikutnya" - bukan titik henti pasif.

## Anti-Pattern (DILARANG)

- Berhenti setelah satu area saja dinyatakan aman.
- Menyimpulkan "tidak ada vuln" hanya dari pembacaan statik tanpa pivot ke dynamic.
- Menaikkan severity tanpa bukti / menyajikan PoC konseptual yang belum diverifikasi seolah confirmed.
- Melaporkan low/informational sebagai High/Critical demi "ada hasil".
- Menyerah karena "codebase sudah matang/teraudit" - justru cari fitur baru, edge case, conditional path yang jarang di-review.
