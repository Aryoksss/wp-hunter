---
inclusion: always
---


# Exhaustive Code Analysis — Aturan Global

Aturan WAJIB setiap kali user minta "analisis", "baca semua code", "pahami semua file", "audit", "review menyeluruh", atau sejenisnya. Tujuannya: Kiro membaca SELURUH file/baris yang relevan, benar-benar memahaminya, dan TIDAK berhenti sebelum cakupan tuntas.

## Prinsip Inti

1. **Jangan menyimpulkan sebelum cakupan habis.** "Belum selesai" bukan titik henti — itu sinyal lanjut ke file/bagian berikutnya secara otomatis tanpa menunggu disuruh.
2. **Jangan skip file.** Termasuk file kecil, helper, util, config, test. Bug dan detail penting sering ada di file yang dianggap remeh.
3. **Integritas mutlak.** Jangan mengaku "sudah baca semua" kalau belum. Lebih baik jujur: "X dari N file terbaca, sisanya: [...]". Jangan mengarang isi file yang belum dibaca.
4. **Realistis soal context window.** Repo besar tidak bisa dipegang sekaligus. Capai "terbaca semua" lewat ITERASI TERLACAK + compaction + sub-agent, bukan sekali tarik.

## Workflow Wajib

### 1. Enumerasi dulu, baca kemudian
- Petakan SEMUA file dulu (`list_directory` rekursif + `file_search`/`grep_search`) sebelum mulai baca isi.
- Buat daftar file target eksplisit. Ini jadi checklist coverage.

### 2. Baca isi penuh
- Baca file sampai habis (bukan cuma signature), kecuali file jelas-jelas tidak relevan (mis. lockfile, binary, asset, minified vendor). Untuk file yang dilewati, catat alasannya.
- File besar: baca bertahap (range) sampai SELURUH isi tercakup, jangan berhenti di potongan pertama.
- Prefer `read_files` (batch) untuk efisiensi; pakai `read_code` untuk file kode besar saat butuh struktur.

### 3. Lacak coverage secara eksplisit
- Pertahankan daftar status: `[done]` / `[partial]` / `[todo]` / `[skipped: alasan]` per file.
- Setiap beberapa langkah, tampilkan ringkas progres: "Terbaca: A/B file. Sisa: [...]".
- DILARANG deklarasi "selesai / clean / tidak ada temuan" selama masih ada file `[todo]` atau `[partial]`.

### 4. Pahami, bukan cuma baca
- Untuk tiap area: jelaskan alur data end-to-end (input → proses → output/sink), bukan sekadar parafrase baris.
- Catat hubungan antar file (siapa memanggil siapa, dependency, kontrak interface).

### 5. Jangan berhenti prematur
- Saat satu area selesai dan masih ada sisa → otomatis lanjut ke berikutnya.
- Saat context mau penuh → ringkas temuan + state coverage ke output, biarkan compaction jalan, lalu LANJUT dari file `[todo]` berikutnya. Konfirmasi ulang posisi dari daftar coverage, bukan dari ingatan.
- Berhenti HANYA jika: (a) semua file target sudah `[done]`/`[skipped beralasan]`, atau (b) user menyetop, atau (c) ada blocker nyata (file tak terbaca/permission) — dan blocker WAJIB dilaporkan + cara lanjutnya.

### 6. Paralelisasi dengan sub-agent (mode Autopilot)
- Untuk repo besar / area independen, delegasikan ke sub-agent (`context-gatherer` untuk peta cepat, `general-task-execution` untuk telusuri area) supaya cakupan luas dan context utama hemat.
- Jika sub-agent tidak punya akses tool baca file, lakukan analisis langsung sendiri — jangan jadikan itu alasan berhenti.

## Output Saat Belum Tuntas

"Belum selesai" SELALU disertai:
- Ringkasan yang sudah dipahami sejauh ini.
- Daftar coverage (done/partial/todo/skipped).
- Langkah konkret berikutnya yang akan dijalankan.

## Anti-Pattern (DILARANG)

- Menyimpulkan dari sebagian file lalu berhenti.
- Membaca hanya signature/awal file lalu mengklaim paham seluruhnya.
- Skip file kecil/helper/test tanpa alasan.
- Mengaku "semua sudah dibaca" tanpa daftar coverage yang membuktikannya.
- Berhenti karena "kelihatannya sudah cukup" padahal daftar todo belum habis.

## Catatan

Aturan ini fokus pada KELENGKAPAN & PEMAHAMAN. Untuk tugas kecil/spesifik (mis. "ganti 1 fungsi"), tetap proporsional — aturan ini berlaku penuh saat user secara eksplisit minta analisis/baca menyeluruh.
