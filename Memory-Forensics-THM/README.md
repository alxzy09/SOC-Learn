
### **Memory Forensics**

Sebelum masuk ke teknis, pahami dulu konsepnya di dunia SOC.

1.  **Apa itu Memory Forensics?**
    *   Ini adalah proses menganalisis isi **RAM (Random Access Memory)** sebuah komputer.
    *   **Teori:** RAM adalah *volatile memory*. Artinya, semua data di dalamnya (password, program yang jalan, proses yang tersembunyi, koneksi jaringan) akan hilang seketika begitu komputer dimatikan atau listrik dicabut.
    *   **Konteks SOC:** Kalau SOC mendeteksi insiden (misal: malware aktif), kita tidak bisa langsung matikan komputer karena bukti di RAM akan hilang. Kita perlu mengambil *image* (foto) RAM dulu, lalu menganalisanya.

2.  **Tool: Volatility**
    *   Ini adalah "Swiss Army Knife" untuk analisis memori. Dia membaca file mentah memori (`.vmem`, `.raw`, `.mem`) dan menerjemahkannya menjadi informasi yang bisa dibaca manusia.

---

### **Langkah 0: Menentukan Profil (The Theory of Profiles)**

Di setiap tugas, langkah pertama selalu menggunakan `imageinfo`.

```bash
volatility imageinfo -f Snapshot6.vmem
```

**Teori & Konsep SOC:**
*   **Kenapa harus pakai profil?**
    *   Sistem operasi (Windows 7, 10, XP, dll) memiliki struktur kernel yang berbeda-beda. Cara Volatility membaca alamat memori (memory addressing) di Windows 7 SP1 64-bit akan berbeda dengan Windows 10.
    *   Kalau profil salah, hasil analisis akan rusak (garbage data).
    *   **Dunia SOC:** Identifikasi OS yang akurat adalah langkah awal *Triage*. Kita harus tahu apa yang sedang kita hadapi sebelum mengambil tindakan lebih lanjut.

---

### **Task 1: Login (Mencari Password User)**

**Misi:** Mencari password user "John".

#### **1. Teori: Credential Storage di Windows**
Di Windows, password tidak disimpan dalam bentuk teks biasa (plaintext) demi keamanan. Mereka disimpan sebagai **Hash**.
*   **SAM (Security Account Manager):** Database lokal yang menyimpan hash password user.
*   **LSASS (Local Security Authority Subsystem Service):** Proses yang menangani keamanan. Seringkali password/hash ini disimpan di memori saat pengguna login, atau saat sistem perlu melakukan otentikasi.

#### **2. Command: `hashdump`**
```bash
volatility -f Snapshot6.vmem --profile Win7SP1x64 hashdump
```

**Apa yang terjadi?**
Volatility memindai memori untuk menemukan struktur data SAM dan LSASS, lalu mengekstrak hash LM dan NTLM.

*   **Output yang penting:**
    `John:1001:aad3b435b51404eeaad3b435b51404ee:47fbd6536d7868c873d5ea455f2fc0c9:::`
    *   Bagian setelah titik terakhir kedua adalah hash NTLM: `47fbd6536d7868c873d5ea455f2fc0c9`.

#### **3. Cracking Hash**
Penulis menggunakan *online hash cracker* (CrackStation).
*   **Teori:** Hash adalah satu arah. Tapi, kita bisa melakukan *brute-force* atau mencocokkan hash tersebut dengan database hash yang sudah diketahui (Rainbow Tables).
*   **Hasil:** Password terbaca.

**Konteks SOC:**
Kalau kamu seorang SOC Analyst dan menemukan hash ini, apa artinya?
1.  **Lateral Movement:** Attacker sering mencuri hash ini (bukan passwordnya) untuk login ke komputer lain di jaringan menggunakan teknik *Pass-the-Hash*. Kita menganalisis ini untuk melihat seberapa jauh attacker menyebar.
2.  **User Awareness:** Password user "John" mungkin lemah, sehingga mudah ditebak. Ini jadi rekomendasi untuk kebijakan password di perusahaan.

---

### **Task 2: Analysis (Timeline & Activity Reconstruction)**

**Misi:**
1.  Kapan komputer terakhir dimatikan?
2.  Apa yang John ketik di CMD?

#### **Q1: Shutdown Time**
Command: `shutdowntime`

**Teori: Windows Registry**
*   Windows menyimpan log penting di **Registry**. Registry adalah database hierarki untuk konfigurasi sistem.
*   Key `ShutdownTime` disimpan dalam hive `SYSTEM`.
*   Saat komputer dimatikan dengan benar (graceful shutdown), Windows mencatat waktu ke dalam memori/registry sebelum daya benar-benar mati.

**Konteks SOC:**
Timeline adalah kunci dalam investigasi forensik.
*   "Apakah malware aktif sebelum atau sesudah komputer dimatikan?"
*   "Apakah ada aktivitas aneh di jam 2 pagi?"
*   Membuat timeline (ketika *boot*, ketika *shutdown*, ketika file dibuat) membantu kita merekonstruksi kejadian (*Chain of Custody* digital).

#### **Q2: Command History**
Command: `cmdscan` (atau `consoles`)

**Teori: Process Memory & Structures**
*   Ketika kamu mengetik di Command Prompt (`cmd.exe`), riwayat perintah tersebut disimpan dalam struktur memori khusus yang disebut `_COMMAND_HISTORY`.
*   Struktur ini disimpan dalam memori proses `conhost.exe` (Console Host Process).
*   Volatility memindai seluruh memori untuk mencari pola byte yang cocok dengan struktur `_COMMAND_HISTORY`.

**Output:**
`echo THM{You_found_me} > test.txt`

**Konteks SOC:**
Ini adalah teknik **Rekonstruksi Kejadian**.
*   Attacker biasanya menggunakan CMD atau PowerShell untuk melakukan eksekusi perintah.
*   Dengan `cmdscan`, kita bisa melihat perintah apa saja yang dijalankan, meskipun attacker sudah menghapus history cmd-nya (`doskey /history` tidak membersihkan memori!).
*   Kita bisa tahu apakah attacker mencoba membuat user baru, mendownload file, atau menjalankan script malware.

---

### **Task 3: TrueCrypt (Encryption & Key Recovery)**

**Misi:** Mencari passphrase enkripsi TrueCrypt.

#### **Teori: Encryption in Memory**
*   **Prinsip Dasar:** Agar komputer bisa membaca file di partisi terenkripsi (misal TrueCrypt, BitLocker), kunci enkripsi (passphrase atau master key) **harus** ada di RAM dalam bentuk plaintext atau bisa direkonstruksi.
*   Komputer tidak bisa membaca data terenkripsi kalau kuncinya tidak di-"dekode" dulu dan disimpan sementara di memori.

#### **Command: `truecryptpassphrase`**
```bash
volatility -f Snapshot14.vmem --profile Win7SP1x64 truecryptpassphrase
```
Volatility mencari pola string tertentu di memori yang berkaitan dengan aplikasi TrueCrypt.

**Hasil:** `forgetmenot`

**Konteks SOC:**
Ini sangat umum dalam kasus **Ransomware** atau penyembunyian data (Data Hiding).
1.  **Ransomware:** Beberapa ransomware mengenkripsi drive victim. Kadang kunci dekripsi ada di RAM sebelum proses enkripsi selesai atau saat ransomware aktif. Jika SOC cepat mengambil *memory dump*, kita bisa memulihkan kuncinya tanpa membayar tebusan.
2.  **Anti-Forensics:** Attacker atau employee jahat menyimpan data sensitif di partisi terenkripsi. Analisis memori adalah satu-satunya cara untuk membukanya tanpa passphrase jika mereka sedang membuka partisinya saat kita melakukan *seizure*.