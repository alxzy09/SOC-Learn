# SOC-Learn

SOC-Learn adalah repository pembelajaran yang berfokus pada pengembangan kemampuan **Security Operations Center (SOC)**. Repository ini berisi kumpulan materi, catatan praktik, dan pembahasan studi kasus yang disusun secara bertahap untuk membantu memahami workflow SOC secara sistematis.

Materi akan terus diperbarui dan ditambahkan secara berkala.

---

## Tujuan Repository

* Memahami konsep dasar hingga lanjutan terkait SOC
* Melatih kemampuan analisis log dan incident handling
* Meningkatkan skill threat detection dan threat investigation
* Mendokumentasikan hasil pembelajaran dari berbagai platform keamanan

---

## Struktur Repository

Setiap directory berisi satu topik atau satu studi kasus pembelajaran SOC.

```text
SOC-Learn/
│
├── Juicy-Details-THM/
│   └── README.md
│
├── Investigating-Windows-THM/
│   └── README.md
│
├── Memory-Forensics-THM/
│   └── README.md
│
└── README.md
```

---

## Table of Contents

1. [Juicy Details – TryHackMe](./Juicy-Details-THM)
2. [Investigating Windows – TryHackMe](./Investigating-Windows-THM)
3. [Memory Forensics - TryHackMe](./Memory-Forensics-THM/)
4. [Compiled – TryHackMe](./Compiled-THM/)

---

## Juicy Details – TryHackMe

Materi pertama dalam repository ini diambil dari room **Juicy Details** di platform TryHackMe.

Directory: `Juicy-Details-THM/`

Materi ini membahas:

* Analisis log keamanan
* Investigasi aktivitas mencurigakan
* Identifikasi indikator kompromi (IoC)
* Proses investigasi dalam konteks SOC

Silakan masuk ke directory tersebut untuk membaca dokumentasi lengkap dan catatan pembelajaran.

---

## Investigating Windows – TryHackMe

Materi kedua dalam repository ini diambil dari room **Investigating Windows** di platform TryHackMe.

Directory: `Investigating-Windows-THM/`

Status: **Completed** (18/02/2026)

Materi ini membahas:

* Windows Event Log Analysis (Security, System, Application)
* Investigasi aktivitas autentikasi dan user (Event ID: 4624, 4625, 4672, 4720)
* Deteksi mekanisme persistence (Registry, Scheduled Tasks, Startup Apps)
* Analisis artefak jaringan (Hosts File, Firewall Rules)
* Rekonstruksi timeline serangan dan ekstraksi IOC
* Dokumentasi dan pelaporan insiden

Silakan masuk ke directory tersebut untuk membaca dokumentasi lengkap dan catatan pembelajaran.

---

## Memory Forensics – TryHackMe

Materi ketiga dalam repository ini diambil dari room **Memory Forensics** di platform TryHackMe.

**Directory:** `Memory-Forensics-THM/`

Materi ini membahas:

*   Dasar-dasar **Memory Forensics** dan konsep Volatile Memory (RAM)
*   Penggunaan framework **Volatility** untuk analisis memory dump
*   **Image Identification**: Menentukan profil OS yang tepat untuk interpretasi memori
*   **Credential Dumping**: Ekstraksi password hash (LM/NTLM) dari memori
*   **Timeline Analysis**: Rekonstruksi aktivitas sistem (Shutdown time, CMD History)
*   **Key Recovery**: Analisis enkripsi dan pemulihan passphrase (TrueCrypt)
*   Rekonstruksi kejadian insiden melalui sisa data di memori (Process Memory)

Silakan masuk ke directory tersebut untuk membaca dokumentasi lengkap dan catatan pembelajaran.

---


## Compiled – TryHackMe

Materi keempat dalam repository ini diambil dari room **Compiled** di platform TryHackMe.

**Directory:** `Compiled-THM/`

**Status:** **Completed** (24/05/2024)

Materi ini membahas:

*   **Dasar Reverse Engineering:** Analisis binary tanpa source code asli.
*   **Identifikasi File:** Menggunakan perintah `file` untuk mengenali format ELF (Linux Executable).
*   **Static Analysis:** Ekstraksi string tersembunyi menggunakan `strings` untuk mencari petunjuk awal.
*   **Decompilation:** Menggunakan **Ghidra** untuk mengubah machine code menjadi pseudocode C yang mudah dibaca.
*   **Analisis Fungsi C:** Memahami logika `scanf` (Format String), `strcmp` (String Comparison), dan variabel stack (`local_28`).
*   **Logic Exploitation:** Merekonstruksi input password berdasarkan pola format string (`DoYouEven%sCTF`).
*   **Understanding Return Values:** Memahami bahwa `strcmp` mengembalikan `0` ketika string cocok.

**Ringkasan Challenge:**
Tantangan ini meminta peserta untuk menemukan password yang benar dari sebuah binary compiled. Melalui analisis dekompilasi, ditemukan bahwa program meminta input dengan pola tertentu dan membandingkan bagian tengah input dengan string rahasia `_init`.

**Proof of Concept (PoC):**
*   **Input Binary:** `DoYouEven_initCTF`
*   **Secret Flag:** `DoYouEven_init`

Silakan masuk ke directory tersebut untuk membaca dokumentasi lengkap, catatan analisis Ghidra, dan langkah-langkah penyelesaian.

---

## Catatan

Repository ini dibuat sebagai dokumentasi pembelajaran dan referensi untuk pengembangan skill SOC secara terstruktur.

Struktur akan terus berkembang seiring penambahan materi baru.

Last Updated: 23/02/2026
