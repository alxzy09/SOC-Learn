# 🕵️‍♂️ Studi Kasus Forensik & Eksploitasi: TryHackMe "Extracted"

## 📋 Pendahuluan: Apa yang Terjadi?
Dalam skenario ini, kita bertindak sebagai analis keamanan. Kita mendapatkan sebuah file tangkapan lalu lintas jaringan (**PCAP**). Dari sana, kita menemukan bahwa sebuah komputer telah terinfeksi skrip berbahaya (**PowerShell**) yang mencuri data sensitif dari aplikasi manajemen password (**KeePass**).

**Tujuan Kita:**
1.  Menganalisis lalu lintas jaringan.
2.  Memahami cara kerja skrip pencuri data.
3.  Mengambil kembali data yang dicuri (Memory Dump & Database).
4.  Memanfaatkan kerentanan pada KeePass untuk mendapatkan password.
5.  Membuka database dan menemukan flag.

---

## 🟢 Fase 1: Analisis Lalu Lintas Jaringan (PCAP)

### 📚 Teori: Apa itu PCAP?
**PCAP (Packet Capture)** adalah file yang berisi rekaman lalu lintas data yang lewat di jaringan pada waktu tertentu. Bayangkan seperti rekaman CCTV, tapi untuk data digital. Alat yang biasa digunakan untuk membukanya adalah **Wireshark**.

### 🔍 Langkah Analisis
1.  **Ekstrak File:** Kita diberikan file ZIP yang berisi `traffic.pcapng`.
    ```bash
    unzip file-1693277727739.zip
    ```
2.  **Buka di Wireshark:**
    ```bash
    wireshark traffic.pcapng
    ```
3.  **Cari Percakapan (Conversations):**
    Di Wireshark, pergi ke menu `Statistics` -> `Conversations`. Kita melihat ada 3 koneksi TCP utama ke IP `10.10.94.106` pada port berbeda:
    *   Port **1339**: Digunakan untuk mengunduh skrip.
    *   Port **1337**: Digunakan untuk mengirim data memori (dump).
    *   Port **1338**: Digunakan untuk mengirim database KeePass.

    > **Kenapa Port aneh?** Port standar HTTP biasanya 80/443. Hacker sering menggunakan port tinggi (seperti 1337) untuk menghindari deteksi firewall dasar atau karena mereka mengontrol server tersebut.

4.  **Ambil Skrip PowerShell:**
    *   Filter percakapan port **1339**.
    *   Kita melihat permintaan `HTTP GET` untuk file `xxxmmdcclxxxiv.ps1`.
    *   Ekstrak file tersebut via Wireshark: `File` -> `Export Objects` -> `HTTP`.

---

## 🟡 Fase 2: Bedah Skrip PowerShell (Malware Analysis)

### 📚 Teori: PowerShell & Obfuscation
**PowerShell** adalah alat otomatisasi kuat di Windows. Karena sangat powerful, hacker sering menggunakannya untuk menyerang (*Living off the Land*).
**Obfuscation** adalah teknik mengacak kode agar sulit dibaca oleh manusia atau antivirus. Tugas kita adalah "membersihkan" kode ini.

### 🔍 Langkah Analisis
Saat dibuka, skrip terlihat sangat berantakan dengan nama variabel acak (contoh: `$YVVbq4INVpT2ADzETTRQ...`). Setelah dibersihkan (deobfuscation), logika utamanya adalah:

1.  **Cek & Download Procdump:**
    Skrip mengecek apakah alat bernama `Procdump.exe` ada. Jika tidak, ia mengunduhnya dari internet.
    *   *Fungsi Procdump:* Alat resmi Microsoft untuk mengambil "foto" isi memori (RAM) dari sebuah program yang sedang berjalan.

2.  **Cari Proses KeePass:**
    ```powershell
    $KeePassProcess = Get-Process -Name 'KeePass'
    ```
    Skrip mencari apakah aplikasi KeePass sedang terbuka di korban.

3.  **Dumping Memori:**
    Jika KeePass ditemukan, skrip menjalankan Procdump untuk menyimpan isi RAM KeePass ke file `1337.dmp`.
    ```powershell
    # Perintah inti yang dijalankan
    Procdump.exe -ma <PID_KeePass> 1337.dmp
    ```

4.  **Enkripsi & Pengiriman Data (C2):**
    Sebelum dikirim ke server hacker, data diacak dulu agar tidak mudah dikenali oleh sistem keamanan jaringan.
    *   **File Memori (`1337.dmp`):** Di-XOR dengan kunci `0x41` (huruf 'A'), lalu di-Base64, lalu dikirim ke port **1337**.
    *   **File Database (`Database1337.kdbx`):** Di-XOR dengan kunci `0x42` (huruf 'B'), lalu di-Base64, lalu dikirim ke port **1338**.

    > **Catatan Penting:** Di dalam PCAP, kita bisa menangkap data yang sedang "dikirim" ini. Karena kita punya PCAP-nya, kita bisa mengambil data yang sudah dienkripsi tersebut dan mendekripsinya kembali.

---

## 🟠 Fase 3: Ekstraksi & Dekoding Data

### 📚 Teori: XOR & Base64
1.  **Base64:** Cara mengubah data biner (gambar, file exe) menjadi teks ASCII agar bisa dikirim via protokol teks (seperti email atau HTTP). Ini **bukan enkripsi**, siapa saja bisa mengubahnya kembali (*decode*).
2.  **XOR (Exclusive OR):** Operasi matematika bitwise sederhana.
    *   Rumus: `Data Asli XOR Kunci = Data Enkripsi`
    *   Sifat Unik: `Data Enkripsi XOR Kunci = Data Asli`
    *   Karena sifat ini, jika kita tahu kuncinya (dalam kasus ini `0x41` dan `0x42` dari analisis skrip), kita bisa balikkan datanya.

### 🔍 Langkah Eksekusi
Kita gunakan `tshark` (versi command line dari Wireshark) untuk mengambil data mentah dari PCAP.

1.  **Ambil Data Memori (Port 1337):**
    ```bash
    tshark -r traffic.pcapng -Y "tcp.dstport == 1337" -T fields -e data | xxd -r -p > 539.dmp
    ```
    *   `-Y "tcp.dstport == 1337"`: Filter hanya paket yang menuju port 1337.
    *   `-e data`: Ambil isi datanya.
    *   `xxd -r -p`: Ubah dari format hex (tampilan tshark) kembali menjadi biner.

2.  **Ambil Data Database (Port 1338):**
    ```bash
    tshark -r traffic.pcapng -Y "tcp.dstport == 1338" -T fields -e data | xxd -r -p > Database1337
    ```

3.  **Dekoding (Reverse Engineering):**
    Kita balikkan proses yang ada di skrip PowerShell (Base64 Decode -> XOR Decrypt).

    *   **Untuk Memory Dump:**
        ```bash
        # 1. Decode Base64, 2. XOR dengan 'A' (0x41)
        base64 -d 539.dmp | xortool-xor -f - -s 'A' -n > 1337.dmp
        ```
    *   **Untuk Database:**
        ```bash
        # 1. Decode Base64, 2. XOR dengan 'B' (0x42)
        base64 -d Database1337 | xortool-xor -f - -s 'B' -n > Database1337.kdbx
        ```

    *Sekarang kita punya file `1337.dmp` (isi RAM) dan `Database1337.kdbx` (file password) yang asli!*

---

## 🔴 Fase 4: Eksploitasi Kerentanan KeePass (CVE-2023-32784)

### 📚 Teori: Mengapa Memori Penting?
Saat kamu mengetik password di komputer, password itu tidak langsung hilang setelah kamu tekan Enter. Password tersebut tersimpan sementara di **RAM (Random Access Memory)** agar CPU bisa memprosesnya.

**CVE-2023-32784** adalah kerentanan pada KeePass versi lama.
*   **Masalah:** Saat kamu mengetik password, karakter yang kamu ketik (meskipun ditampilkan sebagai bintang `*`) sebenarnya meninggalkan jejak di memori dalam bentuk pola tertentu.
*   **Contoh:** Jika passwordnya "halo", di memori mungkin tersisa sisa-sisa string seperti `•a`, `••l`, `•••o`, dll.
*   **Dampak:** attacker yang punya file dump memori bisa merekonstruksi password tersebut.

### 🔍 Langkah Eksekusi
Kita gunakan alat khusus yang dibuat komunitas untuk mengeksploitasi bug ini: `keepass-dump-extractor`.

1.  **Ekstrak Password dari Memori:**
    ```bash
    ./keepass-dump-extractor 1337.dmp -f gaps
    ```
    *   Output yang didapat: `●No[REDACTED]23`
    *   **Analisis:** Kita tahu passwordnya berakhiran `23`, dimulai dengan `No`, tapi ada beberapa karakter tengah yang hilang (terdapat gap). Karakter pertama juga mungkin tidak terbaca sempurna.

2.  **Generate Wordlist (Daftar Kandidat Password):**
    Karena ada karakter yang hilang, kita harus menebak sisanya. Alat tersebut bisa membuat semua kemungkinan kombinasi berdasarkan pola yang ditemukan di memori.
    ```bash
    ./keepass-dump-extractor 1337.dmp -f all > all_possible_passwords.txt
    ```
    File `all_possible_passwords.txt` sekarang berisi ribuan kemungkinan password yang valid secara struktur memori.

---

## 🟣 Fase 5: Brute-force Password Database

### 📚 Teori: Hash & Cracking
File `.kdbx` KeePass dilindungi dengan enkripsi. Kita tidak bisa membukanya tanpa password.
*   **keepass2john:** Alat untuk mengambil "hash" dari file database. Hash adalah sidik jari digital dari password.
*   **John the Ripper (John):** Alat untuk menebak password. Ia akan mengambil kata dari wordlist, membuatnya menjadi hash, dan mencocokkan dengan hash database. Jika cocok, password ditemukan.

### 🔍 Langkah Eksekusi
1.  **Ambil Hash Database:**
    ```bash
    keepass2john Database1337.kdbx > keepass_hash
    ```
2.  **Crack Password:**
    ```bash
    john keepass_hash --wordlist=all_possible_passwords.txt
    ```
    *   John akan bekerja mengecek satu per satu password dari wordlist kita.
    *   **Hasil:** `...[REDACTED]No[REDACTED]23 (Database1337)`
    *   Kita sekarang memiliki master password yang benar!

---

## ⚫ Fase 6: Akses Database & Menemukan Flag

### 🔍 Langkah Eksekusi
Sekarang kita bisa membuka database tersebut. Kita bisa menggunakan aplikasi KeePass asli atau tools CLI seperti `kpcli`.

```bash
kpcli --kdb Database1337.kdbx
```
1.  Masukkan password yang ditemukan tadi.
2.  Navigasi ke entry yang mencurigakan. Biasanya hacker menyembunyikan flag di catatan (Notes).
3.  Perintah di `kpcli`:
    ```bash
    cd Database1337/
    ls
    show -f 2  # Menampilkan entry ke-2 (You win!)
    ```
4.  Di bagian **Notes**, terdapat flag: `THM{...}`.

---

## 🎓 Kesimpulan & Pelajaran untuk Pemula

Dari studi kasus ini, ada beberapa pelajaran keamanan siber yang sangat penting:

1.  **Jangan Asal Klik/Download:** Skrip berbahaya bisa masuk hanya dengan mengunjungi website atau mengunduh file看似 biasa. Selalu inspect traffic jika curiga.
2.  **Enkripsi Itu Penting, Tapi...:** Meskipun data dienkripsi (XOR/Base64) saat dikirim, jika kita punya kunci atau bisa menganalisis kodenya, enkripsi sederhana bisa dibalik.
3.  **Bahaya Memory Dump:** Data sensitif di RAM itu nyata. Inilah sebabnya mengapa akses administratif (yang bisa melakukan dump memori) sangat dilindungi.
4.  **Update Software:** Kerentanan CVE-2023-32784 bisa dihindari jika pengguna KeePass selalu mengupdate aplikasi mereka ke versi terbaru yang sudah ditambal (*patched*).
5.  **Forensik Digital:** Jejak digital selalu ada. Dari PCAP, dari memori, hingga dari log. Seorang pentester harus jeli melihat pola.

