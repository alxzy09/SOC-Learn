# 🛡️ Tutorial Reverse Engineering: TryHackMe "Compiled"

## 📋 Fase 1: Reconnaissance (Pengumpulan Informasi)

Sebelum menyerang atau membedah, kita harus tahu apa yang sedang kita hadapi.

### 1. Cek Tipe File
Setelah mendownload file challenge, langkah pertama adalah mengetahui jenis file tersebut. Di Linux, kita menggunakan perintah `file`.

```bash
file compiled
```

**Output yang diharapkan:**
```text
compiled: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, ...
```

**🧠 Teori Dasar:**
*   **ELF (Executable and Linkable Format):** Ini adalah standar format file untuk executable, object code, dan shared libraries di sistem operasi Linux/Unix (seperti `.exe` di Windows).
*   **64-bit LSB executable:** Artinya program ini dirancang untuk berjalan di arsitektur processor 64-bit.
*   **Mengapa ini penting?** Kita tahu ini adalah program Linux native, bukan script Python atau Bash. Kita butuh lingkungan Linux untuk menjalankannya.

### 2. Atur Izin Akses (Permissions)
Secara default, file yang didownload biasanya tidak memiliki izin untuk dieksekusi demi keamanan.

```bash
chmod 777 compiled
```
*Atau lebih aman:* `chmod +x compiled`

**🧠 Teori Dasar:**
*   **chmod 777:** Memberikan izin *Read, Write, Execute* kepada *Owner, Group, dan Others*.
*   **Risiko:** Dalam produksi, `777` berbahaya karena siapa saja bisa memodifikasi file. Untuk CTF/testing lokal, ini aman agar kita bisa menjalankan program tanpa hambatan izin.

### 3. Jalankan Program
Coba jalankan binary tersebut untuk melihat perilakunya.

```bash
./compiled
```

**Output:**
```text
Enter the password: 
```
(Kita masukkan sembarang text, misal: `test`)
```text
Try again!
```

**🧠 Teori Dasar:**
*   **Interactive Input:** Program ini menunggu input dari *Standard Input (stdin)*.
*   **Logic Check:** Ada logika di dalam program yang membandingkan input kita dengan password yang benar. Jika tidak cocok, keluar pesan "Try again!".

---

## 📋 Fase 2: Initial Analysis (Analisis Awal)

Sebelum membongkar kode, kita cari petunjuk yang mungkin tertinggal secara kasar.

### 1. Cek Strings
Developer sering meninggalkan string teks (kata-kata) di dalam binary yang tidak dienkripsi. Kita bisa melihatnya dengan perintah `strings`.

```bash
strings compiled
```

**Output (Penting):**
Kita akan melihat banyak teks acak, tapi cari yang mirip bahasa manusia. Di artikel ditemukan petunjuk adanya kata "Password" dan format tertentu.

**🧠 Teori Dasar:**
*   **Static Analysis Ringan:** `strings` mengambil semua urutan karakter yang bisa dibaca (printable characters) dari binary.
*   **Keterbatasan:** Jika developer pintar, mereka akan mengenkripsi string atau tidak menyimpan password dalam bentuk teks polos (plaintext). Namun untuk level pemula/CTF awal, ini sering berhasil.

---

## 📋 Fase 3: Deep Dive dengan Ghidra (Reverse Engineering)

Karena `strings` hanya memberi hint, kita butuh alat untuk melihat logika programnya. Kita menggunakan **Ghidra** (tool reverse engineering dari NSA).

### 1. Decompile
Setelah membuka file di Ghidra, kita masuk ke menu **Decompiler**. Ini akan mengubah *Machine Code* (assembly) kembali menjadi kode yang mirip C (pseudocode).

### 2. Bedah Logika Kode (Inti Materi)
Berdasarkan artikel, berikut adalah potongan logika penting yang ditemukan di Ghidra:

```c
undefined8 main(void)
{
  int iVar1;
  char local_28 [32]; // 1. Alokasi Memori

  fwrite("Password: ",1,10,stdout); // 2. Output Prompt
  
  // 3. Input Parsing dengan Format String
  __isoc99_scanf("DoYouEven%sCTF",local_28); 
  
  // 4. Cek Keamanan / Decoy (Jebakan)
  iVar1 = strcmp(local_28,"__dso_handle");
  if ((-1 < iVar1) && (iVar1 = strcmp(local_28,"__dso_handle"), iVar1 < 1)) {
    printf("Try again!");
    return 0;
  }
  
  // 5. Cek Password Utama
  iVar1 = strcmp(local_28,"_init");
  if (iVar1 == 0) {
    printf("Correct!");
  }
  else {
    printf("Try again!");
  }
  return 0;
}
```

### 🧠 Teori Mendalam per Bagian:

#### 1. `char local_28 [32];` (Stack Variable)
*   **Teori:** Ini adalah deklarasi variabel lokal yang disimpan di **Stack Memory**.
*   **Detail:** `local_28` adalah nama variabel, `[32]` artinya ia adalah *array* karakter yang bisa menampung maksimal 32 byte (termasuk null terminator `\0`).
*   **Relevansi Pentesting:** Jika kita memasukkan input lebih dari 32 karakter, kita bisa memicu **Buffer Overflow**. Namun di challenge ini, kita fokus pada logika validasi password dulu.

#### 2. `__isoc99_scanf("DoYouEven%sCTF",local_28);` (Format String Vulnerability/Logic)
*   **Teori:** `scanf` membaca input dari user. String `"DoYouEven%sCTF"` adalah **Format String**.
*   **Cara Kerja:**
    1.  `scanf` mencari literal teks `DoYouEven` di awal input.
    2.  `%s` adalah *placeholder* yang artinya "tangkap semua karakter berikutnya".
    3.  `CTF` adalah literal teks penutup. `scanf` akan berhenti menangkap `%s` begitu ia menemukan teks `CTF`.
    4.  Hasil tangkapan `%s` disimpan ke variabel `local_28`.
*   **Contoh Kasus:**
    *   Input: `DoYouEvenHackCTF`
    *   Yang masuk ke `local_28`: `Hack`
    *   Input: `DoYouEven_initCTF`
    *   Yang masuk ke `local_28`: `_init`

#### 3. `strcmp(local_28, "_init")` (String Comparison)
*   **Teori:** Fungsi `strcmp` (String Compare) membandingkan dua string secara *byte-by-byte*.
*   **Return Value (Penting!):**
    *   `0`: Jika kedua string **SAMA PERSIS**.
    *   `< 0`: Jika string pertama lebih kecil (secara ASCII).
    *   `> 0`: Jika string pertama lebih besar.
*   **Logika Kode:** `if (iVar1 == 0)`. Artinya, program hanya akan mencetak "Correct!" jika isi `local_28` **SAMA PERSIS** dengan `_init`.

#### 4. Bagian `__dso_handle` (Decoy/Red Herring)
*   **Teori:** Ada blok `if` sebelum cek utama yang memeriksa apakah input sama dengan `__dso_handle`.
*   **Fungsi:** Ini adalah mekanisme pertahanan sederhana. Jika kamu menebak string tertentu ini, program akan langsung menolak ("Try again!") sebelum mencapai cek password utama. Ini biasa disebut *anti-debugging* atau *logic bomb* sederhana.

---

## 📋 Fase 4: Menyusun Payload (PoC)

Di sini kita gabungkan teori di atas untuk menyusun input yang benar.

### Analisis Kebutuhan:
1.  **Target Isi Variabel:** Berdasarkan `strcmp(local_28,"_init")`, variabel `local_28` **WAJIB** berisi `_init`.
2.  **Format Input:** Berdasarkan `scanf("DoYouEven%sCTF", ...)`, input user **WAJIB** dibungkus oleh `DoYouEven` di depan dan `CTF` di belakang agar `%s` bisa menangkap `_init` dengan benar.

### Rumus Input:
```text
[Prefix Wajib] + [Isi Target]
DoYouEven      + _init
```

### Password Input:
```text
DoYouEven_init
```


---

## 📋 Fase 5: Verifikasi (Eksekusi PoC)

Mari kita buktikan teori kita dengan menjalankan program dan memasukkan password yang sudah kita rekayasa.

```bash
./compiled
```

**Input:**
```text
Enter the password: DoYouEven_init
```

**Output:**
```text
Correct!
```

🎉 **Berhasil!** Kita berhasil melewati proteksi password tanpa mengetahui source code aslinya, hanya dengan menganalisis binary.

---

## Rangkuman Konsep untuk Pemula

Sebagai calon *pentester* dan *bug hunter*, berikut adalah hal kunci yang harus kamu ambil dari challenge ini:

1.  **Jangan Asal Tebak:** Menggunakan *brute force* (mencoba semua kombinasi) bisa memakan waktu lama. Analisis binary (`file`, `strings`, `ghidra`) jauh lebih efisien.
2.  **Pahami Format String:** Banyak program menggunakan pola input tertentu. Memahami `%s`, `%d`, dll., sangat penting dalam reverse engineering dan eksploitasi (seperti *Format String Vulnerability*).
3.  **Kembali 0 itu Bagus:** Dalam pemrograman C, fungsi perbandingan seperti `strcmp` mengembalikan `0` jika sukses/sama. Ini sering membingungkan pemula karena biasanya `0` berarti error, tapi di sini `0` berarti "Match".
4.  **Tools adalah Teman:**
    *   `file`: Identifikasi target.
    *   `strings`: Cari clue cepat.
    *   `Ghidra`: Bedah logika mendalam (Decompiler).
    *   `chmod`: Siapkan lingkungan eksekusi.