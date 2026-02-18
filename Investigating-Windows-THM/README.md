# Investigating Windows – Blue Team/SOC Analyst Workflow
**Level:** Intermediate | **Platform:** TryHackMe | **Role:** SOC Analyst L1/L2

---

##  Learning Objectives
Setelah menyelesaikan modul ini, bro akan mampu:
1.  Memahami alur kerja (*workflow*) investigasi insiden di lingkungan Windows secara realistis, ala SOC Analyst.
2.  Menganalisis Windows Event Logs untuk mengidentifikasi aktivitas mencurigakan (logon, privilege escalation, process execution).
3.  Mengidentifikasi teknik persistensi attacker (Scheduled Tasks, Registry Run Keys, Startup Apps).
4.  Melakukan rekonstruksi timeline serangan berdasarkan artefak sistem.
5.  Mendokumentasikan temuan dalam format laporan insiden yang rapi dan profesional.

>  **Mindset SOC Analyst:** *"Trust nothing, verify everything. Every click, every log, every timestamp is a clue."*

---

##  Pre-Investigation Checklist (Real-World Prep)
Sebelum mulai "ngutak-ngatik" mesin, analyst profesional nggak langsung buru-buru. Kita siapkan dulu "senjata" dan mentalnya:

```markdown
✅ 1. Pahami Scope & Rules of Engagement
   - Target: Mesin Windows via RDP (IP: [THM Machine IP])
   - Kredensial: Administrator / letmein123!
   - Goal: Investigasi kompromi, identifikasi IOC, jawab pertanyaan room.

✅ 2. Siapkan Tools & Environment
   - RDP Client (mstsc.exe) dengan clipboard enabled buat copy-paste.
   - Notepad/Text Editor lokal buat catat temuan penting (jangan andalkan memory!).
   - Screenshot tool (Snipping Tool) buat dokumentasi bukti.

✅ 3. Atur Mindset Investigasi
   - Jangan asal klik. Setiap action harus ada tujuan: "Apa yang gue cari? Kenapa di sini?"
   - Catat timestamp setiap temuan. Timeline adalah kunci.
   - Asumsikan sistem sudah fully compromised. Fokus: "Apa yang attacker lakukan setelah masuk?"
```

---

##  PHASE 1: Initial Assessment & System Profiling
*Tujuan: Kenali "pasien" sebelum diagnosa. Kita butuh baseline sistem yang normal.*

### Theory: Why This Matters?
Di dunia nyata, analyst nggak bisa langsung loncat ke "cari malware". Kita harus paham dulu:
- OS version & patch level → buat identifikasi vulnerability yang mungkin dieksploit.
- Hostname & domain context → buat pahami scope jaringan.
- User accounts & groups → buat identifikasi potensi privilege escalation path.

###  Tools
- `systeminfo`, `Get-ComputerInfo` (PowerShell)
- `winver` (GUI)
- `net user`, `net localgroup` (CLI)

###  Step-by-Step (Verbose, Realistic Style)

#### Step 1.1: Connect & Initial Observation
```
1. Buka RDP Client (mstsc.exe).
2. Masukkan IP mesin THM, username: Administrator, password: letmein123!
3. Setelah login, JANGAN langsung buka Event Viewer. Ambil napas dulu.
4. Perhatikan desktop: Ada file aneh? Shortcut mencurigakan? Icon yang nggak biasa?
5. Catat: "Desktop bersih, tidak ada file mencurigakan yang visible. Lanjut ke system info."
```

#### Step 1.2: Gather System Fingerprint
```powershell
# Buka PowerShell sebagai Administrator (klik kanan > Run as Administrator)
# Kita pakai PowerShell karena lebih powerful untuk parsing output daripada CMD.

# Cek OS Version, Build Number, Install Date
systeminfo | Select-String -Pattern "OS Name", "OS Version", "System Type", "Install Date"

# Output example:
# OS Name:                   Microsoft Windows 10 Pro
# OS Version:                10.0.17763 N/A Build 17763
# System Type:               x64-based PC
# Install Date:              2/28/2019, 10:15:32 AM

# Catat di Notepad lokal:
# "[TIMESTAMP] OS: Win10 Pro 17763, Installed: 2019-02-28. Build ini rentan terhadap [CVE-XXXX-XXXX] jika tidak dipatch."
```

#### Step 1.3: Inventory User Accounts & Groups
```powershell
# Cek semua local users
net user

# Cek detail user Administrator (kita login sebagai ini, tapi siapa tau ada user lain yang dibuat attacker)
net user Administrator

# Cek siapa saja yang ada di grup Administrators (privilege escalation indicator!)
net localgroup Administrators

# Output example:
# Members:
# Administrator
# Guest
# MaliciousUser  <-- 🚩 RED FLAG! Catat ini!

# Analyst Note: 
# "Ditemukan user 'MaliciousUser' di grup Administrators. 
# Ini bukan default Windows. Potensi akun backdoor yang dibuat attacker. 
# Prioritas investigasi: cek kapan user ini dibuat (Event ID 4720)."
```

>  **Real-World Context:** Di SOC, langkah ini disebut "Asset Profiling". Kita nggak bisa protect what we don't know.

---

##  PHASE 2: Authentication & User Activity Analysis
*Tujuan: Lacak jejak login, siapa, kapan, dan dari mana. Ini jantung investigasi insiden.*

###  Theory: Windows Authentication Logs
Windows mencatat hampir semua aktivitas autentikasi di **Security Log**. Event ID kunci:
- `4624`: Successful logon (perhatikan Logon Type: 2=interactive, 3=network, 10=RDP)
- `4625`: Failed logon (brute force indicator)
- `4672`: Special privileges assigned to new logon (admin rights)
- `4720`: User account created (backdoor account indicator)

### Tools
- Event Viewer (`eventvwr.msc`)
- PowerShell: `Get-WinEvent`, `Get-EventLog`

###  Step-by-Step

#### Step 2.1: Buka Security Log & Filter Awal
```
1. Tekan Win+R, ketik eventvwr.msc, Enter.
2. Navigasi: Windows Logs > Security.
3. Klik kanan "Security" > Filter Current Log...
4. Di field "<All Event IDs>", masukkan: 4624,4625,4672,4720
5. Klik OK. Sekarang kita hanya lihat event autentikasi kritis.
```

#### Step 2.2: Analisis Successful Logon (Event 4624)
```
1. Scroll ke event paling atas (terbaru). Perhatikan TimeCreated.
2. Klik event 4624 terbaru, lihat detail di pane bawah:
   - Account Name: Administrator (ini kita)
   - Logon Type: 10 (RemoteInteractive = RDP) ← sesuai akses kita
   - Source Network Address: [IP kita] ← normal
3. Sekarang, scroll ke bawah cari logon BEFORE kita login.
   - Cari Account Name yang bukan SYSTEM, LOCAL SERVICE, atau DWM-0.
   - Perhatikan Logon Type 10 juga (attacker mungkin pakai RDP).
4. Temuan: 
   "Ditemukan successful logon (Event 4624) untuk user 'MaliciousUser' 
   pada 2019-03-02 14:23:17, Logon Type 10, Source IP: 10.0.0.50. 
   Ini sebelum login kita (2019-03-02 16:00:00). 
   → Attacker mungkin akses via RDP menggunakan akun backdoor."
```

#### Step 2.3: Cek Privilege Escalation (Event 4672)
```
1. Masih di filtered Security Log, cari Event ID 4672.
2. Event ini muncul ketika user dapat special privileges (SeDebugPrivilege, dll).
3. Perhatikan:
   - Subject UserName: Siapa yang dapat privilege?
   - Process Name: Proses apa yang request privilege? (misal: mimikatz.exe, powershell.exe)
4. Temuan:
   "Event 4672 pada 2019-03-02 14:25:03 untuk user 'MaliciousUser', 
   Process: C:\TMP\mimikatz.exe. 
   → Attacker menjalankan Mimikatz untuk dump credentials setelah login."
```

>  **Analyst Note:** Selalu cross-reference timestamp. Event 4624 (login) → 4672 (privilege) → 4688 (process creation) adalah chain of attack yang umum.

---

##  PHASE 3: Persistence Mechanism Investigation
*Tujuan: Temukan cara attacker bertahan di sistem. Ini yang bikin insiden jadi "berulang".*

###  Theory: Common Windows Persistence Techniques
Attacker suka "numpang tinggal" di sistem. Cara umum:
1. **Registry Run Keys**: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
2. **Scheduled Tasks**: Task Scheduler buat jalanin script/malware secara periodic.
3. **Startup Folder**: File yang auto-run saat user login.
4. **Services**: Malware disguised sebagai Windows service.
5. **WMI Event Subscriptions**: Advanced technique, sulit dideteksi.

###  Tools
- Registry Editor (`regedit`)
- Task Scheduler (`taskschd.msc`)
- PowerShell: `Get-ItemProperty`, `Get-ScheduledTask`, `Get-WmiObject`

###  Step-by-Step (Detail, Bertele-tele ala Analyst Beneran)

#### Step 3.1: Cek Registry Run Keys (Manual + CLI)
```
1. Tekan Win+R, ketik regedit, Enter.
2. Navigasi pelan-pelan (jangan asal klik):
   HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
3. Lihat pane kanan: Ada value yang nggak biasa?
   - Nama: "WindowsUpdate" tapi path-nya C:\TMP\evil.exe ← 🚩
   - Data: "C:\TMP\backdoor.exe /silent" ← 🚩
4. Catat setiap suspicious entry:
   "[TIMESTAMP] Registry Run Key: 'WindowsUpdate' → C:\TMP\backdoor.exe"

5. Verifikasi dengan PowerShell (lebih cepat buat parsing):
   Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | 
   Select-Object -Property * | 
   Format-List

6. Cek juga RunOnce dan user-specific Run keys:
   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   HKLM\...\RunOnce
```

#### Step 3.2: Investigate Scheduled Tasks (GUI + CLI)
```
1. Tekan Win+R, ketik taskschd.msc, Enter.
2. Di Task Scheduler Library, klik setiap task satu per satu.
   - Jangan skip! Attacker suka bikin nama task yang "normal" seperti "GoogleUpdate", "OneDrive Sync".
3. Untuk setiap task, cek tab:
   - General: Siapa yang buat? (Author: SYSTEM or MaliciousUser?)
   - Triggers: Kapan task jalan? (At logon? Daily? One time?)
   - Actions: Apa yang dijalanin? (Program/script: powershell.exe, Arguments: -enc [base64])
4. Temuan contoh:
   "Task Name: 'SystemMaintenance'
    Author: MaliciousUser
    Trigger: At logon of any user
    Action: powershell.exe -WindowStyle Hidden -File C:\TMP\persist.ps1
    → Ini persistence mechanism. Script persist.ps1 mungkin download payload atau buka reverse shell."

5. Verifikasi dengan PowerShell:
   Get-ScheduledTask | 
   Where-Object {$_.Principal.UserId -like "*MaliciousUser*" -or $_.TaskName -like "*Maintenance*"} | 
   Get-ScheduledTaskInfo | 
   Select-Object TaskName, LastRunTime, NextRunTime

6. Export task definition buat analisis lebih lanjut:
   Export-ScheduledTask -TaskName "SystemMaintenance" | Out-File C:\TMP\task_export.xml
```

#### Step 3.3: Cek Folder Startup & Temp Files
```
1. Buka File Explorer, navigasi ke:
   C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
   C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
2. Cari file .lnk, .exe, .ps1 yang mencurigakan.
3. Cek juga folder temp yang sering dipakai attacker:
   C:\TMP (folder custom, bukan default Windows)
   C:\Windows\Temp
   C:\Users\Public\Documents
4. Sortir by "Date created". File yang dibuat sekitar timestamp kompromi (2019-03-02 14:00-15:00) adalah prioritas.
5. Temuan:
   "File C:\TMP\mimikatz.exe, created: 2019-03-02 14:20:11. 
    Hash (jika bisa): [catat jika ada tool hash]. 
    → Tool credential dumping, konfirmasi dari Event 4672 sebelumnya."
```

>  **Real-World Tip:** Di SOC, kita bakal upload file mencurigakan ke sandbox (Any.Run, Hybrid-Analysis) atau cek hash-nya di VirusTotal. Di lab THM, cukup identifikasi saja.

---

##  PHASE 4: Network & C2 Artifact Analysis
*Tujuan: Temukan komunikasi ke Command & Control server, DNS poisoning, atau lateral movement.*

###  Theory: Network Indicators of Compromise
- **Hosts File Modification**: Attacker edit `C:\Windows\System32\drivers\etc\hosts` buat redirect domain legit ke IP mereka.
- **Firewall Rules**: Buka port baru buat reverse shell atau C2 channel.
- **Netstat/Network Connections**: Lihat koneksi aktif ke IP eksternal yang mencurigakan.

###  Tools
- Notepad (buat buka file hosts)
- `netstat -ano`, `Get-NetTCPConnection` (PowerShell)
- Windows Firewall with Advanced Security (`wf.msc`)

###  Step-by-Step

#### Step 4.1: Cek File Hosts untuk DNS Poisoning
```
1. Buka Notepad sebagai Administrator (penting! kalau nggak, nggak bisa save).
2. File > Open, navigasi ke: C:\Windows\System32\drivers\etc\hosts
3. Pastikan "All Files" selected di file type dropdown (kalau nggak, file hosts nggak keliatan).
4. Baca setiap baris. Cari entry yang:
   - Redirect domain populer (google.com, microsoft.com) ke IP internal/aneh.
   - Contoh: "10.0.0.100    www.google.com" ← 🚩
5. Temuan:
   "File hosts dimodifikasi. Entry: '192.168.1.200    update.microsoft.com'
    → Attacker redirect Windows Update traffic ke server mereka buat deliver malicious payload."
```

#### Step 4.2: Analisis Firewall Rules (Inbound/Outbound)
```
1. Tekan Win+R, ketik wf.msc, Enter.
2. Klik "Inbound Rules", sort by "Date Modified" (klik header kolom).
3. Cari rule yang:
   - Enabled: Yes
   - Action: Allow
   - Date Modified: Sekitar timestamp kompromi
   - Name: Mencurigakan (misal: "RemoteDebug", "TempAccess")
4. Klik rule tersebut, cek tab "Protocols and Ports":
   - Local Port: 4444, 8080, 1337 ← common reverse shell ports
   - Remote IP: Any atau IP spesifik attacker
5. Temuan:
   "Inbound Rule 'DebugAccess' dibuat 2019-03-02 14:30:00.
    Allows TCP port 4444 from Any. 
    → Kemungkinan reverse shell listener yang dibuka attacker."

6. Cek juga Outbound Rules kalau ada pertanyaan soal C2 communication.
```

#### Step 4.3: Network Connection Snapshot (Optional tapi Recommended)
```powershell
# Di PowerShell, ambil snapshot koneksi aktif:
Get-NetTCPConnection | 
Where-Object {$_.RemoteAddress -notlike "127.*" -and $__.State -eq "Established"} | 
Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Cross-reference OwningProcess dengan:
Get-Process -Id [PID] | Select-Object Name, Path, Company

# Kalau ada process aneh yang koneksi ke IP eksternal, catat sebagai IOC.
```

---

##  PHASE 5: Timeline Reconstruction & IOC Extraction
*Tujuan: Satukan semua puzzle. Kapan serangan mulai, apa urutannya, apa indikator yang bisa kita pakai buat deteksi di masa depan.*

###  Theory: Why Timeline Matters?
Di SOC, laporan insiden yang bagus nggak cuma bilang "ada malware", tapi:
- **When**: Exact timestamp first compromise
- **How**: Initial access vector (RDP brute? Phishing? Exploit?)
- **What**: Actions taken by attacker (recon, persistence, exfiltration)
- **Scope**: Which systems/users affected
- **IOC**: Indicators of Compromise buat deteksi proaktif

###  Step-by-Step: Build the Timeline

#### Step 5.1: Kumpulkan Semua Timestamp Kunci
```
Buka Notepad, buat timeline dalam format:
[TIMESTAMP] [EVENT TYPE] [DESCRIPTION] [EVIDENCE LOCATION]

Contoh:
[2019-03-02 14:15:00] [USER CREATION] User 'MaliciousUser' dibuat via net user command. 
   Evidence: Security Log Event ID 4720.

[2019-03-02 14:20:11] [FILE DROP] mimikatz.exe dropped to C:\TMP\. 
   Evidence: File creation timestamp, Event ID 4688 (process creation).

[2019-03-02 14:23:17] [SUCCESSFUL LOGON] MaliciousUser login via RDP. 
   Evidence: Security Log Event ID 4624, Logon Type 10.

[2019-03-02 14:25:03] [PRIVILEGE ESCALATION] Mimikatz executed with SeDebugPrivilege. 
   Evidence: Security Log Event ID 4672.

[2019-03-02 14:30:00] [PERSISTENCE] Scheduled Task 'SystemMaintenance' created. 
   Evidence: Task Scheduler, Event ID 4698.

[2019-03-02 14:35:22] [C2 COMMUNICATION] Outbound connection to 192.168.1.200:443. 
   Evidence: Firewall log, netstat output.
```

#### Step 5.2: Extract IOC (Indicators of Compromise)
```
Buat list IOC dalam format yang bisa dipakai buat detection rule (misal: SIEM, EDR):

# FILE HASHES (jika ada):
- C:\TMP\mimikatz.exe → SHA256: [hash jika bisa dihitung]

# FILE PATHS:
- C:\TMP\backdoor.exe
- C:\TMP\persist.ps1

# REGISTRY KEYS:
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate

# SCHEDULED TASKS:
- Task Name: SystemMaintenance

# USER ACCOUNTS:
- MaliciousUser (SID: S-1-5-21-...)

# NETWORK:
- IP: 192.168.1.200 (C2 server)
- Port: 4444/TCP (reverse shell)
- Hosts file entry: update.microsoft.com → 192.168.1.200

# EVENT IDS:
- 4720, 4624 (Logon Type 10), 4672, 4698, 4688
```

---

##  PHASE 6: Reporting & Documentation (Real-World Deliverable)
*Tujuan: Komunikasi temuan ke stakeholder. Di lab THM, ini berarti jawab pertanyaan room dengan bukti.*

###  Template Laporan Singkat (Adaptasi buat THM)
```markdown
# Incident Report: Windows Host Compromise Investigation
**Date**: [Tanggal investigasi]
**Analyst**: [Nama lo]
**Target**: [THM Machine IP/Name]

## Executive Summary
Host Windows 10 Pro (Build 17763) terkompromi pada 2019-03-02 ~14:15 UTC. 
Attacker membuat akun backdoor 'MaliciousUser', akses via RDP, 
menjalankan Mimikatz untuk credential dumping, dan menginstal 
persistence mechanism via Scheduled Task dan Registry Run Key.

## Timeline of Events
[Copy timeline dari Phase 5.1]

## Indicators of Compromise (IOC)
[Copy IOC list dari Phase 5.2]

## Recommended Actions
1. Reset password semua user, terutama Administrator.
2. Hapus akun 'MaliciousUser' dan review semua akun lokal.
3. Hapus Scheduled Task 'SystemMaintenance' dan Registry Run Key mencurigakan.
4. Restore file hosts ke default.
5. Blokir IP C2 (192.168.1.200) di firewall perimeter.
6. Enable advanced audit policy untuk process creation (Event 4688) di masa depan.

## Evidence Attachments
- Screenshot Event Viewer: Event 4624, 4672, 4720
- Screenshot Task Scheduler: 'SystemMaintenance' properties
- Export Registry key: Run\WindowsUpdate
```

---

##  APPENDIX: Quick Reference Cheat Sheet

###  Critical Event IDs for Windows Investigation
| Event ID | Description | Why It Matters |
|----------|-------------|---------------|
| 4624 | Successful logon | Lacak akses attacker |
| 4625 | Failed logon | Deteksi brute force |
| 4672 | Special privileges assigned | Indikator privilege escalation |
| 4688 | Process creation (butuh audit policy) | Lacak eksekusi malware |
| 4698 | Scheduled task created | Deteksi persistence |
| 4720 | User account created | Backdoor account indicator |
| 5140 | Network share accessed | Lateral movement clue |

###  PowerShell One-Liners for Forensics
```powershell
# Get last 20 logon events
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20 | 
Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[8].Value}}

# Find suspicious startup items
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run*, 
                 HKCU:\Software\Microsoft\Windows\CurrentVersion\Run* | 
Select-Object PSPath, @{N='Value';E={$_.PSChildName}}, @{N='Data';E={$_."$($_.PSChildName)"}} | 
Where-Object {$_.Data -like "*TMP*" -or $_.Data -like "*powershell*"}

# List scheduled tasks with PowerShell actions
Get-ScheduledTask | 
Where-Object {$_.Actions.Execute -like "*powershell*" -or $_.Actions.Execute -like "*cmd*"} | 
Select-Object TaskName, State, @{N='Action';E={$_.Actions.Execute}}
```

### Registry Paths for Persistence Checks
```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\System\CurrentControlSet\Services\ [cek service aneh]
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell [bisa dimodify buat persistence]
```