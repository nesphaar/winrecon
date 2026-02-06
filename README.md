# 🪟 winrecon — Windows Recon & Security Inventory

**winrecon** is a Windows reconnaissance, inventory, and security assessment tool written in **native PowerShell**, designed for **security audits**, **incident response**, and **post-compromise enumeration** on modern Windows systems.

It is the Windows counterpart to **linrecon**, applying the same philosophy:

- 📎 Evidence-based collection  
- 🧠 Lightweight heuristics  
- 📊 Clear, audit-friendly reporting  

---

## ✨ Key Features

- 🔍 Comprehensive Windows system reconnaissance  
- 🛡️ Automated security findings with severity levels  
- 📄 TXT & HTML reports with indexed evidence  
- ⚙️ Native PowerShell (no external dependencies)  
- 📦 Automatic ZIP packaging  
- 🔐 Administrator privilege validation  

---

## 🧠 What winrecon Collects

### 🖥️ System & Hardware
- Windows version, architecture, and boot time  
- BIOS and system manufacturer information  
- Physical memory  
- Domain membership  

### 💾 Storage
- Volumes and partitions  
- File system types  
- Free space  

### 🌐 Networking
- IP configuration and addresses  
- Listening TCP ports  
- Hosts file inspection  

### 👥 Users & Access
- Local users and groups  
- Logged-on sessions  
- Account status and metadata  

### ⚙️ Services & Tasks
- Running Windows services  
- Enabled scheduled tasks  

### 🔐 Security Posture
- Windows Firewall profiles  
- Antivirus / Microsoft Defender status (via WMI)  
- Recently installed hotfixes  
- RDP exposure  
- SMBv1 protocol status  

### 🧰 Living off the Land (LotL)

Detection of common dual-use binaries, including:

- `powershell.exe`  
- `certutil.exe`  
- `bitsadmin.exe`  
- `curl.exe`  
- `nc.exe`, `nmap.exe`, `python.exe`, etc.  

---

## 🚨 Automated Findings Engine

winrecon includes built-in security heuristics that generate findings with severity labels:

- 🔴 **HIGH**  
- 🟠 **MEDIUM**  
- 🔵 **INFO**  
- 🟢 **OK**  

### Current automated findings include:
- RDP (3389) listening exposure  
- SMBv1 enabled (legacy & vulnerable)  
- Missing or unregistered Antivirus  
- Firewall profile status  

Each finding:
- Is **evidence-backed**  
- Links directly to the relevant section in the HTML report  
- Avoids assumptions when data is unavailable  

## 📄 Output Structure
winrecon__/
├── report.txt # Full textual report
├── report.html # Interactive HTML report
├── errors.txt # Non-fatal execution errors
└── data/
├── 00_os_info.txt
├── 44_listening_ports.txt
├── 81_av_status.txt
├── 140_lotl_inventory.txt
└── ...

📦 Automatically packaged as: **winrecon__.zip**

## 🚀 Usage

### 1️⃣ Open PowerShell as Administrator
Administrator privileges are **mandatory** for a full assessment.

### 2️⃣ Run the script
```powershell
.\winrecon.ps1
```

**The script will:**

Validate administrator privileges

Collect system data

Generate TXT and HTML reports

Create a ZIP archive automatically

## 🛡️ Design Principles

✅ Read-only & non-destructive

❌ No exploitation

❌ No network scanning

❌ No configuration changes

📎 Evidence-first reporting

## 📖 Audit & Incident Response friendly output

🧪 Intended Use Cases

🔐 Security assessments

🚑 Incident response

🟦 Blue team investigations

🕵️ Post-exploitation enumeration

📋 Hardening & compliance reviews

## 📌 Versioning

Current version: 1.0.0
See the script header for the full changelog.

## ⚠️ Disclaimer

This tool is intended only for authorized security testing and system auditing.

Run it only on systems you own or where you have explicit permission to perform an assessment.
