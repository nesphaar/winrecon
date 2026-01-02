🪟 winrecon — Windows Recon & Security Inventory

winrecon is a Windows reconnaissance, inventory, and security assessment tool written in native PowerShell, designed for security audits, incident response, and post-compromise enumeration on modern Windows systems.

It is the Windows counterpart to linrecon, applying the same philosophy:
📎 evidence-based collection,
🧠 lightweight heuristics,
📊 clear reporting.

✨ Key Features

🔍 Comprehensive Windows system reconnaissance

🛡️ Automated security findings with severity levels

📄 TXT & HTML reports with indexed evidence

⚙️ Native PowerShell (no external dependencies)

📦 Automatic ZIP packaging

🔐 Administrator privilege validation

🧠 What winrecon Collects
🖥️ System & Hardware

Windows version, architecture, boot time

BIOS and system manufacturer info

Physical memory and domain membership

💾 Storage

Volumes and partitions

File system types and free space

🌐 Networking

IP configuration and addresses

Listening TCP ports

Hosts file inspection

👥 Users & Access

Local users and groups

Logged-on sessions

Account status and metadata

⚙️ Services & Tasks

Running Windows services

Enabled scheduled tasks

🔐 Security Posture

Windows Firewall profiles

Antivirus / Defender status (via WMI)

Recently installed hotfixes

RDP exposure

SMBv1 protocol status

🧰 Living off the Land (LotL)

Detection of common dual-use binaries:

powershell.exe

certutil.exe

bitsadmin.exe

curl.exe

nc.exe, nmap.exe, python.exe, etc.

🚨 Automated Findings Engine

winrecon includes built-in security heuristics that generate findings with severity labels:

🔴 HIGH

🟠 MEDIUM

🔵 INFO

🟢 OK

Current automated findings include:

RDP (3389) listening exposure

SMBv1 enabled (legacy & vulnerable)

Missing or unregistered Antivirus

Firewall profile status

Each finding:

Is evidence-backed

Links directly to the relevant section in the HTML report

Avoids assumptions when data is unavailable

📄 Output Structure
winrecon_<host>_<timestamp>/
├── report.txt        # Full textual report
├── report.html       # Interactive HTML report
├── errors.txt        # Non-fatal execution errors
└── data/
    ├── 00_os_info.txt
    ├── 44_listening_ports.txt
    ├── 81_av_status.txt
    ├── 140_lotl_inventory.txt
    └── ...


📦 Automatically packaged as:

winrecon_<host>_<timestamp>.zip

🚀 Usage
1️⃣ Open PowerShell as Administrator

This is mandatory for a full assessment.

2️⃣ Run the script
.\winrecon.ps1


The script will:

Validate admin privileges

Collect system data

Generate reports

Create a ZIP archive automatically

🛡️ Design Principles

✅ Read-only & non-destructive

❌ No exploitation

❌ No network scanning

❌ No configuration changes

📎 Evidence-first reporting

📖 Audit & IR friendly output

🧪 Intended Use Cases

🔐 Security assessments

🚑 Incident response

🟦 Blue team investigations

🕵️ Post-exploitation enumeration

📋 Hardening & compliance reviews

📌 Versioning

Current version: 1.0.0

See script header for full changelog.

⚠️ Disclaimer

This tool is intended for authorized security testing and system auditing only.
Run it only on systems you own or have explicit permission to assess.
