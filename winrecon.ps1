<#
# ============================================================
# winrecon - Windows Recon & Security Inventory
#
# Version: 1.0.0
# Author: Gemini (Adapted from Nesphaar's linrecon)
#
# Changelog:
# 1.0.0
# - First stable release for Windows environments (8+ / 2012+)
# - Native PowerShell implementation of linrecon logic
# - Admin privileges check and auto-warning
# - Generates report.txt + report.html + data/*.txt evidence
# - Automated findings for RDP, SMBv1, and Antivirus status
# - Automatic packaging via Compress-Archive (ZIP)
# ============================================================
#>

$VERSION = "1.0.0"
$PROG = "winrecon"

# ------------------------------------------------------------
# Admin elevation check
# ------------------------------------------------------------
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERROR] Superuser privileges are required for a full assessment." -ForegroundColor Red
    Write-Host "[INFO] Please run PowerShell as Administrator." -ForegroundColor Yellow
    return
}

# ------------------------------------------------------------
# Path and environment setup
# ------------------------------------------------------------
$TS = Get-Date -Format "yyyyMMdd_HHmmss"
$HOST_NAME = $env:COMPUTERNAME
$OUTDIR = Join-Path $PSScriptRoot "${PROG}_${HOST_NAME}_${TS}"
$DATADIR = Join-Path $OUTDIR "data"
$HTML = Join-Path $OUTDIR "report.html"
$TXT = Join-Path $OUTDIR "report.txt"
$ERRORS = Join-Path $OUTDIR "errors.txt"

$START_TIME = Get-Date
$START_EPOCH = [DateTimeOffset]::Now.ToUnixTimeSeconds()

# Create directory structure
New-Item -ItemType Directory -Force -Path $DATADIR | Out-Null

# ------------------------------------------------------------
# Progress and Helpers
# ------------------------------------------------------------
$TOTAL_STEPS = 12
$CURRENT_STEP = 0

function Write-Progress-Simple {
    param($msg)
    $script:CURRENT_STEP++
    $percent = [math]::Floor(($script:CURRENT_STEP / $TOTAL_STEPS) * 100)
    Write-Progress -Activity "$PROG v$VERSION Assessment" -Status "$msg" -PercentComplete $percent
}

# Run command and capture output to file
function Run-Cmd {
    param($name, $scriptBlock)
    $f = Join-Path $DATADIR "${name}.txt"
    try {
        $output = & $scriptBlock 2>&1
        "### $name`r`n" + ($output | Out-String) | Out-File $f -Encoding utf8
    } catch {
        # FIX: Use ${name} to prevent PowerShell from thinking ':' is a drive provider
        "[$($TS)] ERROR in ${name}: $($_.Exception.Message)" | Out-File $ERRORS -Append
    }
}

# ------------------------------------------------------------
# Initialize Text Report and Error log
# ------------------------------------------------------------
"==== $PROG report ($TS) ====" | Out-File $TXT
"Version: $VERSION`nHost: $HOST_NAME`nUser: $env:USERNAME" | Out-File $TXT -Append
"==== $PROG errors ($TS) ====" | Out-File $ERRORS

# ------------------------------------------------------------
# 0x - Base System Info
# ------------------------------------------------------------
Write-Progress-Simple "Collecting OS information"
Run-Cmd "00_os_info" { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture, LastBootUpTime, InstallDate }
Run-Cmd "01_computer_system" { Get-CimInstance Win32_ComputerSystem | Select-Object Model, Manufacturer, TotalPhysicalMemory, Domain, PartOfDomain }
Run-Cmd "02_bios" { Get-CimInstance Win32_BIOS | Select-Object SerialNumber, SMBIOSBIOSVersion, ReleaseDate }

# ------------------------------------------------------------
# 1x - Storage and Hardware
# ------------------------------------------------------------
Write-Progress-Simple "Collecting storage info"
Run-Cmd "10_disks" { Get-Volume | Select-Object DriveLetter, FriendlyName, FileSystemType, Size, SizeRemaining }
Run-Cmd "11_partitions" { Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Size, Type }

# ------------------------------------------------------------
# 4x - Networking and Ports
# ------------------------------------------------------------
Write-Progress-Simple "Collecting network config"
Run-Cmd "40_ip_config" { Get-NetIPConfiguration -All }
Run-Cmd "41_ip_addresses" { Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias, AddressFamily }
Run-Cmd "44_listening_ports" { Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess }
Run-Cmd "46_hosts_file" { Get-Content C:\Windows\System32\drivers\etc\hosts }

# ------------------------------------------------------------
# 6x - Users and Groups
# ------------------------------------------------------------
Write-Progress-Simple "Collecting user accounts"
Run-Cmd "60_local_users" { Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description }
Run-Cmd "61_local_groups" { Get-LocalGroup | Select-Object Name, Description }
Run-Cmd "64_logged_on_users" { qwinsta }

# ------------------------------------------------------------
# 7x - Services and Tasks
# ------------------------------------------------------------
Write-Progress-Simple "Collecting services and tasks"
Run-Cmd "70_running_services" { Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName }
Run-Cmd "74_scheduled_tasks" { Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State }

# ------------------------------------------------------------
# 8x - Security (Firewall, AV, Patches)
# ------------------------------------------------------------
Write-Progress-Simple "Collecting security status"
Run-Cmd "80_firewall_profiles" { Get-NetFirewallProfile | Select-Object Name, Enabled }
Run-Cmd "81_av_status" { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct }
Run-Cmd "82_recent_hotfixes" { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 }

# ------------------------------------------------------------
# 10x - Software Inventory
# ------------------------------------------------------------
Write-Progress-Simple "Collecting software inventory"
Run-Cmd "100_installed_apps" { 
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher
}

# ------------------------------------------------------------
# 14x - Living off the Land (LotL)
# ------------------------------------------------------------
Write-Progress-Simple "Identifying LotL tools"
$lotl_tools = @("nc.exe", "nmap.exe", "python.exe", "gcc.exe", "ssh.exe", "powershell.exe", "certutil.exe", "bitsadmin.exe", "curl.exe")
Run-Cmd "140_lotl_inventory" {
    foreach($t in $lotl_tools) {
        $where = Get-Command $t -ErrorAction SilentlyContinue
        if($where) { "[FOUND] $t at $($where.Source)" }
    }
}

# ------------------------------------------------------------
# Automated Findings (Heuristics)
# ------------------------------------------------------------
$FINDINGS_HTML = ""
function Add-Finding($sev, $title, $detail, $evidence) {
    $script:FINDINGS_HTML += "<tr><td><b class='sev-$sev'>$sev</b></td><td>$title</td><td>$detail</td><td>$evidence</td></tr>"
}

# Finding: RDP exposure
$rdpPort = Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue
if ($rdpPort) {
    Add-Finding "MEDIUM" "RDP Listening" "Remote Desktop (3389) is active. Ensure it is protected by MFA or Firewall." "<a href='#44_listening_ports'>evidence</a>"
}

# Finding: SMBv1 status
$smb1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smb1 -eq $true) {
    Add-Finding "HIGH" "SMBv1 Enabled" "SMBv1 is legacy and highly vulnerable to exploits like EternalBlue." "Native API"
}

# Finding: Antivirus
$av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
if (-not $av) {
    Add-Finding "HIGH" "No Antivirus Detected" "WMI query returned no registered AntiVirus product." "<a href='#81_av_status'>evidence</a>"
}

# ------------------------------------------------------------
# HTML Report Generation
# ------------------------------------------------------------
Write-Progress-Simple "Generating HTML report"
$END_TIME = Get-Date
$END_EPOCH = [DateTimeOffset]::Now.ToUnixTimeSeconds()
$DURATION = $END_EPOCH - $START_EPOCH

$html_header = @"
<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${PROG} report - ${HOST_NAME}</title>
<style>
  body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}
  h1{margin:0 0 8px 0}
  pre{white-space:pre-wrap;background:#f6f8fa;border:1px solid #d0d7de;padding:12px;border-radius:8px}
  table{border-collapse:collapse;width:100%;margin-bottom:20px}
  th,td{border:1px solid #d0d7de;padding:8px;text-align:left}
  th{background:#f6f8fa}
  .sev-HIGH{background:#ffebe9;color:#cf222e;padding:2px 6px;border-radius:4px}
  .sev-MEDIUM{background:#fff8c5;color:#9a6700;padding:2px 6px;border-radius:4px}
  .sev-OK{background:#dafbe1;color:#1a7f37;padding:2px 6px;border-radius:4px}
  .sev-INFO{background:#ddf4ff;color:#0969da;padding:2px 6px;border-radius:4px}
</style>
</head><body>
<h1>${PROG} - Inventory & Audit</h1>
<h2>Execution Summary</h2>
<pre>
Host: $HOST_NAME
Start: $START_TIME
End: $END_TIME
Duration: $DURATION seconds
Output Dir: $OUTDIR
</pre>
<h2>Automated Findings</h2>
<table>
<tr><th>Severity</th><th>Finding</th><th>Details</th><th>Evidence</th></tr>
$FINDINGS_HTML
</table>
<h2>Collected Data</h2>
"@

$html_content = ""
Get-ChildItem $DATADIR -Filter *.txt | ForEach-Object {
    $name = $_.BaseName
    $content = Get-Content $_.FullName | Out-String
    $html_content += "<h3 id='$name'>$name</h3><pre>$([System.Net.WebUtility]::HtmlEncode($content))</pre>"
}

$html_header + $html_content + "</body></html>" | Out-File $HTML -Encoding utf8

# ------------------------------------------------------------
# Packaging
# ------------------------------------------------------------
Write-Progress-Simple "Packaging results"
$zipPath = "$OUTDIR.zip"
if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
    Compress-Archive -Path $OUTDIR -DestinationPath $zipPath -Force
}

Write-Progress -Activity "Finished" -Completed
Write-Host "`n[OK] Report generated at: $OUTDIR" -ForegroundColor Green
Write-Host "[OK] Archive created: $zipPath" -ForegroundColor Cyan
