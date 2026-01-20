# ATT&CK-ARENA: Gladiator Deployment Script
# ---------------------------------------------------------
Clear-Host
Write-Host "WELCOME TO THE ATT&CK-ARENA" -ForegroundColor Cyan
Write-Host "WARNING: This script will modify system settings and RESTART the machine." -ForegroundColor Yellow
Write-Host "---------------------------------------------------------"

# 1. Check Admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator!"
    exit
}

# 2. Champion & Network Setup
$ChampionIP = Read-Host "Enter the Champion (DC) IP Address"
Write-Host "[*] Verifying Champion availability..." -ForegroundColor Gray
if (!(Test-Connection -ComputerName $ChampionIP -Count 2 -Quiet)) {
    Write-Host "[!] ERROR: Champion at $ChampionIP did not respond to ping. Build the DC first!" -ForegroundColor Red
    exit
}

$TargetIP = Read-Host "Enter the FIXED IP for this Gladiator"
$Gateway  = Read-Host "Enter the Network Gateway IP"

Write-Host "[*] Applying Static Networking..." -ForegroundColor Gray
$Interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $Interface.InterfaceIndex -IPAddress $TargetIP -PrefixLength 24 -DefaultGateway $Gateway -Confirm:$false -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceIndex $Interface.InterfaceIndex -ServerAddresses $ChampionIP

# 3. Security Hardening (Firewall, Registry, AuditPol)
Write-Host "[*] Configuring Firewall, Registry, and Audit Policies..." -ForegroundColor Gray
netsh advfirewall firewall add rule name="ARENA-Allow-ICMPv4-In" protocol=icmpv4:8,any dir=in action=allow
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -Value 1
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Output /t REG_DWORD /d 1 /f

# 4. Sysmon Installation
$ToolsDir = "C:\Arena-Tools"
if (!(Test-Path $ToolsDir)) { New-Item $ToolsDir -ItemType Directory }
Write-Host "[*] Installing Sysmon with Olaf Hartong's Config..." -ForegroundColor Gray
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$ToolsDir\Sysmon.zip"
Expand-Archive "$ToolsDir\Sysmon.zip" -DestinationPath "$ToolsDir\Sysmon" -Force
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "$ToolsDir\Sysmon\sysmonconfig.xml"
Start-Process "$ToolsDir\Sysmon\Sysmon64.exe" -ArgumentList "-i $ToolsDir\Sysmon\sysmonconfig.xml -accepteula" -Wait

# 5. Winlogbeat Deployment
Write-Host "[*] Deploying Winlogbeat..." -ForegroundColor Gray
$WLB_URL = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.12.0-windows-x86_64.zip"
Invoke-WebRequest -Uri $WLB_URL -OutFile "$ToolsDir\Winlogbeat.zip"
Expand-Archive "$ToolsDir\Winlogbeat.zip" -DestinationPath "$ToolsDir" -Force
# Handling the versioned folder name
$ExtractedFolder = Get-ChildItem -Path $ToolsDir -Filter "winlogbeat-*" -Directory | Select-Object -First 1
Move-Item $ExtractedFolder.FullName "$ToolsDir\Winlogbeat" -Force

# Create YAML (Sentinel is usually at .100 in our setup)
$SuggestedSentinel = $TargetIP.Substring(0, $TargetIP.LastIndexOf('.')) + ".100"
$SentinelIP = Read-Host "Enter Sentinel (ELK) IP Address [Default: $SuggestedSentinel]"
if ([string]::IsNullOrWhiteSpace($SentinelIP)) { $SentinelIP = $SuggestedSentinel }

$Yaml = @"
winlogbeat.event_logs:
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4104
output.logstash:
  hosts: ["$SentinelIP:5044"]
"@
$Yaml | Out-File "$ToolsDir\Winlogbeat\winlogbeat.yml" -Encoding ascii
Set-Location "$ToolsDir\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat

# 6. Connectivity Test
Write-Host "[?] Final Connectivity Check..." -ForegroundColor Gray
if (Test-Connection -ComputerName $SentinelIP -Count 1 -Quiet) { Write-Host ">> Sentinel Reachable." -ForegroundColor Green }
if (Test-Connection -ComputerName $ChampionIP -Count 1 -Quiet) { Write-Host ">> Champion Reachable." -ForegroundColor Green }

# 7. Identity & Restart
$NewName = Read-Host "Enter New Hostname [Default: Gladiator]"
if ([string]::IsNullOrWhiteSpace($NewName)) { $NewName = "Gladiator" }
$Domain = Read-Host "Enter Domain to join [Default: arena.local]"
if ([string]::IsNullOrWhiteSpace($Domain)) { $Domain = "arena.local" }

Write-Host "[!] Ready to join $Domain. You will be prompted for credentials." -ForegroundColor Cyan
$Credential = Get-Credential -UserName "Administrator" -Message "Enter Domain Admin Password"
Add-Computer -NewName $NewName -DomainName $Domain -Credential $Credential -Force

Write-Host "ALL SYSTEMS READY. Restarting in 10 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 10
Restart-Computer
