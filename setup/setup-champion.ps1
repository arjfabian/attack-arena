# ATT&CK-ARENA: Champion (Domain Controller) Deployment Orchestrator
# ---------------------------------------------------------
$ArenaDomain = "arena.local"
$ToolsDir    = "C:\Arena-Tools"
$RAW_BASE    = "https://raw.githubusercontent.com/arjfabian/attack-arena/refs/heads/main/setup/configs"

# 1. Admin Check
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Please run this script as Administrator!"
    exit
}

# --- PHASE DETECTION ---
# ProductType 2 = Domain Controller.
$IsDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2

if (-not $IsDC) {
    # ==========================================
    # PHASE 1: PRE-PROMOTION
    # ==========================================
    Write-Host "CHAMPION PHASE 1: INFRASTRUCTURE" -ForegroundColor Cyan
    
    $TargetIP = Read-Host "Enter the FIXED IP for this Champion (e.g., 192.168.122.200)"
    $Gateway  = Read-Host "Enter the Network Gateway IP"

    Write-Host "[*] Configuring Static Networking..." -ForegroundColor Gray
    $Interface = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    New-NetIPAddress -InterfaceIndex $Interface.InterfaceIndex -IPAddress $TargetIP -PrefixLength 24 -DefaultGateway $Gateway -Confirm:$false -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceIndex $Interface.InterfaceIndex -ServerAddresses "127.0.0.1"

    Write-Host "[*] Installing AD DS Role & Renaming..." -ForegroundColor Gray
    Rename-Computer -NewName "aa-champion" -Force -ErrorAction SilentlyContinue
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

    Write-Host "[!] PROMOTING TO DC. You will be prompted for a DSRM Password." -ForegroundColor Yellow
    $DSRMPass = Read-Host "Enter DSRM Password" -AsSecureString
    
    Install-ADDSForest `
        -DomainName $ArenaDomain `
        -DomainNetbiosName "ARENA" `
        -SafeModeAdministratorPassword $DSRMPass `
        -InstallDns -Force
} 
else {
    # ==========================================
    # PHASE 2: TELEMETRY (POST-REBOOT)
    # ==========================================
    Write-Host "CHAMPION PHASE 2: TELEMETRY" -ForegroundColor Cyan
    
    # 1. Advanced Auditing
    Write-Host "[*] Enabling Advanced Domain Auditing..." -ForegroundColor Gray
    auditpol /set /subcategory:"Directory Service Changes" /success:enable
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Output /t REG_DWORD /d 1 /f

    # 2. Sysmon
    if (!(Test-Path $ToolsDir)) { New-Item $ToolsDir -ItemType Directory }
    Write-Host "[*] Downloading Sysmon and custom Arena config..." -ForegroundColor Gray
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$ToolsDir\Sysmon.zip"
    Expand-Archive "$ToolsDir\Sysmon.zip" -DestinationPath "$ToolsDir\Sysmon" -Force
    
    # FETCH CONFIG FROM YOUR REPO
    Invoke-WebRequest -Uri "$RAW_BASE/sysmonconfig.xml" -OutFile "$ToolsDir\Sysmon\sysmonconfig.xml"
    Start-Process "$ToolsDir\Sysmon\Sysmon64.exe" -ArgumentList "-i $ToolsDir\Sysmon\sysmonconfig.xml -accepteula" -Wait

    # 3. Winlogbeat
    $SentinelIP = Read-Host "Enter Sentinel (ELK) IP Address"
    Write-Host "[*] Deploying Winlogbeat with remote assets..." -ForegroundColor Gray
    $WLB_URL = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.12.0-windows-x86_64.zip"
    Invoke-WebRequest -Uri $WLB_URL -OutFile "$ToolsDir\Winlogbeat.zip"
    Expand-Archive "$ToolsDir\Winlogbeat.zip" -DestinationPath "$ToolsDir" -Force
    $ExtractedFolder = Get-ChildItem -Path $ToolsDir -Filter "winlogbeat-*" -Directory | Select-Object -First 1
    Move-Item $ExtractedFolder.FullName "$ToolsDir\Winlogbeat" -Force

    # FETCH YAML TEMPLATE FROM YOUR REPO AND INJECT IP
    Invoke-WebRequest -Uri "$RAW_BASE/winlogbeat.yml" -OutFile "$ToolsDir\Winlogbeat\winlogbeat.yml"
    (Get-Content "$ToolsDir\Winlogbeat\winlogbeat.yml") -replace "<SENTINEL_IP>", $SentinelIP | Set-Content "$ToolsDir\Winlogbeat\winlogbeat.yml"

    Set-Location "$ToolsDir\Winlogbeat"
    .\install-service-winlogbeat.ps1
    Start-Service winlogbeat
    
    Write-Host "CHAMPION IS READY. The Forest is guarded." -ForegroundColor Green
}