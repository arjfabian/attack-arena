# 1. Force Advanced Audit Policy to override Basic Policy
$regPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $regPath -Name "SCENoApplyLegacyAuditPolicy" -Value 1

# 2. Enable Advanced Audit Categories (Process Creation & Command Line)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
reg add "hklm\software\microsoft\windows\currentversion\policies\system\audit" /v ProcessCreationIncludeCmdLine_Output /t REG_DWORD /d 1 /f

# 3. Enable PowerShell Script Block Logging (The #1 way to catch fileless attacks)
$psLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force }
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1

# 4. Open Ports for Logging (allowing Winlogbeat to reach Debian)
New-NetFirewallRule -DisplayName "Arena-Log-Out" -Direction Outbound -LocalPort 5044 -Protocol TCP -Action Allow

Write-Host "AA-TARGET: Audit Policies and Telemetry have been hardened for the Arena." -ForegroundColor Cyan