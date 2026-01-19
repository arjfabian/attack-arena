![ATT&CK-ARENA Logo](assets/logo/logo-128x128.png)

# ⚔️ ATT&CK-ARENA

## Phase 1: Setting Up The Infrastructure

ATT&CK-ARENA is a Purple Team lab that helps simulate attack techniques from Atomic Red Team and capture them using the ELK stack (Elasticsearch, Logstash, and Kibana), in order to validate whether a SIEM ruleset is effective before deploying them to production.

The project uses a hybrid environment that combines Windows virtual machines (VMs) and Docker containers to simulate an enterprise setting:

- A Windows 10 workstation (`Gladiator`),
- A Windows Server workstation (`Champion`),
- A Kali Linux Machine (`Challenger`),
- The ELK stack (`[TODO: Add name]`), inside a Docker container.

The Dockerized component is intended to keep data safe even if the container is eventually destroyed.

While the Windows VMs are to be provided by the user, instructions for configuring them and the Docker container will be provided in this document as well.

### 1.1 The Host

YOUR_HOST_IP

#### 1.1.1 The `docker-compose.yml`

At the project root, set up a Docker Compose YAML file that will set up the network and the security parameters automatically for the ELK stack.

```yaml
services:
  # The Brain: Elasticsearch
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: aa-elasticsearch
    environment:
      - node.name=aa-elasticsearch
      - discovery.type=single-node
      - xpack.security.enabled=false # Set to true later for production hardening
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"
    networks:
      - arena-net

  # The Collector: Logstash
  logstash:
    image: docker.elastic.co/logstash/logstash:8.12.0
    container_name: aa-logstash
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
    ports:
      - "5044:5044"
    depends_on:
      - elasticsearch
    networks:
      - arena-net

  # The Face: Kibana
  kibana:
    image: docker.elastic.co/kibana/kibana:8.12.0
    container_name: aa-kibana
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch
    networks:
      - arena-net

networks:
  arena-net:
    driver: bridge

volumes:
  esdata:
    driver: local
```

### 1.2 The Windows Server Target: `Champion`

The `Champion` acts as the Domain Controller (DC) for the `arena.local` forest.
For developing this project, Windows Server 2022 (Evaluation Version, with Desktop Experience) will be used.

#### 1.2.1 Promotion to Domain Controller

The first step is to promote the Champion to DC, and then let the Gladiator join.

This code is provided as `promotion.ps1` inside the `infrastructure/champion/` folder.

```powershell
# 1. Install Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# 2. Create the Arena Forest (This will prompt for a DSRM password)
# Note: This will automatically reboot the server!
Install-ADDSForest `
    -DomainName "arena.local" `
    -DomainNetbiosName "ARENA" `
    -InstallDns `
    -Force
```

**NOTE:** In order for PowerShell to allow execution of this script, run the following command:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

You will be asked for a "SafeModeAdministratorPassword". Define a strong password and proceed. Windows Server will be restarted.

#### 1.2.2 Advanced Auditing for the Champion

To catch Lateral Movement and Kerberoasting, the Champion needs specific "eyes" that are usually off by default.

This code is provided as `advanced-auditing.ps1` inside the `infrastructure/champion/` folder.

```powershell
# Enable Directory Service Changes (Success)
auditpol /set /subcategory:"Directory Service Changes" /success:enable

# Enable Account Management (Success/Failure)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable

# Force the policy update
gpupdate /force
```

#### 1.2.3 Sysmon

We will use Olaf Hartong’s Sysmon-Modular configuration. It is specifically designed for detection engineering because it maps events directly to MITRE ATT&CK IDs.

1. First, download Sysmon via the [Official Microsoft Sysinternals Link](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and put it in the `C:\Program Files\` folder. For offline testing purposes, a copy of the tool (as a ZIP file) is included in the `infrastructure/gladiator/` folder.

2. Download the Config: Save Olaf Hartong's [sysmonconfig.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml) into the same folder as Sysmon. For offline testing purposes, a copy of the file is included in the `infrastructure/gladiator/` folder.

3. Install via PowerShell (Admin):

    ```powershell
    .\Sysmon64.exe -i sysmonconfig.xml -accepteula
    ```

#### 1.3.4 Winlogbeat (The Courier)

Now that Sysmon is generating "combat data," we need it to be visible to the ELK stack.

1. Download [Winlogbeat 8.12.0 x86_64](https://www.elastic.co/downloads/past-releases/winlogbeat-8-12-0) and put it in the `C:\Program Files\` folder. For offline testing purposes, a copy of the tool (as a ZIP file) is included in the `infrastructure/gladiator/` folder 

2. Set up a minimal configuration for Winlogbeat so that Security, System, and Sysmon/Operational logs are sent to the SIEM core over port 5044.

This code is provided as `winlogbeat.yml` inside the `infrastructure/gladiator/` folder.

```yaml
winlogbeat.event_logs:
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4104 # Captures Script Blocks

output.logstash:
  hosts: ["<YOUR_HOST_IP>:5044"]

logging.level: info
logging.to_files: true
```

**IMPORTANT:** Replace <YOUR_HOST_IP> with the IP set in [Step 1.1](#11-the-host).

3. Install and start the service:

```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

4. Verify the connection (a.k.a. The First "Ping"):

    1. Go to your browser at `http://localhost:5601` (Kibana).
    2. Click Explore on my own.
    3. Go to Stack Management > Index Management.

If you see an index named something like `arena-logs-`, the "Arena" is live.



### 1.3 The Windows 10 Target: `Gladiator`

The Windows 10 host will generate high-fidelity telemetry for the Sentinel.

#### 1.3.1 Domain Join

```powershell
# Join the domain (It will prompt for the Champion's Administrator credentials)
Add-Computer -DomainName "arena.local" -Restart
```

**NOTE:** In order for PowerShell to allow execution of this script, run the following command:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### 1.3.2 Preparation Script

The first step is to run a PowerShell script that forces the advanced auditing policies needed to map to MITRE ATT&CK. The script does three things:

1. **Enables Advanced Auditing:** Turns on "Process Creation" (with command-line arguments), "Registry Changes," and "Logon/Logoff" events.

2. **Powershell Logging:** Turns on Script Block Logging (crucial for catching obfuscated malware).

3. **Firewall Prep:** Opens the ports needed for you to send logs to the Sentinel later.

This code is provided as `arena-prep.ps1` inside the `infrastructure/gladiator/` folder.

```powershell
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
```

#### 1.3.3 Sysmon

We will use Olaf Hartong’s Sysmon-Modular configuration. It is specifically designed for detection engineering because it maps events directly to MITRE ATT&CK IDs.

1. First, download Sysmon via the [Official Microsoft Sysinternals Link](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and put it in the `C:\Program Files\` folder. For offline testing purposes, a copy of the tool (as a ZIP file) is included in the `infrastructure/gladiator/` folder.

2. Download the Config: Save Olaf Hartong's [sysmonconfig.xml](https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml) into the same folder as Sysmon. For offline testing purposes, a copy of the file is included in the `infrastructure/gladiator/` folder.

3. Install via PowerShell (Admin):

    ```powershell
    .\Sysmon64.exe -i sysmonconfig.xml -accepteula
    ```

#### 1.3.4 Winlogbeat (The Courier)

Now that Sysmon is generating "combat data," we need it to be visible to the ELK stack.

1. Download [Winlogbeat 8.12.0 x86_64](https://www.elastic.co/downloads/past-releases/winlogbeat-8-12-0) and put it in the `C:\Program Files\` folder. For offline testing purposes, a copy of the tool (as a ZIP file) is included in the `infrastructure/gladiator/` folder 

2. Set up a minimal configuration for Winlogbeat so that Security, System, and Sysmon/Operational logs are sent to the SIEM core over port 5044.

This code is provided as `winlogbeat.yml` inside the `infrastructure/gladiator/` folder.

```yaml
winlogbeat.event_logs:
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4104 # Captures Script Blocks

output.logstash:
  hosts: ["<YOUR_HOST_IP>:5044"]

logging.level: info
logging.to_files: true
```

**IMPORTANT:** Replace <YOUR_HOST_IP> with the IP set in [Step 1.1](#11-the-host).

3. Install and start the service:

```powershell
cd "C:\Program Files\Winlogbeat"
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

4. Verify the connection (a.k.a. The First "Ping"):

    1. Go to your browser at `http://localhost:5601` (Kibana).
    2. Click Explore on my own.
    3. Go to Stack Management > Index Management.

If you see an index named something like `arena-logs-`, the "Arena" is live.






---

## Other Steps (not yet implemented)

```bash
# 5.1. Install UFW
sudo apt install ufw -y

# 5.2. Enable Firewall
sudo ufw enable

# 5.3. Add necessary rules for the lab
# 9200: Elasticsearch API (internal comms)
# 5601: Kibana Web UI (host access)
# 5044: Logstash Beats Input (Target VM logs)
# 22: SSH (remote management)
sudo ufw allow 9200/tcp
sudo ufw allow 5601/tcp
sudo ufw allow 5044/tcp
sudo ufw allow 22/tcp

# 5.4. Verification (Matches your status output)
sudo ufw status
```


## Troubleshooting

### Fail to join domain

#### Problem

You receive the message `Computer 'aa-gladiator' failed to join domain 'arena.local' from its current group 'WORKGROUP' with following error message: The specified domain either does not exist or could not be contacted.` (or similar) when trying to join the domain.

#### Solution

If you can ping the Champion from the Gladiator, the problem might be DNS resolution.

**The DNS "Handshake" Test**

On your Gladiator (W10), run this command. It doesn't just ping; it asks DNS for the "Secret Map" of your domain:

```powershell
nslookup -type=srv _ldap._tcp.dc._msdcs.arena.local
```

If it fails, the Gladiator is likely using your router or a public DNS (like `8.8.8.8`) instead of the Champion.

**The Fix:** Go to the Gladiator's Network Adapter settings and manually set the Primary DNS to the static IP of the Champion. Leave the secondary DNS blank for now. Then test again.