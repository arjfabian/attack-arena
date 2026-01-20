# Technique: [MITRE ID - Name]

## 1. Hypothesis
*We believe that [Technique Name] can be detected by monitoring [Process/Registry/Network] events from [Gladiator/Champion].*

## 2. The Attack (Challenger)
- **Tool:** [e.g., Nmap, PowerShell, Atomic Red Team]
- **Command:** ```powershell
  [The exact command you ran]

```

## 3. The Evidence (Sentinel)

* **Log Source:** [e.g., Sysmon, WinEventLog]
* **Event ID:** [e.g., 1 (Process Create)]
* **Key Fields:**
* `process.command_line`: ...
* `user.name`: ...



## 4. Detection Logic

* **KQL Query:** `process.name : "powershell.exe" and ...`
* **Sigma Rule:** [Link to file in /detections]

```
