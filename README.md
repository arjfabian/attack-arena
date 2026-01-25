# ⚔️ ATT&CK-FORGE

## Introduction

**ATT&CK-FORGE** is a high-fidelity Purple Team playground designed to bridge the gap between "running an attack" and "building a defense." By simulating real-world adversary behaviors via **Atomic Red Team** and capturing deep telemetry through a dockerized **ELK Stack**, this lab provides a safe, reproducible environment to validate SIEM rules before they hit production.

Whether you are a **SOC Analyst** or a **Cybersecurity Student**, ATT&CK-FORGE provides the infrastructure to see the battle from both sides, with exposure to production-style telemetry.

## Why This Lab Exists

Most Purple Team labs focus on *executing* attacks. ATT&CK-FORGE focuses on *validating detections*, without the shift to a red team framework or a full SOC platform.

The key question this lab answers: **"How do I know my SIEM rules actually work before deploying them to production?"**

By testing detection logic against controlled adversary behaviors in a safe environment, you can:
- Reduce false positives before they overwhelm your SOC
- Identify coverage gaps in your monitoring stack
- Build institutional knowledge of attack patterns
- Develop muscle memory for incident triage

ATT&CK-FORGE features an aggressive Signal-To-Noise curation via specific Logstash tweaks, to reduce ~90% of the noise before the logs ever leave the endpoints (**Champion** or **Gladiator**), while still capturing Atomic Red Team simulations. In real-world environments, similar filtering strategies can significantly reduce storage requirements and analyst distraction.

## The Combatants

The Forge mimics a modern enterprise environment through a hybrid VM/Container architecture:

* **🛡️ Gladiator (Workstation):** A Windows 10 endpoint—the primary target for client-side attacks.
* **🏰 Champion (Server):** A Windows Server 2022 Domain Controller—the "Crown Jewel" of the domain.
* **🏹 Challenger (Attacker):** A Kali Linux machine armed with Nmap and Atomic Red Team scripts.
* **👁️ Sentinel (SIEM):** A containerized ELK stack (Elasticsearch, Logstash, Kibana) acting as the all-seeing eye.

## The Rules of Engagement

1. **Launch:** Execute a technique from the `Challenger` against a target.
2. **Observe:** Monitor the `Sentinel` dashboard to see if the telemetry reaches the SIEM.
3. **Analyze:** Use the [Report Template](./simulations/REPORT-TEMPLATE.md) to document the detection.
4. **Harden:** Adjust Sysmon configs or GPOs and repeat the attack to verify the new defense.

## Lab Specifications

To replicate the stable environment used in developing this project, I recommend the following "Gold Image" setup:

| Component | Software / Version |
| --- | --- |
| **OS - Workstation** | Windows 10 Pro |
| **OS - Server** | Windows Server 2022 (Standard/Eval) |
| **Telemetry** | Sysmon v15.15 (with modular configuration) |
| **Shipper** | Winlogbeat v8.12.0 |
| **Stack** | ELK Stack (Dockerized) |

Please note that the architecture is actually **hardware-agnostic** so it can be deployed either on virtual machines (for a portable lab environment) or on physical hosts (enabling realistic endpoint behavior, timing characteristics, or team roleplay).

## Quick Start (in Development)

### Infrastructure Setup

The setup scripts, contained in the `setup/` folder, act as "one-liners" to deploy the necessary infrastructure to the **Sentinel**, the **Champion** and the **Gladiator**.

In the Docker host, run this script to setup the Sentinel:

```sh
curl -sSL datorum.net/af-setup-sentinel/ | bash
```

In the Windows Server machine, run this script to setup the Champion:

```pwsh
irm https://datorum.net/aa-setup-champion/ | iex
```

In the Windows machine, run this script to setup the Gladiator:

```pwsh
irm https://datorum.net/aa-setup-gladiator/ | iex
```

### Testing

Verify that Kibana started capturing logs:

1. In the Linux host, go to `http://localhost:5601`.
2. Go to **Stack Management > Index Management**.
3. Check if `forge-logs-[today's-date]` exists.
4. If it exists, go to **Discover** and make sure your Data View (Index Pattern) is set to `forge-logs-*`.

Notes about tests will be added as soon as they're available.

## Project Lifecycle

ATT&CK-FORGE is being actively developed in iterative phases:

🟢 **Phase 1 (Completed):** Telemetry pipeline, infrastructure, and baseline filtering
🟡 **Phase 2 (In Progress):** Controlled simulation of selected MITRE ATT&CK techniques with documented detections
⚪ **Phase 3 (Planned):** Detection regression, logic updates, and software version drift handling (potentially automated).

## Disclaimer

⚠️ **This lab is for authorized security testing and educational purposes only.**

Do not use techniques demonstrated here against systems you don't own or have explicit permission to test. Unauthorized access to computer systems is illegal.

## Licensing

This project is licensed under the **MIT License**. You are free to use, modify, and distribute this lab as long as you provide attribution.