# ⚔️ ATT&CK-ARENA

## Introduction

**ATT&CK-ARENA** is a high-fidelity Purple Team playground designed to bridge the gap between "running an attack" and "building a defense." By simulating real-world adversary behaviors via **Atomic Red Team** and capturing deep telemetry through a dockerized **ELK Stack**, this lab provides a safe, reproducible environment to validate SIEM rules before they hit production.

Whether you are a **SOC Analyst** looking to "proof" your detections or a **Cybersecurity Student** hungry for raw log analysis, ATT&CK-ARENA provides the infrastructure to see the battle from both sides.

## The Combatants

The arena mimics a modern enterprise environment through a hybrid VM/Container architecture:

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

To replicate this environment, I recommend the following "Gold Image" setup:

| Component | Software / Version |
| --- | --- |
| **OS - Workstation** | Windows 10 Pro |
| **OS - Server** | Windows Server 2022 (Standard/Eval) |
| **Telemetry** | Sysmon v15.15 (with modular configuration) |
| **Shipper** | Winlogbeat v8.12.0 |
| **Stack** | ELK Stack (Dockerized) |

> **Note:** Detailed configuration scripts for each combatant can be found in the `infrastructure/` directory.

## Current Status

🟢 **Operational:**
- ELK Stack deployment (Elasticsearch 8.12, Logstash, Kibana)
- Active Directory environment (Champion as DC)
- Sysmon + Winlogbeat telemetry pipeline
- Network connectivity between all combatants

🟡 **In Progress:**
- Implementing MITRE ATT&CK techniques (Discovery, Persistence phases)
- Building detection rules library
- Documenting simulation reports

🔴 **Planned:**
- Full Atomic Red Team integration
- Automated attack orchestration
- Custom Kibana dashboards for each tactic

## Licensing

This project is licensed under the **MIT License** - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details. Essentially, you are free to use, modify, and distribute this lab as long as you provide attribution.
