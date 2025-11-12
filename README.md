# Simple Port Scanning tool

A lightweight Python tool using **Scapy** to perform automated **pre-ATT&CK reconnaissance** — combining SYN port scanning and DNS probing — with structured **JSON output** for analysis.

> ⚠️ **Ethical Use Only:**  
> This tool is intended **solely for learning, testing, and authorized security assessment**.  
> Do **not** scan systems or networks you do not own or have explicit written permission to test.

---

## 🔍 Features

- Performs **TCP SYN scans** on a list of common ports (half-open technique).
- Sends **DNS probes (UDP/53)** to detect DNS responders.  
- Collects basic **device fingerprinting hints** (open ports, banners, timing).  
- Exports all scan results to a structured **JSON file** for easy integration or analysis.  
- Lightweight, dependency-minimal, and easy to extend for red-team pre-ATT&CK phases.

---

## ⚙️ Requirements

- Python **3.8+** (tested up to 3.12)  
- `scapy` Python package → `pip install scapy`  
- **Administrator / root privileges** required for SYN scans (use `sudo` on Unix systems)

---
## Example Output 
![Scan Output](./Output.png)

