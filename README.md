# 🛡️ Zerguz SOCAgent

> **A lightweight SOC monitoring application developed in Python that combines Network Intrusion Detection System (NIDS) and Endpoint Detection & Response (EDR) capabilities into a single tool.**

Zerguz SOCAgent is a real-time security monitoring solution developed for Blue Team operations, SOC laboratories, and cybersecurity training environments.

The application not only analyzes network traffic but also continuously monitors running system processes to detect suspicious behavior, generate security alerts, and collect forensic evidence for further investigation.

---

# 🚀 Features

## 🌐 NIDS (Network Intrusion Detection System)

Using Scapy, the application analyzes live network traffic and detects the following attack patterns:

* TCP Port Scanning
* UDP Port Scanning
* ICMP Flood / Ping Sweep
* DNS Tunneling Attempts
* Excessive DNS Traffic
* Abnormally Long DNS Queries

Whenever an attack is detected, the system automatically:

* Generates a real-time security alert.
* Saves the related packets as a PCAP file.
* Creates a structured JSON alert log.
* Reports detailed information about the detected event.

---

## 🖥️ EDR (Endpoint Detection & Response)

SOCAgent does more than monitor network traffic.

It continuously analyzes running system processes to identify suspicious activities.

Current detection capabilities include:

* Applications executed from suspicious directories
* Shell processes launched by web servers
* Potential WebShell activity
* Continuous live process monitoring

Supported web servers:

* Apache
* Nginx
* HTTPD
* Tomcat
* IIS (w3wp)

Monitored command-line interpreters:

* cmd.exe
* PowerShell
* Bash
* Sh
* Zsh
* Dash
* Ash

---

# 📦 Evidence Collection

Whenever a network attack is detected, SOCAgent automatically records the following information.

## PCAP File

The packets related to the detected attack are automatically captured and saved.

Example:

```text
zerguz_evidence_PORT_SCAN_192.168.1.15_20260705_213500.pcap
```

## JSON Alert Log

Each generated alert includes:

* Date
* Time
* Detection Module
* Attack Type
* Source IP
* Destination IP
* Description
* PCAP Evidence

These logs can be easily integrated into SIEM platforms or other security analysis tools.

---

# 🔍 Supported Detection Capabilities

## Network Security

* Port Scan Detection
* ICMP Flood Detection
* Ping Sweep Detection
* DNS Tunneling Detection
* DNS Frequency Analysis
* DNS Query Length Analysis
* Packet History Tracking
* Alert Cooldown Mechanism

## Endpoint Security

* Suspicious Directory Detection
* Parent Process Analysis
* WebShell Behavior Detection
* Live Process Monitoring

---

# 📂 Project Structure

```text
Zerguz-SOCAgent-EN.py
zerguz_soc_alerts.json
zerguz_evidence_*.pcap
```

---

# 🛠️ Technologies Used

* Python 3
* Scapy
* psutil
* Colorama
* JSON
* Multithreading
* Packet Capture (PCAP)

---

# ⚙️ Installation

Clone the repository.

```bash
git clone https://github.com/Malikejder/Zerguz-SOCAgent-EN.git
cd Zerguz-SOCAgent
```

Install the required dependencies.

```bash
pip install scapy psutil colorama
```

Linux users may also need to install the following package.

```bash
sudo apt install libpcap-dev
```

---

# ▶️ Usage

Linux

```bash
sudo python3 Zerguz-SOCAgent-EN.py
```

Windows (Run as Administrator)

```bash
python Zerguz-SOCAgent-EN.py
```

---

# 📋 Example Alerts

### NIDS

```text
[ALERT - NIDS]

Attack Type : PORT_SCAN_DETECTED

Source IP : 192.168.1.50

Destination IP : 192.168.1.10

PCAP Evidence Saved
```

### EDR

```text
[ALERT - EDR]

Attack Type : WEBSHELL_ANOMALY_DETECTED

Process : cmd.exe

Parent : w3wp.exe
```

---

# 📁 Generated Files

## JSON Alert Log

```text
zerguz_soc_alerts.json
```

All detected events are stored in structured JSON format.

## PCAP Evidence Files

```text
zerguz_evidence_<attack>_<ip>_<timestamp>.pcap
```

A separate PCAP file containing the relevant network traffic is generated for every detected attack.

---

# 🎯 Project Objectives

This project was developed to gain practical experience in the following areas:

* SOC Operations
* Blue Team Practices
* Network Security Monitoring
* Endpoint Detection & Response (EDR)
* Incident Response
* Packet Analysis
* Security Automation with Python
* Digital Forensics and Evidence Collection
* Cyber Threat Analysis

---

# ⚠️ Legal Disclaimer

This project is intended solely for educational purposes, laboratory environments, Blue Team exercises, and authorized security testing.

It should not be used on unauthorized systems or networks.

The developer assumes no responsibility for any misuse of this software.

---

# 👨‍💻 Developer

**Malikejder Durgun**

Computer Programmer | Cybersecurity | Blue Team | SOC Analyst | Python Security Tool Developer
