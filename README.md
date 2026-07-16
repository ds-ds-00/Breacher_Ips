# Breacher_Ips
A multi-threaded, asynchronous Host-based Intrusion Prevention System (HIPS) engineered in Python. Utilizes Scapy for real-time packet ingestion, sliding-window signatures for stateful threat detection, and kernel-level Netfilter/iptables rules for automated active mitigation
---

##  Architectural Topology

The system uses an asynchronous execution queue to guarantee zero-drop packet monitoring under intense traffic streams.
<pre>
       ┌──────────────────────┐
       │  Raw Network Socket  │
       └──────────┬───────────┘
                  │
                  ▼ [Scapy Sniffer Loop]
       ┌──────────────────────┐
       │  Asynchronous Queue  │
       └──────────┬───────────┘
                  │
                  ▼ [ExtractorWorker Thread]
       ┌──────────────────────┐
       │  Feature Extraction  │
       └──────────┬───────────┘
                  │
                  ▼ [Normalized Data]
       ┌──────────────────────┐
       │   Detection Engine   │
       └────┬────────────┬────┘
            │            │
            │ Evaluate   │ Evaluate
            ▼ Modules    ▼ Components
   ┌────────────────┐   ┌─────────────────┐
   │ Stateful Rule  │   │ DatabaseManager │
   │   Evaluator    │   └────────┬────────┘
   └────────┬───────┘            │
            │                    ▼ [Thread-Safe Commit]
            ▼ Alert Triaged     ┌─────────────────┐
   ┌────────────────┐           │ SQLite Storage  │
   │    Firewall    │           │ (breacherips.db)│
   │   Controller   │           └─────────────────┘
   └────────┬───────┘
            │
            ▼ [System Call Wrapper]
   ┌────────────────┐
   │   Netfilter    │
   │  (iptables)    │
   └────────────────┘
</pre>


### Core Subsystems

1. **Ingestion Layer (`capture/`)**: Hooks into raw network socket interfaces using Scapy's non-blocking capture engine. Binds to designated adapters and pushes raw datagram structures straight onto an bounded processing queue.
2. **Parsing Layer (`parser/`)**: Spawns an isolated `ExtractorWorker` thread that constantly handles queue extraction, safely abstracting and normalizing structural attributes (IP headers, transport layer flags, timestamps).
3. **Detection Engine (`detection/`)**: Orchestrates concurrent, stateful inspection plugins using rolling time-window vectors. Current evaluation definitions cover:
   * **SYN Flood**: Tracks anomalous, asymmetric half-open TCP flags.
   * **Port Scan**: Evaluates unique threshold targets across horizontal/vertical port sweeps within tight temporal limits.
   * **ICMP Flood**: Monitors rapid ping intervals.
   * **Bruteforce**: Inspects rapid application-layer protocol failure densities.
4. **Mitigation Layer (`prevention/`)**: Manages real-time protection actions via a core network guardrail verification matrix. Includes an integrated CIDR-compliant network/host `whitelist` check. If a non-whitelisted anomaly triggers an alert, it dynamically drops hostile vectors at the kernel level using Netfilter rules.
5. **Persistence Layer (`database/`)**: A thread-safe transactional engine built on SQLite. It generates real-time telemetry analytics using optimized indices on security event records.

---

## 📁 Repository Directory Structure

```text
prevention_sys/
├── capture/
│   ├── __init__.py
│   └── sniffer.py           # Non-blocking raw packet sniffer loop
├── parser/
│   ├── __init__.py
│   └── extractor.py         # Asynchronous worker processing packet queue
├── detection/
│   ├── __init__.py
│   ├── engine.py            # Central analytics processing engine 
│   ├── syn.py               # Stateful TCP SYN Flood signature evaluation
│   ├── portscan.py          # Horizontal/Vertical port scan evaluation
│   ├── icmp.py              # Volumetric ICMP Flood evaluation
│   └── bruteforce.py        # Application authentication failure logic
├── prevention/
│   ├── __init__.py
│   ├── firewall.py          # Netfilter / iptables interaction wrapper
│   └── whitelist.py         # Thread-safe object managing safe CIDR blocks
├── database/
│   ├── __init__.py
│   ├── db.py                # Thread-safe SQLite engine manager
│   ├── models.py            # SQLite table definitions and indices
│   └── breacherips.db       # Persistent binary local ledger (Git ignored)
├── requirements.txt         # Frozen package deployment dependencies
├── .gitignore               # System, cache, and DB storage rules
├── main.py                  # Daemon application root startup coordinator
└── verify_db.py             # Administrative utility to dump raw events
```

---

# Core Subsystems

##  Ingestion Layer (`capture/`)

The ingestion layer is responsible for continuously monitoring network traffic using Scapy's packet capture engine. Packets are captured in real time and immediately placed into a thread-safe queue without performing any heavy processing. This design ensures that packet capture remains responsive even during periods of high network activity.

**Responsibilities**

- Capture live packets from the network interface
- Operate independently of the detection engine
- Push packets into a bounded processing queue
- Minimize packet loss during heavy traffic

---

##  Parsing Layer (`parser/`)

The parsing layer consists of a dedicated worker thread that continuously retrieves packets from the queue and extracts normalized features required by the detection engine.

Extracted information includes:

- Source IP Address
- Destination IP Address
- Source Port
- Destination Port
- Protocol
- TCP Flags
- Packet Timestamp

The normalized packet structure is then forwarded to the detection engine.

---

##  Detection Engine (`detection/`)

The detection engine performs stateful traffic analysis by maintaining sliding windows of network activity. Each attack detector operates independently and evaluates incoming packets against predefined thresholds.

Currently implemented detection modules include:

- **SYN Flood Detection**
  - Detects excessive TCP SYN packets originating from the same source.

- **Port Scan Detection**
  - Detects horizontal and vertical scanning by monitoring connections to multiple destination ports within a configurable time window.

- **ICMP Flood Detection**
  - Identifies abnormal ICMP Echo Request traffic exceeding normal operating thresholds.

- **Brute Force Detection**
  - Tracks repeated authentication attempts over a short period to identify potential password guessing attacks.

---

##  Prevention Layer (`prevention/`)

When malicious activity is detected, the prevention subsystem performs automated response actions.

Protection workflow:

1. Verify whether the source IP exists in the whitelist.
2. Ignore trusted hosts.
3. Insert an `iptables` DROP rule for malicious sources.
4. Record the prevention action inside the database.

---

## 💾 Persistence Layer (`database/`)

BreacherIPS stores all detected security events inside a local SQLite database.

Each record contains information such as:

- Timestamp
- Source IP
- Attack Type
- details
- Detection Status
- Prevention Action

The database layer is thread-safe and operates independently of the detection engine.


#  Installation

## Prerequisites

Install the required system packages on Ubuntu/Debian.

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv iptables nmap -y
```

---

## Clone the Repository

```bash
git clone https://github.com/ds-ds-00/Breacher_Ips.git

cd Breacher_Ips/prevention_sys
```

---

## Create Virtual Environment

```bash
python3 -m venv ips_env

source ips_env/bin/activate

pip install -r requirements.txt
```

---

## Configure Whitelist

Before launching BreacherIPS, whitelist your trusted IP addresses to prevent accidental blocking.

Example:

```python
whitelist.add_to_whitelist("127.0.0.1")
whitelist.add_to_whitelist("192.168.1.0/24")
```

---

## Start the IPS

```bash
sudo ../ips_env/bin/python3 main.py
```

---

# 🧪 Testing

## Verify Logged Events

```bash
sudo python3 verify_db.py
```

---

## Port Scan Detection

Run an Nmap SYN scan from another machine.

```bash
sudo nmap -sS <TARGET_IP>
```

---

## ICMP Flood Detection

```bash
ping -f <TARGET_IP>
```

---

## SYN Flood Detection

Generate a high volume of TCP SYN traffic using a controlled testing environment or penetration testing lab. BreacherIPS should detect the abnormal traffic pattern and automatically create an `iptables` rule for non-whitelisted hosts.

---

# ✨ Features

- Multi-threaded architecture
- Asynchronous producer-consumer pipeline
- Real-time packet capture using Scapy
- Stateful attack detection
- Automatic IP blocking via iptables
- Thread-safe SQLite logging
- Whitelist support
- Modular detection engine
- Easily extensible design

---

#  Future Enhancements

Planned improvements include:

- Automatic IP unblock utility
- Web dashboard for monitoring
- Email alerting
- Machine learning-based anomaly detection
- YAML rule configuration
- Docker support
- nftables support
- REST API

---





