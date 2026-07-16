# Breacher_Ips
A multi-threaded, asynchronous Host-based Intrusion Prevention System (HIPS) engineered in Python. Utilizes Scapy for real-time packet ingestion, sliding-window signatures for stateful threat detection, and kernel-level Netfilter/iptables rules for automated active mitigation
---

##  Architectural Topology

The system uses an asynchronous execution queue to guarantee zero-drop packet monitoring under intense traffic streams.
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
