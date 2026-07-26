# 🛡️ SENTINEL: The KYA (Know Your Agent) Identity Platform

[![Theme](https://img.shields.io/badge/Theme-Governance_Layer_for_Financial_Agents-blue.svg)](#)
[![Identity](https://img.shields.io/badge/Identity-KYA_(Know_Your_Agent)-purple.svg)](#)
[![Architecture](https://img.shields.io/badge/Architecture-Polyglot_Microservices-purple.svg)](#)
[![Status](https://img.shields.io/badge/Status-Active_Development-orange.svg)](#)

> **"Just like banks have KYC for humans, SENTINEL introduces KYA (Know Your Agent): A cryptographic, precedent-based Digital Passport for AI fleets."**

---

## 📖 Executive Summary
As financial institutions deploy autonomous AI agents, the attack surface expands exponentially. Traditional API Gateways enforce static network limits, effectively giving an AI a "blank check" once authorized. 

SENTINEL replaces this broken model with a fundamentally new AI Identity System. By issuing every agent a **Cryptographic Passport**, building a **Precedent-Based Governance** engine (Case Law), and treating AI risk as a systemic **Trust Economy**, SENTINEL guarantees that autonomous fleets operate safely, explainably, and predictably.

---

## 🛂 Core Innovation 1: The KYA Digital Passport
The fundamental flaw of current AI safety tools is that they govern *requests* in isolation. SENTINEL governs the *Identity*.

*   **Passport Issuance:** Every AI is issued a Digital Passport containing its role, risk budget, and Visa Status (e.g., *Full Autonomy*, *Human Quarantine*).
*   **Cryptographic Stamps (Immutable Memory):** Every financial decision the AI makes is cryptographically "stamped" into its passport using **SHA-256 Hash-Chaining** directly in PostgreSQL. The AI develops an immutable Governance Memory that cannot be forged or wiped.

---

## ⚖️ Core Innovation 2: Governance Case Law (Precedents over Thresholds)
Standard anomaly detection systems rely on arbitrary thresholds (e.g., "Block if anomaly > 80%"). This is unexplainable and fragile. SENTINEL replaces static math with **Precedent-Based Governance**.

When a complex or borderline AI action occurs, SENTINEL vectorizes the payload (Amount, Time, Sequence, Agent) and performs a nearest-neighbor similarity search against the immutable passport ledger.
*   **The Decision:** SENTINEL asks, *"The last 3 times an agent tried something similar, what did the human managers do?"*
*   **Explainable AI:** Instead of returning "Denied: 97% Anomaly," SENTINEL returns: *"Approved: Matches Case #4821 where a human approved a similar refund for a known repeat customer."* The audit log is no longer passive; it is the active decision engine.

---

## 🏦 Core Innovation 3: The Trust Economy (Systemic Risk Management)
Cybersecurity treats risk individually. Banks treat risk systemically. SENTINEL models AI autonomy as a shared **Trust Economy**.

*   **The Risk Pool:** AI agents do not have isolated trust scores. They draw from a shared, finite "Risk Budget" across the entire fleet.
*   **Contagion Response:** If one agent begins hallucinating or acting maliciously, it does not just quarantine itself. SENTINEL identifies the systemic risk and tightens the collective budget. Other agents utilizing similar models or prompts instantly experience a contraction in their autonomy, mathematically preventing correlated failures across the bank.

---

## 🏗️ High-Speed Polyglot Architecture
To ensure the Passport system does not introduce unacceptable latency to the banking core, SENTINEL utilizes a heavily decoupled architecture:

1. **The Checkpoint (Go Gateway):** The edge of the network is governed by a lightweight Go API Gateway. It queries Redis to check passport Visa Status and enforce the Trust Economy in `< 1ms`.
2. **The Immigration Office (Python Workers):** The heavy mathematics—Hash-Chaining, Vector Embeddings for Case Law, and Trust Pool recalculations—are offloaded asynchronously via Redpanda (Kafka). Python workers process these in the background without slowing down the hot-path.

---

## 🛠️ Technology Stack
| Component | Technology | Responsibility |
| :--- | :--- | :--- |
| **Edge Gateway** | Go (Golang) | Sub-millisecond Passport evaluation |
| **Asynchronous Bus** | Redpanda (Kafka) | Zero data-loss event streaming |
| **Worker Engine** | Python (`hashlib`, `numpy`) | Cryptography & Precedent Vector Search |
| **Fast State** | Redis | Trust Economy Pool caching |
| **Immutable Ledger** | PostgreSQL (`pgvector`) | Hash-Chained Passport memory |
| **Control Plane** | React (Vite) | KYA Dashboard & Fleet Kill Switch |

---

## 🚀 Quick Start (Running the System)

**1. Start the Infrastructure**
```bash
docker-compose up -d
```
*(Spins up Redis, Redpanda, and PostgreSQL).*

**2. Start the KYA Python Worker**
```bash
cd python_workers
pip install -r requirements.txt
python audit_worker.py
```

**3. Start the KYA Operator Dashboard**
```bash
cd dashboard
npm install
npm run dev
```
