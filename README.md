# 🛡️ SENTINEL 
**S**ecure **E**nforcement & **N**etworked **T**rust **I**nfrastructure for **N**eutralized **E**xposure in **L**ive **T**ransactions

[![Theme](https://img.shields.io/badge/Theme-Governance_Layer_for_Financial_Agents-blue.svg)](#)
[![Identity](https://img.shields.io/badge/Identity-KYA_(Know_Your_Agent)-purple.svg)](#)
[![Status](https://img.shields.io/badge/Status-Active_Development-orange.svg)](#)

> **"Just like banks have KYC for humans, SENTINEL introduces KYA (Know Your Agent): A cryptographic, continuously evolving Digital Passport for AI agents."**

---

## 📖 Overview
As autonomous AI agents multiply across financial services, deploying them responsibly requires more than static API keys and rigid `ALLOW/DENY` rules. **SENTINEL** is a next-generation AI Identity System designed for enterprise finance.

Instead of a traditional API Gateway, SENTINEL issues every AI agent a **Digital Passport**. This passport maintains a cryptographic memory of the agent's actions and continuously monitors its behaviour. If an agent acts erratically, its autonomy is dynamically suspended—ensuring compromised AI models never cause catastrophic financial damage.

---

## 🛂 The KYA System (Know Your Agent)

### 1. The Digital Passport
When an AI is deployed on the banking network, it is issued a digital passport. It begins with a "Visa Status" of *Full Autonomy* (Trust Score: 100).

### 2. Immutable Cryptographic Stamps
Every financial decision the AI makes is mathematically "stamped" into its passport. SENTINEL utilizes **SHA-256 Hash-Chaining** (Blockchain logic built directly into PostgreSQL) to ensure an agent cannot erase or alter its Governance Memory.

### 3. The Border Patrol (Behavioural Immune System)
SENTINEL continuously reads the passport. If the AI deviates from its normal baseline (e.g., a massive spike in high-value refunds), SENTINEL detects the anomaly and degrades the agent's passport Trust Score. 

### 4. Adaptive Autonomy (Visa Revocation)
We abandoned the binary `ALLOW/DENY` model. If an agent's trust drops below a critical threshold, its Visa is downgraded to *Quarantine*. The agent loses its autonomy and is instantly rerouted to a Human Approval desk.

---

## 🏗️ High-Speed Polyglot Architecture

To ensure passport evaluation does not introduce latency to the banking core, SENTINEL is decoupled:

1. **Go (Golang) Gateway:** Intercepts traffic and checks passport status via Redis in `<1ms`.
2. **Python KYA Workers:** Consumes the event stream via Redpanda (Kafka) to run heavy anomaly mathematics and stamp the cryptographic ledger asynchronously.

---

## 🛠️ Technology Stack
| Category | Tech | Why? |
|----------|------|------|
| **Checkpoint Gateway** | Go (Golang) | Max concurrency, sub-millisecond edge latency |
| **Immigration Worker** | Python | Cryptographic hashing & behavioural modeling |
| **Event Stream** | Redpanda (Kafka) | Zero data-loss asynchronous audit routing |
| **Passport State** | Redis | High-speed Trust Score caching |
| **Ledger Storage** | PostgreSQL | Immutable passport history |
| **Operator Dashboard** | React (Vite) | Real-time KYA monitoring and Kill Switch |

---

## 🚀 Quick Start

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
