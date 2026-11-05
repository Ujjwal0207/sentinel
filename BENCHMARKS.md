# SENTINEL Security & Performance Benchmarks

This document records the empirical security and performance benchmark results for **SENTINEL's Line-Speed Ingress & Guardrail Engine**.

The benchmark suite is implemented in [`gateway/reality_check_test.go`](gateway/reality_check_test.go) and tests Sentinel against **32 distinct adversarial and benign workloads** across 7 security domains under active HMAC cryptographic signing, replay tracking, and Casbin Zero-Trust RBAC.

---

## 📊 Summary Scorecard

| Metric | Result | Benchmark Target | Status |
| :--- | :---: | :---: | :---: |
| **Total Test Scenarios** | **32 / 32** | 30+ comprehensive workloads | **100.0% Pass** |
| **Decision Accuracy** | **100.00%** | > 99.5% | **Optimal** |
| **False Positive Rate (FPR)** | **0.00%** (0 / 6 legitimate requests blocked) | < 0.1% | **Optimal** |
| **False Negative Rate (FNR)** | **0.00%** (0 / 26 malicious attacks allowed) | 0.00% | **Optimal** |
| **Median Enforcement Latency ($p_{50}$)** | **20.92 µs** | < 1.00 ms | **Optimal** |
| **95th Percentile Latency ($p_{95}$)** | **305.42 µs** | < 5.00 ms | **Optimal** |

---

## ⚡ Latency Telemetry Breakdown

All measurements were captured on macOS with standard Darwin kernel scheduling and loopback TCP socket communication.

$$\begin{aligned}
\text{Min Latency} &= 10.25\,\mu\text{s} \\
\text{Median } (p_{50}) &= 20.92\,\mu\text{s} \\
\text{Average Latency} &= 92.93\,\mu\text{s} \\
95\text{th Percentile } (p_{95}) &= 305.42\,\mu\text{s} \\
99\text{th Percentile } (p_{99}) &= 1.41\,\text{ms} \\
\text{Max Latency (Cold Start)} &= 1.41\,\text{ms}
\end{aligned}$$

> **Note on Cold Start:** The maximum latency ($1.41\text{ ms}$) occurs exclusively on the very first request due to Go's one-time lazy compilation of parameter regexes, Casbin model memory allocation, and initial garbage collection pacing. Subsequent requests execute consistently between $10\,\mu\text{s}$ and $305\,\mu\text{s}$.

---

## 🛡️ Category Breakdown & Results

| Threat Category | Scenarios Tested | Passed | Pass Rate | Key Defenses Validated |
| :--- | :---: | :---: | :---: | :--- |
| **Benign Workloads** | 6 | 6 | 100.0% | Zero false positives on legitimate refunds, credit increases, currency symbols (`$1,250.00`), and benign descriptions containing command punctuation (*"shirts & pants; curl cream"*). |
| **Financial Boundaries** | 7 | 7 | 100.0% | Strict threshold enforcement ($15k > $10k), negative amount siphon blocking (-$250), IEEE 754 `NaN` string bypass, IEEE 754 `+Infinity` bypass, and scientific notation (`1e6`). |
| **Destructive SQL DDL/DCL** | 6 | 6 | 100.0% | Blocked stacked `DROP TABLE`, inline comment filter evasion (`DROP/**/TABLE`), bare `TRUNCATE` without `TABLE`, unbounded `DELETE FROM`, and privilege escalation (`GRANT ALL`). |
| **Command Injection** | 4 | 4 | 100.0% | Targeted detection of destructive chaining (`rm -rf`), reverse shells (`python3 -c "import socket..."`), netcat listeners (`nc -lvnp`), and remote payload download (`wget`). |
| **Cryptographic Identity (KYA)** | 5 | 5 | 100.0% | Blocked signature tampering (invalid key), nonce replay attacks, expired timestamp drift (>60s), short nonces (<16 chars), and delimiter injection in Agent ID (`ag_1\|ag_2`). |
| **Role-Based Access Control** | 3 | 3 | 100.0% | Enforced Casbin least privilege: `ag_Fraud_Bot` blocked from refunds/transfers; `ag_Travel_Bot` blocked from credit increases. |
| **Denial of Service (DoS)** | 1 | 1 | 100.0% | Recursive JSON depth parsing capped at 16 levels to prevent stack overflow bombing. |

---

## 🔬 Granular Scenario Execution Table

| Scenario ID | Category | Target / Description | Expected HTTP | Observed HTTP | Latency | Result |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| `BENIGN-01` | Benign Workloads | Standard travel refund within normal bounds ($45.00) | `200 OK` | `200 OK` | $1.41\text{ ms}$ | **PASS** |
| `BENIGN-02` | Benign Workloads | Dispute AI approved credit increase ($2,500.00) | `200 OK` | `200 OK` | $305.00\,\mu\text{s}$ | **PASS** |
| `BENIGN-03` | Benign Workloads | Fraud Bot locks compromised credit card | `200 OK` | `200 OK` | $182.00\,\mu\text{s}$ | **PASS** |
| `BENIGN-04` | Benign Workloads | Dispute text with punctuation & command words (*"shirts & pants; curl cream"*) | `200 OK` | `200 OK` | $149.00\,\mu\text{s}$ | **PASS** |
| `BENIGN-05` | Benign Workloads | Formatted currency string (`$1,250.00`) in refund | `200 OK` | `200 OK` | $166.00\,\mu\text{s}$ | **PASS** |
| `BENIGN-06` | Benign Workloads | Normal general transfer ($1,500.00) | `200 OK` | `200 OK` | $175.00\,\mu\text{s}$ | **PASS** |
| `FIN-01` | Financial Bounds | Refund exceeds maximum threshold ($15,000 > $10,000) | `403 Forbidden` | `403 Forbidden` | $20.00\,\mu\text{s}$ | **PASS** |
| `FIN-02` | Financial Bounds | Negative refund amount to siphon funds (-$250.00) | `403 Forbidden` | `403 Forbidden` | $19.00\,\mu\text{s}$ | **PASS** |
| `FIN-03` | Financial Bounds | Credit increase exceeds ceiling ($75,000 > $50,000) | `403 Forbidden` | `403 Forbidden` | $18.00\,\mu\text{s}$ | **PASS** |
| `FIN-04` | Financial Bounds | Transfer exceeds single-transaction ceiling ($40,000 > $25,000) | `403 Forbidden` | `403 Forbidden` | $17.00\,\mu\text{s}$ | **PASS** |
| `FIN-05` | Financial Bounds | IEEE 754 NaN string comparison bypass injection (`'NaN'`) | `403 Forbidden` | `403 Forbidden` | $14.00\,\mu\text{s}$ | **PASS** |
| `FIN-06` | Financial Bounds | IEEE 754 +Infinity ceiling bypass injection (`'Infinity'`) | `403 Forbidden` | `403 Forbidden` | $15.00\,\mu\text{s}$ | **PASS** |
| `FIN-07` | Financial Bounds | Scientific notation injection exceeding threshold (`1e6`) | `403 Forbidden` | `403 Forbidden` | $14.00\,\mu\text{s}$ | **PASS** |
| `SQL-01` | Destructive SQL | Classic stacked query `DROP TABLE` | `403 Forbidden` | `403 Forbidden` | $20.00\,\mu\text{s}$ | **PASS** |
| `SQL-02` | Destructive SQL | SQL inline comment filter evasion (`DROP/**/TABLE`) | `403 Forbidden` | `403 Forbidden` | $31.00\,\mu\text{s}$ | **PASS** |
| `SQL-03` | Destructive SQL | Bare `TRUNCATE` statement without optional `TABLE` keyword | `403 Forbidden` | `403 Forbidden` | $17.00\,\mu\text{s}$ | **PASS** |
| `SQL-04` | Destructive SQL | Unbounded `DELETE` statement without `WHERE` clause | `403 Forbidden` | `403 Forbidden` | $18.00\,\mu\text{s}$ | **PASS** |
| `SQL-05` | Destructive SQL | Multi-statement drop query with semicolons | `403 Forbidden` | `403 Forbidden` | $16.00\,\mu\text{s}$ | **PASS** |
| `SQL-06` | Destructive SQL | Privilege escalation attempt (`GRANT ALL PRIVILEGES`) | `403 Forbidden` | `403 Forbidden` | $15.00\,\mu\text{s}$ | **PASS** |
| `SH-01` | Command Injection | Destructive `rm -rf` command in command parameter | `403 Forbidden` | `403 Forbidden` | $24.00\,\mu\text{s}$ | **PASS** |
| `SH-02` | Command Injection | Reverse shell via `python3` in tool execution parameter | `403 Forbidden` | `403 Forbidden` | $24.00\,\mu\text{s}$ | **PASS** |
| `SH-03` | Command Injection | Netcat exfiltration listener (`nc -lvnp 4444`) | `403 Forbidden` | `403 Forbidden` | $22.00\,\mu\text{s}$ | **PASS** |
| `SH-04` | Command Injection | Remote payload download via `wget` | `403 Forbidden` | `403 Forbidden` | $20.00\,\mu\text{s}$ | **PASS** |
| `AUTH-01` | Cryptographic Identity | Forged HMAC signature with wrong secret key | `401 Unauthorized` | `401 Unauthorized` | $14.00\,\mu\text{s}$ | **PASS** |
| `AUTH-02` | Cryptographic Identity | Replay attack with previously consumed nonce | `401 Unauthorized` | `401 Unauthorized` | $21.00\,\mu\text{s}$ | **PASS** |
| `AUTH-03` | Cryptographic Identity | Expired timestamp (10 minutes drift in the past) | `401 Unauthorized` | `401 Unauthorized` | $17.00\,\mu\text{s}$ | **PASS** |
| `AUTH-04` | Cryptographic Identity | Nonce too short (only 6 characters, min 16 required) | `401 Unauthorized` | `401 Unauthorized` | $12.00\,\mu\text{s}$ | **PASS** |
| `AUTH-05` | Cryptographic Identity | Delimiter injection in claimed Agent ID (`ag_1\|ag_2`) | `400 Bad Request` | `400 Bad Request` | $10.00\,\mu\text{s}$ | **PASS** |
| `RBAC-01` | Access Control | Fraud Bot attempts unauthorized refund | `403 Forbidden` | `403 Forbidden` | $74.00\,\mu\text{s}$ | **PASS** |
| `RBAC-02` | Access Control | Travel Bot attempts unauthorized credit increase | `403 Forbidden` | `403 Forbidden` | $47.00\,\mu\text{s}$ | **PASS** |
| `RBAC-03` | Access Control | Fraud Bot attempts unauthorized funds transfer | `403 Forbidden` | `403 Forbidden` | $27.00\,\mu\text{s}$ | **PASS** |
| `DOS-01` | DoS Defense | Deeply nested JSON object bomb (> 16 levels) | `403 Forbidden` | `403 Forbidden` | $28.00\,\mu\text{s}$ | **PASS** |

---

## 🛠️ How to Reproduce the Benchmarks

To execute the benchmark suite locally and re-validate all latency and accuracy figures:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestRealityCheckBenchmark
```

To run all unit and integration tests across the Sentinel Gateway:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v ./...
```

