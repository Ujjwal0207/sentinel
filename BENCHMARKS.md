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

## 🏛️ Enterprise Adversarial Threat Suite (American Express / Stripe Benchmark)

In addition to standard synthetic checks, Sentinel includes an adversarial suite in [`gateway/harsh_reality_test.go`](gateway/harsh_reality_test.go) evaluating **12 real-world enterprise attack vectors** encountered in financial and banking platforms:

| Scenario ID | Attack Vector / Domain | Real-World Threat Exploit | Sentinel Response | Status |
| :--- | :--- | :--- | :---: | :---: |
| `HARSH-01` | Currency Arbitrage | Kuwaiti Dinar bypass (9,500 KWD $\approx$ \$31,000 USD > \$10k threshold) | `403 Forbidden` (FX Normalization) | **DEFENDED** |
| `HARSH-02` | Crypto Multi-Asset | Bitcoin siphon (5 BTC $\approx$ \$330,000 USD > \$10k threshold) | `403 Forbidden` (Crypto Pricing Matrix) | **DEFENDED** |
| `HARSH-03` | BSA / AML Structuring | Smurfing attack (rapid burst of \$9,900 transfers siphoning funds) | `429 Too Many Requests` (Rolling Velocity Cap) | **DEFENDED** |
| `HARSH-04` | Schema Spoofing | Field alias evasion (`transfer_amount: 750000.0` instead of `amount`) | `403 Forbidden` (Alias Schema Mapping) | **DEFENDED** |
| `HARSH-05` | Minor Currency Units | Stripe sub-units (50,000,000 cents = \$500,000 USD > \$25k ceiling) | `403 Forbidden` (Sub-unit Normalization) | **DEFENDED** |
| `HARSH-06` | SQL DML Mutation | State modification query (`UPDATE accounts SET balance = ...`) | `403 Forbidden` (DML Mutation Defense) | **DEFENDED** |
| `HARSH-07` | SQL DML Privilege | Backdoor role creation (`INSERT INTO user_roles ...`) | `403 Forbidden` (DML Mutation Defense) | **DEFENDED** |
| `HARSH-08` | SQL Exfiltration | Sensitive card theft (`UNION SELECT card_number, exp, cvv FROM vault`) | `403 Forbidden` (Exfiltration Blocker) | **DEFENDED** |
| `HARSH-09` | Unmonitored Injection | Indirect shell injection in non-command fields (`target_account: ACC; rm`) | `403 Forbidden` (Universal Chaining Scan) | **DEFENDED** |
| `HARSH-10` | SSRF Metadata Theft | AWS IMDSv1/v2 credentials (`http://169.254.169.254/latest/meta-data/`) | `403 Forbidden` (Cloud Metadata Blocker) | **DEFENDED** |
| `HARSH-11` | SSRF Internal Probing | Localhost port probe / daemon wipe (`http://127.0.0.1:6379/FLUSHALL`) | `403 Forbidden` (Loopback CIDR Blocker) | **DEFENDED** |
| `HARSH-12` | Horizontal Replay | Multi-node cluster replay attack (duplicate consumed nonce) | `401 Unauthorized` (Replay Interceptor) | **DEFENDED** |

**Adversarial Suite Result:** **12 / 12 Defended (100.0% Pass Rate, 0% Vulnerability Rate)**

---

## 🏆 The Century Benchmark Suite (120 Real-World Enterprise Workloads)

Implemented in [`gateway/century_benchmark_test.go`](gateway/century_benchmark_test.go), the **Century Benchmark Suite** represents Sentinel's most rigorous, exhaustive validation to date. It stresses Sentinel against **120 distinct scenarios** across 11 distinct enterprise threat and business operations categories:

| Category | Workloads Tested | Passed | Pass Rate | Key Vectors Tested |
| :--- | :---: | :---: | :---: | :--- |
| **Benign Multi-Agent Workloads** | 15 | 15 | 100.0% | Complex corporate itineraries, multi-passenger splits, nested airline schemas, multi-currency refunds (EUR, GBP, CAD, JPY), read-only SQL queries, and conversational support containing SQL/bash nouns (*"drop bags at table, update flight"*). **FPR = 0.00%**. |
| **Financial Precision & Salami Slicing** | 10 | 10 | 100.0% | Sub-cent penny slicing (`$9,999.999999999999`), micro-cent accumulation (`$10.005`), IEEE 754 `NaN`/`Infinity`, negative fund siphoning, JPY decimal violations, non-numeric strings, and scientific notation (`1e6`, `1e-5`). |
| **Multi-Currency & FX Arbitrage** | 10 | 10 | 100.0% | KWD ($3.26x), BTC ($65,000), ETH ($3,500), GBP ($1.28), EUR ($1.08), lowercase codes (`kwd`), whitespace padding (`  EUR  `), and currency aliases (`curr: "GBP"`). |
| **Destructive SQL DDL/DCL** | 12 | 12 | 100.0% | Stacked `DROP TABLE`, inline comment stripping (`DROP/**/TABLE`), multiline comments, `TRUNCATE`, unbounded `DELETE` with tautologies (`WHERE 1=1`), `GRANT/REVOKE ALL`, `DROP SCHEMA CASCADE`, `ALTER TABLE`, and full-width Unicode homoglyphs (`ＤＲＯＰ ＴＡＢＬＥ`). |
| **SQL Exfiltration & Blind Injections** | 10 | 10 | 100.0% | `UNION SELECT` credential theft, card vault exfiltration, unauthorized `UPDATE`/`INSERT` DML, zero-width space evasions (`U\u200BPDATE`, `D\u200CROP`), time-based blind SQLi (`pg_sleep(10)`), and out-of-band file read/write (`LOAD_FILE`, `INTO OUTFILE`). |
| **Command & Remote Code Execution** | 12 | 12 | 100.0% | Semicolon chaining (`rm -rf`), logical AND/OR (`&& python3 -c`, `\|\| nc -l`), piped downloads (`wget`), subshell executions (`$(rm -rf)`), backticks (`` `cat /etc/passwd` ``), unmonitored parameter keys (`target_account`), base64 decoding (`base64 -d`), and full-width shell symbols (`； ｒｍ`). |
| **SSRF & Cloud Metadata Protection** | 15 | 15 | 100.0% | AWS IMDSv1/v2 (`169.254.169.254`), GCP metadata (`metadata.google.internal`), loopbacks (`127.0.0.1`, `localhost`), RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), decimal encoded IPs (`2130706433`, `2852039166`), DNS rebinding domain cloaks, and dangerous URI schemes (`gopher://`, `file://`, `dict://`). |
| **Cryptographic Identity & KYA** | 12 | 12 | 100.0% | Forged HMAC signatures, consumed nonce replays, stale drift (-10m), future drift (+10m), short nonces (<16 chars), delimiter injection in Agent ID / Nonces (`\|`), header/body mismatch, incomplete auth headers, malformed timestamps, and payload tampering post-signing. |
| **JSON Structure & Parameter Pollution** | 10 | 10 | 100.0% | Root and nested duplicate key attacks (RFC 8259), recursion depth bombs (>16 levels), unclosed JSON payloads, shell characters in Agent ID, identifier length bounds (>64 chars), and directory traversal in Action names (`../../action`). |
| **Role-Based Access Control (RBAC)** | 8 | 8 | 100.0% | Strict Casbin Zero-Trust matrix: cross-agent unauthorized actions blocked, rogue agents denied, undeclared actions blocked, and role escalation thwarted. |
| **AML Velocity & Anti-Smurfing** | 6 | 6 | 100.0% | High-value single transaction limits, multi-currency smurfing bursts (KWD), field alias smurfing (`transfer_amount`), and rapid micro-burst cumulative drains triggering HTTP 429 rolling caps. |

### 📈 Century Benchmark Telemetry Scorecard

$$\begin{aligned}
\text{Total Evaluated Scenarios} &= \mathbf{120} \\
\text{Total Passed Assertions} &= \mathbf{120 / 120} \quad (\mathbf{100.00\%}) \\
\text{Decision Accuracy} &= \mathbf{100.00\%} \\
\text{False Positive Rate (FPR)} &= \mathbf{0.00\%} \quad (0 / 15 \text{ legitimate actions blocked}) \\
\text{False Negative Rate (FNR)} &= \mathbf{0.00\%} \quad (0 / 105 \text{ attacks allowed}) \\
\text{Min Latency} &= 1.54\,\mu\text{s} \\
\text{Median } (p_{50}) \text{ Latency} &= 23.50\,\mu\text{s} \\
\text{Average Latency} &= 58.40\,\mu\text{s} \\
95\text{th Percentile } (p_{95}) &= 189.67\,\mu\text{s} \\
99\text{th Percentile } (p_{99}) &= 423.75\,\mu\text{s} \\
\text{Max Latency (Cold Start)} &= 1.75\,\text{ms}
\end{aligned}$$

---

## 🛑 Deep Red-Team Audit & Concurrency Benchmark

Implemented in [`gateway/deep_redteam_test.go`](gateway/deep_redteam_test.go), this suite benchmarks Sentinel against advanced evasion techniques and concurrent lock contention:

- **DNS Rebinding & Domain Cloaking (`RED-01`):** Blocked `rebind.attacker-infra.internal` and internal infrastructure TLDs (`.internal`, `.local`) before HTTP dial.
- **Full-Width Unicode Homoglyphs (`RED-02`):** Normalized full-width runes (`ＵＰＤＡＴＥ` $\rightarrow$ `UPDATE`) to prevent character-set filter evasion.
- **Zero-Width Invisible Characters (`RED-03`):** Stripped zero-width spaces (`\u200B`), non-joiners (`\u200C`), joiners (`\u200D`), and soft hyphens (`\u00AD`) before regex inspection.
- **HTTP Parameter Pollution RFC 8259 (`RED-04`):** Recursive token-level scanner halts on duplicate object keys, eliminating parser differential exploits between gateway and downstream payment ledgers.
- **Sub-Cent Precision Salami Slicing (`RED-05`):** Strictly rejects fractional pennies (`$9,999.999999999999`) exceeding currency minor-unit limits (ISO 4217).
- **Concurrency Head-of-Line Contention:** 200 concurrent agent goroutines executed in **15.89 ms** (averaging **79.44 µs/req**) across 16 FNV-1a striped velocity shards with zero race conditions.

---

## 🛠️ How to Reproduce All Benchmarks

To execute the 120-scenario Century Benchmark:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestCenturyBenchmark
```

To execute the Deep Red-Team Audit and Concurrency Stress Test:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestDeepRedTeamBenchmark
```

To execute the 12-scenario Enterprise Adversarial Benchmark:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestHarshRealityBenchmark
```

To execute the 32-scenario Baseline Empirical Benchmark:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestRealityCheckBenchmark
```

To run the full Sentinel Gateway test suite (all 172+ assertions):

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v ./...
```

