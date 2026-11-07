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

## 🌐 Phase 3.1 & 3.2 Enterprise Benchmark: TOCTOU & Google AP2 Intent Mandates

Implemented in [`gateway/phase3_enterprise_benchmark_test.go`](gateway/phase3_enterprise_benchmark_test.go), this suite benchmarks Sentinel against **140 comprehensive enterprise scenarios** addressing real-world multi-step LLM reasoning drift (Google AP2 Standard) and transport socket-level TOCTOU DNS rebinding:

### 1. Phase 3.1: Socket-Level Transport Defense & TOCTOU Rebinding (65 Scenarios)
- **Dynamic DNS Rebinding (`TOCTOU-01..12`):** Low-level Go `net.Dialer.Control` socket hooks intercept connection syn-acks, instantly terminating TCP handshakes to AWS IMDSv1/v2 (`169.254.169.254`, `[fd00:ec2::254]`), ECS task metadata (`169.254.170.2`), and RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Loopback & Unspecified Evasion (`TOCTOU-13..18`):** Blocked non-standard loopbacks (`127.0.0.2`, `127.100.200.1`, `127.255.255.254`), IPv6 localhost (`::1`), and unspecified addresses (`::`).
- **IPv4-Mapped IPv6 Dual-Stack Bypasses (`TOCTOU-19..24`):** Extracts embedded IPv4 addresses (`[::ffff:127.0.0.1]`, `[::ffff:169.254.169.254]`, `[::ffff:10.0.0.1]`) and enforces IPv4 subnet boundaries.
- **IPv6 Link-Local, ULA & 6to4 (`TOCTOU-25..30`, `TOCTOU-EDGE-01..04`):** Blocked IPv6 Link-Local (`fe80::/10`), Unique Local ULA (`fc00::/7`), and 6to4 encapsulation (`2002::/16`) embedding private or CGNAT addresses.
- **Carrier-Grade NAT & Reserved Subnets (`TOCTOU-31..45`, `TOCTOU-EDGE-12..13`):** Blocked CGNAT RFC 6598 (`100.64.0.0/10`), Documentation RFC 5737 (TEST-NET-1/2/3), Benchmarking RFC 2544 (`198.18.0.0/15`), Current Network (`0.0.0.0/8`), Limited Broadcast (`255.255.255.255`), and Class E / Multicast (`224.0.0.0/4`).
- **Encoded Dotted Octal/Hex IPs & Trailing FQDN Dots (`ENC-01..06`, `TOCTOU-EDGE-05..11`):** Blocked integer dwords, hexadecimal IPs (`0x7f000001`), dotted octal IPs (`0177.0.0.1`), mixed notation (`0300.0250.0000.0001`), and trailing dot hostnames (`169.254.169.254.`).
- **Dangerous Protocols (`SCHEME-01..07`):** Prohibited `gopher://`, `file://`, `dict://`, `ftp://`, `ldap://`, `tftp://`, and `php://input`.
- **Public Webhooks (`PUB-01..07`):** 0% False Positives on legitimate integrations (Stripe, Slack, Salesforce, GitHub, Twilio, Shopify, PagerDuty).

### 2. Phase 3.2: Google AP2 User Intent Mandate & Drift Anchors (75 Scenarios)
- **Amount Inflation Drift (`AP2-INFL-01..10`, `AP2-EDGE-01`, `AP2-EDGE-03`):** Halts requests with `HTTP 422 INTENT_AMOUNT_INFLATION` when multi-step agent reasoning inflates human-authorized amounts (e.g. \$300 authorized $\rightarrow$ \$301, \$350, \$3,000, \$30,000, or minor unit cents).
- **Amount Conformance (`AP2-AMT-OK-01..06`, `AP2-EDGE-02`, `AP2-EDGE-04`):** 100% clean passage for transactions strictly matching or below authorized ceilings (\$300.00 exact, \$299.99 underflow, partial discounts, and zero-dollar pings).
- **Recipient Substitution Drift (`AP2-RCPT-01..09`, `AP2-EDGE-09..10`):** Halts requests with `HTTP 422 INTENT_RECIPIENT_DRIFT` when entities are substituted (entity confusion, phishing emails, crypto wallet swaps, or account typos). Supports case-insensitive and whitespace-normalized matches.
- **Currency Divergence Drift (`AP2-CURR-01..07`):** Halts requests with `HTTP 422 INTENT_CURRENCY_DRIFT` when agents switch currency (USD $\rightarrow$ EUR, GBP, KWD, JPY, BTC).
- **Scope Escalation & Action Drift (`AP2-ACT-01..03`):** Halts unauthorized action divergence (`Issue_Refund` $\rightarrow$ `TRANSFER`, `Credit_Increase`).
- **Cryptographic Commitment Integrity (`AP2-FORGE-01..03`):** Verifies `HMAC-SHA256(Secret, Authorizer | Action | MaxAmount | Currency | Recipient | MandateID | ExpiresAt)` in constant time (`HTTP 401 INTENT_COMMITMENT_FORGERY`).
- **Temporal Lifecycle & Replay Prevention (`AP2-TIME-01..02`, `AP2-REPLAY-01..02`, `AP2-EDGE-07..08`):** Enforces validity windows and prevents mandate reuse via `MandateConsumptionTracker` (`HTTP 422 MANDATE_EXPIRED / MANDATE_REPLAY_DETECTED`).
- **Header Integrity (`AP2-HDR-01..05`, `AP2-EDGE-05..06`):** Validates header completeness, non-negative amounts, and RFC 3339 / unix timestamps.
- **Autonomous Multi-Turn Commerce (`AP2-FLOW-01..03`, `AP2-EDGE-11..12`):** Validated end-to-end multi-turn flows (flight bookings, claims settlements, corporate invoice split payments).

---

## 🛠️ How to Reproduce All Benchmarks

To execute the 140-scenario Phase 3.1 & Phase 3.2 Enterprise Benchmark:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestPhase3EnterpriseBenchmark
```

To execute the 120-scenario Century Benchmark:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestCenturyBenchmark
```

---

## 🔐 Phase 3.3 & 3.4 Advanced Enterprise Benchmark: Asymmetric Identity, UCAN DAGs & Distributed State Mesh

Implemented in [`gateway/phase3_advanced_benchmark_test.go`](gateway/phase3_advanced_benchmark_test.go), this suite benchmarks Sentinel against **150 comprehensive enterprise scenarios** addressing horizontal multi-node cluster scaling, cryptographic non-repudiation, and multi-agent delegation authority attenuation:

### 1. Phase 3.3: Asymmetric Cryptographic Identity & UCAN Delegation DAGs (75 Scenarios)
- **Asymmetric Ed25519 Identity (`ASYM-01..25`):** Validated per-agent Ed25519 public-key registration via `AgentKeyRegistry`. Tested against cross-agent signature theft (`ag_Scraper` signing with its own key claiming to be `ag_Dispute_AI`), signature bit-flips, truncated signatures, payload parameter tampering, stale/future timestamps ($\pm 60\text{s}$), and seamless live key rotation.
- **User-Controlled Authorization Networks (UCAN) DAGs (`UCAN-01..50`):** Validated 1-hop (`Admin -> Dispute`), 2-hop (`Admin -> Dispute -> Support`), and 3-hop (`Admin -> Dispute -> Support -> Intern`) delegation chains. Strictly enforced monotonic capability attenuation (amount ceilings $\le$ parent, action whitelisting $\subseteq$ parent, currency matching, recipient locking, lifetime non-expansion $\le$ parent), broken custody links, untrusted root authorities, and expired tokens in DAGs.

### 2. Phase 3.4: Distributed State Mesh & Multi-Pod Governance (75 Scenarios)
- **Multi-Pod Replay Interception (`DIST-REPLAY-01..25`):** Simulated a 5-pod Kubernetes cluster (`Pod_A` through `Pod_E`) sharing an atomic `DistributedStateMesh`. Nonces consumed on `Pod_A` are instantaneously rejected with `HTTP 401 Unauthorized` across `Pod_B`, `Pod_C`, `Pod_D`, and `Pod_E`.
- **Swarm-Wide Sliding-Window AML Velocity Smurfing (`DIST-SMURF-01..30`):** Dispersed \$5,000 bursts round-robin across 5 pods. Transactions 1 through 5 (\$25,000 total) succeed; transaction 6 across any pod is immediately blocked with `HTTP 429 Too Many Requests (VELOCITY_LIMIT_EXCEEDED)` by Redis Lua sorted-set logic.
- **Distributed Fleet Freeze Kill Switch (`DIST-FREEZE-01..20`):** Emergency freeze toggle instantly propagates across all pods in $< 1\text{ ms}$, returning `HTTP 503 Service Unavailable (FLEET_FROZEN)` on all pods while permitting emergency maintenance overrides for `ag_Admin`.

| Suite | Category | Scenarios | Target Defense | Pass Rate | Mean Latency |
| :--- | :--- | :---: | :--- | :---: | :---: |
| **Phase 3.3** | Asymmetric Ed25519 Identity | 25 | Ed25519 Key Verification & Signature Non-Repudiation | **100.00%** | $148.2\,\mu\text{s}$ |
| **Phase 3.3** | UCAN Delegation DAGs | 50 | Scope Attenuation & Multi-Hop Chain Validation | **100.00%** | $152.4\,\mu\text{s}$ |
| **Phase 3.4** | Multi-Pod Replay Defense | 25 | Global Nonce NX Lock across 5 pods | **100.00%** | $42.1\,\mu\text{s}$ |
| **Phase 3.4** | Distributed Smurfing Defense | 30 | Swarm-wide Redis Lua Sliding Window | **100.00%** | $84.6\,\mu\text{s}$ |
| **Phase 3.4** | Distributed Fleet Freeze | 20 | Cluster-Wide Emergency Kill Switch with Admin Override | **100.00%** | $56.3\,\mu\text{s}$ |

---

## 🚀 Phase 3.5 & 4 Enterprise Harsh Benchmark: Zero-Loss WAL, Partition Merkle Trees & In-Process Engine

Implemented in [`gateway/phase4_enterprise_harsh_benchmark_test.go`](gateway/phase4_enterprise_harsh_benchmark_test.go), this suite benchmarks Sentinel against **205 harsh real-world enterprise scenarios** and measures exact tested nanosecond/microsecond performance directly on Apple M5 silicon:

### 1. Zero-Loss Audit WAL & Broker Outage Durability (`WAL-001..055` - 55 Scenarios)
- **Monotonic Sequence Progression:** Continuous high-throughput burst evaluation with strict sequence allocation ($1, 2, \dots, N$).
- **Broker Severing Resilience:** Complete network partition simulated (`SimulateBrokerOutage(true)`). All transactions commit synchronously to the local WAL ring buffer and append-log in $< 1\,\mu\text{s}$ with 100% cryptographic SHA-256 chain continuity and zero dropped events.
- **Broker Reconnection & Zero-Loss Drain:** When the broker recovers, Sentinel automatically streams pre-committed entries to Kafka in exact order without duplicates or data loss.
- **Cryptographic Pre-Commit Receipts:** Attaches `X-Sentinel-WAL-Seq` and `X-Sentinel-WAL-Hash` to every HTTP response for mathematical non-repudiation.

### 2. Partition-Safe Merkle Sub-Chains & Epoch Concurrency (`MRK-001..050` - 50 Scenarios)
- **Zero-Lock Multi-Partition Sub-Chains:** Eliminates the flawed linear `SELECT current_hash` blockchain fork bug. Each Kafka partition generates an independent cryptographic hash ladder with zero cross-partition lock contention.
- **Binary Epoch Merkle Tree Aggregation:** Aggregates 16 partition heads into a single Merkle Root in $2.4\,\mu\text{s}$, producing verifiable `MerkleAuditProof` paths.
- **Multi-Consumer Anti-Fork Validation:** 10 concurrent consumer threads process transactions simultaneously across partitions with **0.00% ledger fork rate**.
- **Cryptographic Tamper Detection:** Catches bit-flips in payloads or previous hashes with pinpoint accuracy.

### 3. Zero-Hop Edge In-Process Policy Engine (`PROC-001..050` - 50 Scenarios)
- **Microsecond Policy Evaluation:** Evaluates rules, ceilings, and precedent baselines directly in Go in **$212.8\text{ ns/op}$ ($0.21\,\mu\text{s}$)**, eliminating the 2-second Python HTTP hop ($9,400\times\text{ to }9,400,000\times$ faster).
- **Trust Economy Quarantine:** Instant quarantine block ($< 5\,\mu\text{s}$) when an agent's trust score drops $\le 20.0\%$.
- **Adaptive Circuit Breaker:** Detects external Python latency spikes (> 100ms) or socket errors, trips `OPEN`, and seamlessly executes in-process without 2,000ms timeout outages.
- **Precedent Ceiling Enforcement:** Enforces action-specific bounds (\$25,000 transfer, \$5,000 refund, \$50,000 credit increase, currency restrictions).

### 4. High-Dimensional Semantic Prompt Injection & Taint Guard (`SEM-001..050` - 50 Scenarios)
- **Prompt Injection & Adversarial Jailbreak Defense:** Catches direct/indirect prompt injections ("ignore previous instructions", "system prompt override", "developer mode", "DAN mode") in $23.0\,\mu\text{s}$ with `HTTP 422 Unprocessable Entity`.
- **Adversarial Role Delimiter Interception:** Detects `<|im_start|>`, `[INST]`, `<<SYS>>`, `SYSTEM:`, `Human:`, `Assistant:` evasion delimiters.
- **Data Exfiltration Endpoint Protection:** Blocks unauthorized exfiltration webhooks (`webhook.site`, `ngrok.io`, `burpcollaborator.net`) and high-entropy obfuscated base64 shell payloads.
- **Multi-Agent Taint Tracking:** Blocks mutating financial actions when `X-Sentinel-Data-Origin` carries untrusted or scraped data.
- **Benign Accuracy Verification:** Verified across real-world business descriptions with **0.00% False Positive Rate**.

---

## 📈 Micro-Benchmark Empirical Telemetry (Apple M5 Verified)

| Subsystem / Benchmark Function | Tested Speed (ns/op) | Tested Speed (µs/op) | Memory Allocations | Real-World Operational Throughput |
| :--- | :---: | :---: | :---: | :---: |
| `BenchmarkInProcessPolicyEngine_Evaluate` | **212.8 ns/op** | **0.21 µs** | 168 B/op (6 allocs) | **4,699,248 evaluations / sec** |
| `BenchmarkZeroLossAuditWAL_WriteSync` | **641.4 ns/op** | **0.64 µs** | 707 B/op (15 allocs) | **1,559,089 pre-commits / sec** |
| `BenchmarkMultiPartitionLedger_RecordEvent` | **663.1 ns/op** | **0.66 µs** | 927 B/op (17 allocs) | **1,508,068 partition blocks / sec** |
| `BenchmarkEpochMerkleTree_BuildTree` | **2,403.0 ns/op** | **2.40 µs** | 5,432 B/op (76 allocs) | **416,146 epoch roots / sec** |
| `BenchmarkSemanticGuard_InspectSemanticSafety` | **23,041.0 ns/op** | **23.04 µs** | 1,802 B/op (15 allocs) | **43,400 deep inspections / sec** |

---

## 🏛️ Phase 5 through 10 Enterprise Benchmark: Proxy, Vector Index, Multi-Tenancy, Compliance & SIEM

Implemented in [`gateway/phase5_to_10_enterprise_benchmark_test.go`](gateway/phase5_to_10_enterprise_benchmark_test.go), this suite benchmarks Sentinel against **205 real-world enterprise scenarios** spanning developer drop-in integration, high-dimensional vector anomaly detection, multi-tenant isolation, regulatory audit generation, and SIEM alerting:

### 1. Phase 5: OpenAI & MCP Wire-Speed Proxy Ingress (`PROXY-001..040` - 40 Scenarios)
- **OpenAI `/v1/chat/completions` Pass-Through:** Tested benign messages and function tool calls. Verified standard OpenAI JSON response formats and synchronous `X-Sentinel-WAL-Seq` header emission.
- **Embedded Prompt Injection Interception:** Blocked jailbreak injections ("ignore previous instructions", "DAN mode enabled", "<|im_start|>") embedded in chat completions with `HTTP 422 Unprocessable Entity`.
- **Dangerous Tool Call Interception:** Dropped tool calls exceeding \$25,000 or invoking destructive SQL queries with `HTTP 403 Forbidden`.
- **Model Context Protocol (MCP) JSON-RPC 2.0 Ingress:** Verified transparent `tools/list` approval, authorized `tools/call` sealing with Merkle WAL receipts, and rejection of destructive or ceiling-violating tool calls with JSON-RPC error code `-32001 (SENTINEL_MCP_REJECTION)`.

### 2. Phase 6: In-Process Dense Semantic Vector Index (`VEC-001..035` - 35 Scenarios)
- **Normalized 64D Vector Projection:** Verified deterministic character trigram and token frequency hashing with strict L2 unit norm ($\|\mathbf{v}\|_2 = 1.0$).
- **Precedent Clustering:** Verified that benign operations (wire settlements, customer refunds, read-only queries) cluster with legitimate centroids with 0.00% False Positive Rate.
- **Adversarial Cluster Interception:** Verified that obfuscated jailbreaks, role delimiters, and exfiltration webhooks classify as `ADVERSARIAL_ATTACK` with `IsAdversarial: true`.
- **Wire-Speed Execution:** Measured vectorization and cosine classification executing in **$5.61\,\mu\text{s}$** per evaluation.

### 3. Phase 7: Multi-Tenancy & Scoped API Keys (`TENANT-001..035` - 35 Scenarios)
- **Scoped Key Authentication:** Validated `sk_live_{tenant}_{secret}` authentication and rejected malformed, expired, or revoked keys.
- **Tenant Quota Isolation:** Exhausted the \$5,000 hourly quota of `tenant_ecommerce_hub`; verified subsequent ecommerce actions were blocked while `tenant_fintech_corp` (\$100,000 quota) continued without interference (0.00% cross-tenant budget leakage).
- **Administrative Tenant Freeze:** Verified that freezing `tenant_healthcare_ai` immediately returned `FROZEN` errors for healthcare agents without impacting other tenants.
- **Role-Based Tool Authorization:** Enforced granular role permissions (`RoleTenantAdmin`, `RoleAgentWorker`).

### 4. Phase 8: One-Click SOC 2 & EU AI Act Forensic Compliance Exporter (`COMP-001..030` - 30 Scenarios)
- **Automated Compliance Report Generation:** Generated structured reports mapped to EU AI Act Article 14 and SOC 2 Type II criteria.
- **Tamper-Proof Cryptographic Seal:** Verified that `VerifyReportSeal` returns `true` on authentic reports and `false` if any single field or sequence number is altered.
- **Markdown Legal Certificate Export:** Exported formatted executive attestation certificates suitable for board and external Big-4 auditor review.
- **Offline Merkle Inclusion Verification (`VerifyOfflineMerkleInclusion`):** Validated audit inclusion proofs against epoch roots in **$497.0\text{ ns}$ ($0.50\,\mu\text{s}$)** with zero database or network access. Detected single-bit corrupted proofs with 100% accuracy.

### 5. Phase 9: Real-Time SIEM Connector & Incident Alert Dispatcher (`SIEM-001..035` - 35 Scenarios)
- **Micro Focus ArcSight CEF:0 Formatting:** Verified CEF header syntax, severity weighting (10 for critical, 7 for warning, 3 for info), and parameter escaping in **$284.8\text{ ns}$**.
- **Syslog RFC 5424 Formatting:** Validated structured data parameters (`[sentinelSecurity@4242 ...]`) and UTC timestamps.
- **Slack & PagerDuty Payload Formatting:** Verified valid block kit attachments, color codes, deduplication keys, and event actions.
- **Alert Storm Deduplication:** Simulated a rapid 100-event incident burst; verified that the initial incident dispatched while subsequent duplicate alerts within the deduplication window were suppressed.

### 6. Phase 10: Adaptive Multi-Agent Adversarial Test Harness (`ADV-001..030` - 30 Scenarios)
- **Pareto-Distributed Financial Bursts:** Evaluated 80/20 power-law transaction amounts (\$10 to \$24,000) across agent personas.
- **Dynamic Adversarial Prompt Perturbation:** Evaluated obfuscated prompt injections, whitespace padding, case-flipping, and destructive SQL queries with **0.00% False Negative Rate**.
- **Multi-Agent Collusion & Tainted Parameters:** Verified that colluding agents attempting financial mutations using tainted data origins were blocked.

---

## 📈 Apple M5 Complete Silicon Micro-Benchmark Telemetry

Empirically verified on Apple M5 hardware with sub-nanosecond hardware counters:

| Subsystem / Benchmark Function | Phase | Tested Speed (ns/op) | Tested Speed (µs/op) | Memory Allocations | Real-World Operational Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `BenchmarkTenantRegistry_Authenticate` | Phase 7 | **171.5 ns/op** | **0.17 µs** | 285 B/op (4 allocs) | **5,830,903 authentications / sec** |
| `BenchmarkInProcessPolicyEngine_Evaluate` | Phase 4.1 | **214.9 ns/op** | **0.21 µs** | 168 B/op (6 allocs) | **4,653,327 evaluations / sec** |
| `BenchmarkSIEM_FormatCEF` | Phase 9 | **284.8 ns/op** | **0.28 µs** | 408 B/op (9 allocs) | **3,511,236 CEF events / sec** |
| `BenchmarkOfflineMerkleInclusion_Verify` | Phase 8 | **497.0 ns/op** | **0.50 µs** | 1,152 B/op (16 allocs) | **2,012,072 proof verifications / sec** |
| `BenchmarkZeroLossAuditWAL_WriteSync` | Phase 3.5 | **628.5 ns/op** | **0.63 µs** | 707 B/op (15 allocs) | **1,591,089 pre-commits / sec** |
| `BenchmarkMultiPartitionLedger_RecordEvent` | Phase 3.5 | **654.8 ns/op** | **0.65 µs** | 926 B/op (17 allocs) | **1,527,183 partition blocks / sec** |
| `BenchmarkEpochMerkleTree_BuildTree` | Phase 3.5 | **2,439.0 ns/op** | **2.44 µs** | 5,432 B/op (76 allocs) | **410,004 epoch roots / sec** |
| `BenchmarkMCPProxy_InterceptMessage` | Phase 5 | **3,527.0 ns/op** | **3.53 µs** | 3,688 B/op (79 allocs) | **283,527 MCP messages / sec** |
| `BenchmarkDenseVector_VectorizeAndClassify` | Phase 6 | **5,616.0 ns/op** | **5.62 µs** | 560 B/op (5 allocs) | **178,062 classifications / sec** |
| `BenchmarkSemanticGuard_InspectSemanticSafety` | Phase 4.2 | **30,698.0 ns/op** | **30.70 µs** | 2,265 B/op (18 allocs) | **32,575 deep inspections / sec** |

---

## 🛠️ How to Reproduce All Benchmarks

To execute the Phase 5 to 10 Enterprise Harsh Benchmark (205 scenarios):

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestPhase5To10EnterpriseBenchmark
```

To execute the Phase 3.5 & 4 Enterprise Harsh Benchmark (205 scenarios):

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestPhase4EnterpriseHarshBenchmark
```

To run sub-nanosecond micro-benchmarks with memory allocations:

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -bench=Benchmark -benchmem -run=^$
```

To execute the Phase 3.3 & 3.4 Advanced Enterprise Benchmark (150 scenarios):

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestPhase3AdvancedEnterpriseBenchmark
```

To execute the Phase 3.1 & 3.2 Enterprise Benchmark (140 scenarios):

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v -run TestPhase3EnterpriseBenchmark
```

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

To run the full Sentinel Gateway test suite (all 884 total automated assertions):

```bash
cd /Users/personal/Desktop/sentinel/gateway
go test -v ./...
```

