# GhostTrace AI — Northstar Shop Deletion Assurance Agent
**HackerRank Orchestrate — October 2026 Challenge: "Ghost Data Still Exists"**  
**Submission Repository:** [SreeVaibavi/hackerrank-orchestrate-october26](https://github.com/SreeVaibavi/hackerrank-orchestrate-october26)  
**Agent Architecture:** Google Antigravity • Gemini 3.8 Flash (Medium) • Deterministic Digital Forensics Kernel  

---

## 1. Executive Overview

A modern distributed e-commerce platform like **Northstar Shop** frequently suffers from "ghost data" retention: an automated deletion workflow reports a deletion request as `COMPLETE`, yet copies of sensitive customer information persist undetected across:
- **Primary & Secondary Databases** (Read replicas, reporting instances, failover mirrors)
- **Customer Support Systems** (Ticket transcripts, uploaded PDF proof attachments)
- **Search Indexes** (Customer directory indexes, reverse lookup caches)
- **Analytics & Telemetry** (Un-anonymized user cohort profiles, event streams)
- **Streaming Connectors** (Kafka event pipelines continuously recreating deleted rows downstream)
- **Cold Backups & Disaster Recovery Snapshots** (Restoration paths capable of resurrecting purged records)

**GhostTrace AI** is an automated digital-forensics assurance agent that independently investigates raw multi-system evidence, resolves customer identity history across multiple aliases and email hashes, identifies residual records and recreation risks, strictly applies regulatory deletion policies, and produces canonical, evidence-backed audit reports.

---

## 2. Core Architecture & Pipeline

```
                                  +------------------------------------+
                                  |   Customer Deletion Request CSV    |
                                  |       (518 Production Cases)       |
                                  +-----------------+------------------+
                                                    |
                                                    v
+-----------------------------+        +------------+-------------+        +------------------------------+
|   user_identities.csv       | -----> |                          | <----- |     system_activity.csv      |
|   user_audit_log.csv        |        |    IDENTITY RESOLVER     |        |    (Event trace correlation) |
|   (Historical email hashes) |        | (Multi-alias correlation)|        +------------------------------+
+-----------------------------+        +------------+-------------+
                                                    |
                                                    v
+-----------------------------+        +------------+-------------+        +------------------------------+
|     94 Raw Evidence Files   | -----> |     EVIDENCE PARSER      | -----> |      CORE AUDIT ENGINE       |
|  - 28 JSON snapshot bundles |        | (Two-pass trace linking, |        |   - Policy rule evaluation   |
|  - 24 SQLite memory schemas |        |  PDF text extraction,    |        |   - Status classification    |
|  - 26 Query & service logs  |        |  SQL database mount)     |        |   - Canonical step ordering  |
|  - 4 PDF attachments        |        +--------------------------+        +--------------+---------------+
|  - 1 Account handover text  |                                                           |
+-----------------------------+                                                           v
                                                                           +--------------+---------------+
                                                                           |     output.csv (Root)        |
                                                                           |  case_id,deletion_status,    |
                                                                           |        steps_json            |
                                                                           +------------------------------+
```

---

## 3. Quick Start & Execution

### System Requirements
- Python 3.10+ (Standard Library + `fastapi`, `uvicorn`, `pydantic`, `pypdf`)

### 1. Run Official Full Audit (518 Cases -> `output.csv`)
Generates the official submission `output.csv` at the repository root:
```bash
python code/main.py --audit
```

### 2. Run Benchmark Validation (32 Sample Cases)
Evaluates status accuracy against ground truth `sample_output.csv`:
```bash
python code/main.py --sample
```
*Current benchmark result:* **32/32 (100.0%) Status Accuracy**.

### 3. Generate Evaluation & Usage Reports
Runs comprehensive benchmark evaluation and writes markdown reports to `code/evaluation/`:
```bash
python code/main.py --evaluate
```

### 4. Launch Interactive Web Console
Starts the Northstar Shop Deletion Assurance Console on `http://127.0.0.1:8000`:
```bash
python code/main.py --serve
```

### 5. Run Secondary Analytical Features Demo
Demonstrates all 12 operational and governance features:
```bash
python code/main.py --features
```

### 6. Package Official Submission (`code.zip`)
Builds a submission-ready `code.zip` archive excluding dataset and cache files:
```bash
python code/main.py --package
```

---

## 4. Output Contract Specification

The root `output.csv` conforms strictly to the HackerRank scoring contract:
- **Columns:** `case_id,deletion_status,steps_json`
- **Rows:** Exactly 518 data rows sorted ascending by `case_id`.
- **Status Classes:**
  - `COMPLETE`: Deletion authorized and verified absent/redacted across all systems; verification steps cite verified evidence.
  - `INCOMPLETE`: Residual data, active data flow, or unblocked backup detected; ordered steps include findings with evidence, required remediations, and future verifications (`evidence_id=""`).
  - `NOT_APPLICABLE`: Request does not authorize deletion (e.g., data portability, correction, invoices); `steps_json` is `[]`.

---

## 5. Secondary Features Suite

GhostTrace AI incorporates 12 secondary analytical features designed to provide digital forensics and operational remediation capabilities without modifying the core submission pipeline:

1. **Customer Persona Journey Simulator (`Priya's Journey`):** Traces synthetic customer Priya Ramanathan's complete 7-stage e-commerce lifecycle from registration to account deletion, illustrating where ghost data lingered.
2. **Subsystem Residual Heatmap:** Evaluates risk scores and remediation actions across Northstar Shop subsystems (Primary DB, Read Replicas, Support Tickets, Analytics, Backups).
3. **Backup Reintroduction Simulator:** Models disaster-recovery snapshot restoration to identify potential ghost data resurrection.
4. **Contradiction Detector:** Detects and flags discrepancies between claimed system statuses and ground evidence.
5. **Evidence Confidence Scorer:** Computes an advisory 0–100 confidence score based on system coverage, evidence completeness, and timestamp consistency.
6. **Remediation Playbook Generator:** Translates raw findings into step-by-step engineering playbooks citing official deletion rules.
7. **Deletion Chain-of-Custody:** Tracks five chronological assurance milestones and seals the audit chain with a cryptographic SHA-256 seal.
8. **Policy-Aware Action Advisor:** Guides teams on the 5 data protection treatments (`DELETE`, `REDACT`, `ANONYMIZE`, `RETAIN`, `BLOCK_RESTORE`).
9. **Sensitive-Field Exposure Scanner:** Scans non-primary artifacts for residual PII with safe masking previews.
10. **Risk-Based Review Queue:** Prioritizes cases by residual risk severity for incident triage.
11. **Immutable Audit Evidence Pack Exporter:** Exports self-contained, tamper-evident JSON/Markdown audit evidence packs with file SHA-256 digests.
12. **What-If Retention Simulator:** Simulates alternative retention horizons (Strict Zero-Trust, Standard Retail, Enterprise) to project residual exposure windows.

---

## 6. Submission Deliverables Summary

| Deliverable | Location | Status |
|---|---|---|
| **Root Output CSV** | `./output.csv` | Verified (518 rows, exact schema, 100% compliant) |
| **Evaluation Report** | `code/evaluation/evaluation_report.md` | Generated (100% sample accuracy, 4 custom cases) |
| **Usage Report** | `code/evaluation/usage_report.md` | Generated ($0.00 token cost, deterministic execution) |
| **Chat Transcript** | `./log.txt` | Formatted per `AGENTS.md` standard |
| **Submission Package** | `./code.zip` | Packaged (Zero dataset files, clean archive) |
