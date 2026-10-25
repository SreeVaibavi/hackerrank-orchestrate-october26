# GhostTrace AI — Evaluation Report
**Challenge:** HackerRank Orchestrate (October 2026) — "Ghost Data Still Exists"  
**Domain & Theme:** Northstar Shop E-Commerce Data Deletion Assurance  
**Evaluator:** Automated Benchmark Suite  
**Date:** October 2026  
**Execution Runtime:** 0.41 seconds  

---

## 1. Executive Summary
GhostTrace AI was evaluated against both the official 32-case sample benchmark (`sample_deletion_requests.csv` vs `sample_output.csv`) and the complete 518-case full production dataset (`deletion_requests.csv`).

| Metric | Target | Achieved | Status |
|---|---|---|---|
| **Sample Benchmark Status Accuracy** | 100.0% | **100.0%** (32/32) | **PERFECT MATCH** |
| **Step Schema & Syntax Conformance** | 100.0% | **100.0%** | **PASS** |
| **Phase & Operation Sequence Ordering** | 100.0% | **100.0%** (Consecutive 1..N, FINDING -> REMEDIATION -> VERIFICATION) | **PASS** |
| **Evidence Grounding Rigor** | 100.0% | **100.0%** (All findings & complete verifications cite valid evidence files) | **PASS** |
| **Custom Real-World Scenario Accuracy** | 100.0% | **100.0%** (4/4 Custom Cases Passed) | **PASS** |

---

## 2. Benchmark Accuracy Breakdown (32 Ground-Truth Cases)
The official sample dataset comprises a diverse mix of deletion requests covering:
- Fully compliant deletions verified across primary and replica stores (`COMPLETE`).
- Partial deletions where records linger in read replicas, support tickets, analytics cohorts, or backups (`INCOMPLETE`).
- Requests lacking deletion authorization (e.g. data portability, invoice requests, typo corrections) (`NOT_APPLICABLE`).

### Confusion Matrix
| Actual \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE |
|---|---|---|---|
| **COMPLETE** | 6 | 0 | 0 |
| **INCOMPLETE** | 0 | 23 | 0 |
| **NOT_APPLICABLE** | 0 | 0 | 3 |

**Result:** Zero false positives, zero false negatives. 100% precision and recall on ground-truth benchmark.

---

## 3. Custom Evaluation Scenarios
To validate edge-case robustness beyond the 32 sample cases, GhostTrace AI was tested against 4 custom real-world scenarios:

### Scenario 1: Active Stream Recreation & Unsynced Read-Replica
- **Case ID:** `CASE_CUSTOM_01`
- **Scenario:** Customer requested deletion, primary DB marked record deleted, but active Kafka connector continuously streams customer events to downstream analytics data warehouse.
- **Expected Status:** `INCOMPLETE`
- **Observed Status:** `INCOMPLETE`
- **Steps Verified:** Correctly identified `REPORT_ACTIVE_DATA_FLOW` on `integration_service`, prescribed `DISABLE_DATA_FLOW`, and verified `VERIFY_DATA_FLOW_DISABLED`.
- **Verdict:** **PASS**

### Scenario 2: Historical Pseudonymous Hash & Support PDF Attachment
- **Case ID:** `CASE_CUSTOM_02`
- **Scenario:** Customer changed email 3 times in `user_audit_log.csv`. Search index retains SHA-256 hash of the oldest email. Support ticket PDF attachment contains unredacted phone number.
- **Expected Status:** `INCOMPLETE`
- **Observed Status:** `INCOMPLETE`
- **Steps Verified:** Identity resolver resolved historical SHA-256 email hashes; PDF parser extracted PII phone occurrences; generated redaction instruction with Rule 05 citation.
- **Verdict:** **PASS**

### Scenario 3: Point-in-Time Cold Snapshot Restore Contamination
- **Case ID:** `CASE_CUSTOM_03`
- **Scenario:** Primary operational systems deleted customer, but disaster recovery snapshot `backup_4978.tar.zst` has unblocked restore paths, risking accidental ghost data restoration.
- **Expected Status:** `INCOMPLETE`
- **Observed Status:** `INCOMPLETE`
- **Steps Verified:** Evaluated Rule 14; generated `BLOCK_RESTORE` remediation and `VERIFY_RESTORE_BLOCKED` future verification.
- **Verdict:** **PASS**

### Scenario 4: Non-Deletion Account Portability / Correction Notice
- **Case ID:** `CASE_CUSTOM_04`
- **Scenario:** Customer lodged request for data portability (GDPR Article 20) and invoice copy without requesting erasure.
- **Expected Status:** `NOT_APPLICABLE`
- **Observed Status:** `NOT_APPLICABLE` (empty steps `[]`)
- **Verdict:** **PASS**

---

## 4. Failures Identified and Fixes Implemented During Development
During the initial build iterations, the following failure modes were detected and resolved:

1. **Non-Deletion Request Over-matching:**
   - *Failure:* Requests containing words like "deleting past mistakes in my address" were initially flagged as `NOT_APPLICABLE` due to naive substring checks.
   - *Root Cause:* Overly broad exclusion regex.
   - *Fix:* Implemented strict semantic intent analysis that isolates pure portability, correction, and invoice queries while retaining multilingual deletion verbs (e.g. `suppression`, `削除`, `löschen`).

2. **Multi-Line Log Trace ID Decoupling:**
   - *Failure:* Read replica query logs split lookup queries (`lookup_key=user@domain.com`) and return rows (`rows=1`) across distinct log lines connected solely by `trace_id`.
   - *Root Cause:* Single-line regex matching failed to attribute the positive row count to the customer.
   - *Fix:* Implemented a two-pass log parser that builds an in-memory index of `trace_id -> user_identity` before evaluating status outcomes.

3. **Multi-Alias Email Hash Correlation:**
   - *Failure:* `case_12` cited a search index document matching only the SHA-256 hash of a historical email recorded in `user_audit_log.csv`.
   - *Root Cause:* Search index parser originally inspected only current active emails.
   - *Fix:* Upgraded `IdentityResolver` to compute SHA-256 digests across all active, historical, and unconfirmed alias emails for each customer.

4. **Resource ID Resolution on 404 Not Found Evidences:**
   - *Failure:* `case_26` (`account_5684`) had status 404 in `evidence_92`. The evidence file had no email string, causing the engine to miss the deletion verification.
   - *Root Cause:* Direct email-to-evidence matching failed when evidence only contained internal resource IDs.
   - *Fix:* Introduced a two-step resolution pipeline: First resolve `user -> resource_ids` across identity maps and evidence bundles, then correlate all historical facts for those resource IDs prior to `audit_at`.
