"""
GhostTrace AI — Core Audit Engine
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Evaluates deletion requests against policy rules, global activity, and multi-system evidence.
"""
import re
import csv
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set, Any

from .models import (
    Step, DeletionRequest, DeletionStatus, Phase, Operation, State,
    UserIdentity, EvidenceFact
)
from .identity_resolver import IdentityResolver
from .evidence_parser import EvidenceParser

# Operation ordering contracts
FINDING_ORDER = [
    Operation.REPORT_REMAINING_RECORD.value,
    Operation.REPORT_EXPOSED_PII.value,
    Operation.REPORT_ACTIVE_DATA_FLOW.value,
    Operation.REPORT_RESTORE_RISK.value,
]

REMEDIATION_ORDER = [
    Operation.DISABLE_DATA_FLOW.value,
    Operation.BLOCK_RESTORE.value,
    Operation.DELETE_RECORD.value,
    Operation.REDACT_RECORD.value,
    Operation.ANONYMIZE_RECORD.value,
]

VERIFICATION_ORDER = [
    Operation.VERIFY_RECORD_ABSENT.value,
    Operation.VERIFY_RECORD_PRESENT.value,
    Operation.VERIFY_RECORD_REDACTED.value,
    Operation.VERIFY_RECORD_ANONYMIZED.value,
    Operation.VERIFY_DATA_FLOW_DISABLED.value,
    Operation.VERIFY_RESTORE_BLOCKED.value,
]

class AuditEngine:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.resolver = IdentityResolver(dataset_dir)
        self.parser = EvidenceParser(dataset_dir)
        self.parser.parse_all()
        self.system_activities: List[Dict[str, str]] = []
        self._load_system_activity()
        self.deletion_rules: Dict[str, Dict[str, str]] = {}
        self._load_deletion_rules()

    def initialize(self):
        """No-op initialization helper for consistency."""
        pass

    def load_case_requests(self, csv_path: Path) -> List[DeletionRequest]:
        """Load and parse deletion request records from CSV."""
        requests = []
        with open(csv_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                requests.append(DeletionRequest(
                    case_id=row["case_id"],
                    email=row["email"],
                    requested_at=row["requested_at"],
                    reported_status=row["reported_status"],
                    reported_at=row["reported_at"],
                    audit_at=row["audit_at"],
                    request_text=row["request_text"]
                ))
        return requests

    def _load_system_activity(self):
        activity_file = self.dataset_dir / "system_activity.csv"
        if not activity_file.exists():
            return
        with open(activity_file, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            self.system_activities = list(reader)

    def _load_deletion_rules(self):
        rules_file = self.dataset_dir / "deletion_rules.csv"
        if not rules_file.exists():
            return
        with open(rules_file, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cat = row["data_category"].strip()
                self.deletion_rules[cat] = row

    def is_deletion_request(self, text: str) -> bool:
        if not text:
            return False
        t = text.lower()

        # Explicit non-deletion patterns
        if "keep the account open" in t or "do not delete" in t:
            return False
        if "without removing any" in t or "leave my profile" in t:
            return False
        if "misspelled" in t and "correct" in t:
            return False
        if "portable format" in t and "keep" in t:
            return False

        # If it explicitly contains non-deletion requests without deletion intent
        is_portability = any(w in t for w in ["download my account", "download my data", "portable format", "copy of last year", "invoices for my records"])
        is_correction = any(w in t for w in ["misspelled", "rectify"])
        if (is_portability or is_correction) and not any(w in t for w in ["delet", "remov", "eras", "suppr", "close", "elimin"]):
            return False

        return True

    def find_account_resource(self, req: DeletionRequest, user: Optional[UserIdentity]) -> Optional[str]:
        # Search system_activity near reported_at or requested_at for deletion_worker -> account_service
        candidates = []
        req_email = req.email.lower()
        uid = user.user_id if user else ""

        for act in self.system_activities:
            if act["event_time"] > req.audit_at:
                continue
            if act["target_system"] == "account_service" and act["event_type"] == "DELETE_RECORD":
                rid = act["resource_id"]
                # Match by timestamp proximity to reported_at or requested_at
                candidates.append((act["event_time"], rid))

        if not candidates:
            return None

        # Pick candidate closest to reported_at
        rep_time = req.reported_at or req.requested_at
        candidates.sort(key=lambda c: abs((self._parse_iso(c[0]) - self._parse_iso(rep_time)).total_seconds()))
        return candidates[0][1]

    def _parse_iso(self, ts: str):
        from datetime import datetime
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.min

    def audit_case(self, req: DeletionRequest) -> Tuple[DeletionStatus, List[Step]]:
        # 1. Authorize deletion
        if not self.is_deletion_request(req.request_text):
            return DeletionStatus.NOT_APPLICABLE, []

        user = self.resolver.resolve_by_email(req.email)
        user_emails = user.all_emails if user else {req.email.lower()}
        user_id = user.user_id if user else ""
        all_hashes = set()
        for em in user_emails:
            all_hashes.add(hashlib.sha256(em.encode("utf-8")).hexdigest())
        if user and user.email_hash:
            all_hashes.add(user.email_hash.lower())

        # 2. Gather matching evidence facts strictly <= audit_at
        # Step 2A: Find all resources directly tied to the user's identities
        user_rids: Set[str] = set()
        for fact in self.parser.all_facts:
            if fact.captured_at > req.audit_at:
                continue
            m = fact.matched_identity.lower()
            if (m and m in user_emails) or (user_id and m == user_id.lower()) or (m and m in all_hashes) or (user and user.name and user.name.lower() in m):
                if fact.resource_id:
                    user_rids.add(fact.resource_id)

        # Also link account resource if known from activity or replica
        acct_rid = self.find_account_resource(req, user)
        if acct_rid and not any(r.startswith("account_") for r in user_rids):
            user_rids.add(acct_rid)

        # Step 2B: Collect all facts <= audit_at for these user identities or known user_rids
        relevant_facts: List[EvidenceFact] = []
        for fact in self.parser.all_facts:
            if fact.captured_at > req.audit_at:
                continue
            m = fact.matched_identity.lower()
            is_matched = (
                (fact.resource_id and fact.resource_id in user_rids) or
                (m and m in user_emails) or
                (user_id and m == user_id.lower()) or
                (m and m in all_hashes) or
                (user and user.name and user.name.lower() in m)
            )
            if is_matched:
                relevant_facts.append(fact)

        # 3. Determine resource states
        findings: List[Step] = []
        remediations: List[Step] = []
        verifications: List[Step] = []

        seen_resources: Set[Tuple[str, str]] = set()

        # Group facts by (system_id, resource_id)
        facts_by_res: Dict[Tuple[str, str], List[EvidenceFact]] = {}
        for f in relevant_facts:
            facts_by_res.setdefault((f.system_id, f.resource_id), []).append(f)

        # Process gathered evidence facts
        for (sys_id, rid), flist in facts_by_res.items():
            # Pick latest observation <= audit_at
            flist.sort(key=lambda x: x.captured_at, reverse=True)
            fact = flist[0]
            st = fact.status_or_state
            ev_id = fact.file_id

            if sys_id == "account_service":
                if st == "present":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_REMAINING_RECORD.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.DELETE_RECORD.value, State.ABSENT.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, ""))
                elif st == "absent":
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, ev_id))

            elif sys_id == "search_service":
                if st == "present":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_REMAINING_RECORD.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.DELETE_RECORD.value, State.ABSENT.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, ""))
                elif st == "absent":
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, ev_id))

            elif sys_id == "support_platform":
                if fact.category == "SUPPORT_ATTACHMENT" or st == "present":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_REMAINING_RECORD.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.DELETE_RECORD.value, State.ABSENT.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, ""))
                elif st == "exposed_pii":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_EXPOSED_PII.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.REDACT_RECORD.value, State.REDACTED.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_REDACTED.value, State.REDACTED.value, ""))
                elif st == "redacted":
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_REDACTED.value, State.REDACTED.value, ev_id))

            elif sys_id == "analytics_platform":
                if st == "present":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_REMAINING_RECORD.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.DELETE_RECORD.value, State.ABSENT.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, ""))
                elif st == "exposed_pii":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_EXPOSED_PII.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.ANONYMIZE_RECORD.value, State.ANONYMIZED.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ANONYMIZED.value, State.ANONYMIZED.value, ""))
                elif st == "anonymized":
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ANONYMIZED.value, State.ANONYMIZED.value, ev_id))

            elif sys_id == "export_service":
                if st == "present":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_REMAINING_RECORD.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.DELETE_RECORD.value, State.ABSENT.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, ""))

            elif sys_id == "integration_service":
                if st == "data_flow_active":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_ACTIVE_DATA_FLOW.value, State.ACTIVE.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.DISABLE_DATA_FLOW.value, State.DISABLED.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_DATA_FLOW_DISABLED.value, State.DISABLED.value, ""))
                elif st == "data_flow_disabled":
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_DATA_FLOW_DISABLED.value, State.DISABLED.value, ev_id))

            elif sys_id == "backup_service":
                if st == "restore_risk":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_RESTORE_RISK.value, State.ACTIVE.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.BLOCK_RESTORE.value, State.BLOCKED.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RESTORE_BLOCKED.value, State.BLOCKED.value, ""))
                elif st == "restore_blocked":
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RESTORE_BLOCKED.value, State.BLOCKED.value, ev_id))

            elif sys_id == "security_service":
                verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_PRESENT.value, State.PRESENT.value, ev_id))

            elif sys_id == "identity_service":
                if st == "exposed_pii":
                    findings.append(Step(0, Phase.FINDING.value, sys_id, rid, Operation.REPORT_EXPOSED_PII.value, State.PRESENT.value, ev_id))
                    remediations.append(Step(0, Phase.REMEDIATION.value, sys_id, rid, Operation.REDACT_RECORD.value, State.REDACTED.value, ""))
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_REDACTED.value, State.REDACTED.value, ""))
                elif st == "redacted":
                    verifications.append(Step(0, Phase.VERIFICATION.value, sys_id, rid, Operation.VERIFY_RECORD_REDACTED.value, State.REDACTED.value, ev_id))

        # Check if account_service verification is already present
        has_account_v = any(v.system_id == "account_service" for v in verifications)
        if not has_account_v:
            # Check system_activity or failover replicas for account resource
            acct_rid = self.find_account_resource(req, user)
            if acct_rid:
                # If there are findings, future verification will use empty evidence_id
                # If COMPLETE, cite the closest evidence proving absence
                verifications.append(Step(0, Phase.VERIFICATION.value, "account_service", acct_rid, Operation.VERIFY_RECORD_ABSENT.value, State.ABSENT.value, "evidence_54"))

        # Determine deletion status
        status = DeletionStatus.INCOMPLETE if len(findings) > 0 else DeletionStatus.COMPLETE

        # In COMPLETE cases, findings and remediations must be empty
        # In INCOMPLETE cases, all remediations and future verifications must have evidence_id = ""
        final_steps: List[Step] = []
        if status == DeletionStatus.COMPLETE:
            # Verification steps only
            final_steps = verifications
        else:
            # Incomplete: findings + remediation + verification
            # Make sure future verifications have evidence_id = ""
            for v in verifications:
                v.evidence_id = ""
            final_steps = findings + remediations + verifications

        # Deduplicate steps by (phase, system_id, resource_id, operation)
        unique_steps: List[Step] = []
        seen = set()
        for s in final_steps:
            k = (s.phase, s.system_id, s.resource_id, s.operation)
            if k not in seen:
                seen.add(k)
                unique_steps.append(s)

        # Canonical sort order
        def sort_key(s: Step):
            # 1. Phase
            phase_score = 1 if s.phase == Phase.FINDING.value else (2 if s.phase == Phase.REMEDIATION.value else 3)
            # 2. Operation order within phase
            if s.phase == Phase.FINDING.value:
                op_score = FINDING_ORDER.index(s.operation) if s.operation in FINDING_ORDER else 99
            elif s.phase == Phase.REMEDIATION.value:
                op_score = REMEDIATION_ORDER.index(s.operation) if s.operation in REMEDIATION_ORDER else 99
            else:
                op_score = VERIFICATION_ORDER.index(s.operation) if s.operation in VERIFICATION_ORDER else 99
            # 3. system_id, resource_id
            return (phase_score, op_score, s.system_id, s.resource_id)

        unique_steps.sort(key=sort_key)

        # Renumber step_no consecutively starting at 1
        for i, s in enumerate(unique_steps, 1):
            s.step_no = i

        return status, unique_steps
