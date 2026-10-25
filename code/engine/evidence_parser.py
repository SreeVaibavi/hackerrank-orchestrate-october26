"""
GhostTrace AI — Evidence Parsing Engine (Enhanced)
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Parses all 94 evidence artifacts across SQL, JSON, Log, Text, and PDF files.
"""
import os
import re
import csv
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from .models import EvidenceFact

class EvidenceParser:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.manifest: Dict[str, Dict[str, str]] = {}
        self.facts_by_file: Dict[str, List[EvidenceFact]] = {}
        self.all_facts: List[EvidenceFact] = []
        self._load_manifest()

    def _load_manifest(self):
        manifest_path = self.dataset_dir / "evidence_files.csv"
        if not manifest_path.exists():
            return

        with open(manifest_path, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                fid = row["file_id"].strip()
                self.manifest[fid] = {
                    "file_id": fid,
                    "file_path": row["file_path"].strip(),
                    "origin": row.get("origin", "").strip(),
                    "captured_at": row.get("captured_at", "").strip()
                }

    def parse_all(self):
        for fid, info in self.manifest.items():
            rel_path = info["file_path"]
            full_path = self.dataset_dir / rel_path
            if not full_path.exists():
                continue

            captured_at = info["captured_at"]
            ext = full_path.suffix.lower()

            try:
                if ext == ".json":
                    self._parse_json(fid, full_path, captured_at)
                elif ext == ".sql":
                    self._parse_sql(fid, full_path, captured_at)
                elif ext == ".log":
                    self._parse_log(fid, full_path, captured_at)
                elif ext == ".txt":
                    self._parse_txt(fid, full_path, captured_at)
                elif ext == ".pdf":
                    self._parse_pdf(fid, full_path, captured_at)
            except Exception as e:
                pass

    def _add_fact(self, fact: EvidenceFact):
        self.facts_by_file.setdefault(fact.file_id, []).append(fact)
        self.all_facts.append(fact)

    def _parse_json(self, fid: str, path: Path, captured_at: str):
        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return

        # Type A: service_resource_export
        if "service_exports" in data:
            exports = data["service_exports"]
            for sys_name, svc_data in exports.items():
                if not isinstance(svc_data, dict):
                    continue

                if "profile_lookups" in svc_data:
                    for item in svc_data["profile_lookups"]:
                        rid = item.get("resource_id", "")
                        status_code = item.get("status_code", 404)
                        profile = item.get("profile") or {}
                        email = profile.get("email") or ""
                        cust_ref = profile.get("customer_reference") or ""
                        obs_at = item.get("observed_at", captured_at)

                        state_type = "absent" if status_code == 404 else "present"
                        ident = email.lower() if email else cust_ref
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="account_service",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=ident,
                            category="USER_PROFILE",
                            status_or_state=state_type,
                            details={"status_code": status_code, "profile": profile}
                        ))

                if "profiles" in svc_data:
                    for item in svc_data["profiles"]:
                        rid = item.get("resource_id", "")
                        email = item.get("email") or ""
                        phone = item.get("phone") or ""
                        cust_ref = item.get("customer_reference") or ""
                        obs_at = item.get("observed_at", captured_at)

                        has_pii = bool(email or phone or (cust_ref and not cust_ref.startswith("anon_")))
                        state_type = "exposed_pii" if has_pii else "anonymized"
                        ident = email.lower() if email else cust_ref
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="analytics_platform",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=ident,
                            category="ANALYTICS_PROFILE",
                            status_or_state=state_type,
                            details=item
                        ))

                if "restore_entries" in svc_data:
                    for item in svc_data["restore_entries"]:
                        rid = item.get("resource_id", "")
                        email = item.get("customer_email") or ""
                        cust_ref = item.get("customer_reference") or ""
                        restore_allowed = item.get("restore_allowed", False)
                        obs_at = item.get("observed_at", captured_at)

                        state_type = "restore_risk" if restore_allowed else "restore_blocked"
                        ident = email.lower() if email else cust_ref
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="backup_service",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=ident,
                            category="BACKUP_ARCHIVE",
                            status_or_state=state_type,
                            details=item
                        ))

                if "exports" in svc_data:
                    for item in svc_data["exports"]:
                        rid = item.get("resource_id", "")
                        email = item.get("owner_email") or ""
                        cust_ref = item.get("customer_reference") or ""
                        obs_at = item.get("observed_at", captured_at)

                        ident = email.lower() if email else cust_ref
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="export_service",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=ident,
                            category="USER_EXPORT",
                            status_or_state="present",
                            details=item
                        ))

                if "connectors" in svc_data:
                    for item in svc_data["connectors"]:
                        rid = item.get("resource_id", "")
                        email = item.get("customer_email") or ""
                        cust_ref = item.get("customer_reference") or ""
                        enabled = item.get("enabled", False)
                        obs_at = item.get("observed_at", captured_at)

                        state_type = "data_flow_active" if enabled else "data_flow_disabled"
                        ident = email.lower() if email else cust_ref
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="integration_service",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=ident,
                            category="DATA_FLOW",
                            status_or_state=state_type,
                            details=item
                        ))

                if "index_queries" in svc_data:
                    for item in svc_data["index_queries"]:
                        rid = item.get("resource_id", "")
                        query = item.get("query", "")
                        hits = item.get("hits") or {}
                        total = hits.get("total", 0)
                        obs_at = item.get("observed_at", captured_at)

                        state_type = "present" if total > 0 else "absent"
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="search_service",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=query.lower(),
                            category="SEARCH_INDEX_ENTRY",
                            status_or_state=state_type,
                            details=item
                        ))

                if "audit_records" in svc_data:
                    for item in svc_data["audit_records"]:
                        rid = item.get("resource_id", "")
                        subj_ref = item.get("subject_reference") or ""
                        obs_at = item.get("observed_at", captured_at)

                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="security_service",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=subj_ref,
                            category="SECURITY_AUDIT_LOG",
                            status_or_state="retained",
                            details=item
                        ))

                if "tickets" in svc_data:
                    for item in svc_data["tickets"]:
                        rid = item.get("resource_id", "")
                        email = item.get("requester_email") or ""
                        name = item.get("requester_name") or ""
                        phone = item.get("requester_phone") or ""
                        cust_ref = item.get("customer_reference") or ""
                        obs_at = item.get("observed_at", captured_at)

                        has_pii = bool(email or name or phone)
                        state_type = "exposed_pii" if has_pii else "redacted"
                        ident = email.lower() if email else cust_ref
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="support_platform",
                            resource_id=rid,
                            captured_at=obs_at,
                            matched_identity=ident,
                            category="SUPPORT_MESSAGE",
                            status_or_state=state_type,
                            details=item
                        ))

        # Type B: customer_data_snapshot_bundle
        elif "snapshots" in data:
            for snap in data["snapshots"]:
                store = snap.get("data_store", "")
                coll = snap.get("collection", "")
                snap_time = snap.get("captured_at", captured_at)
                for rec in snap.get("records", []):
                    rid = rec.get("resource_id", "")
                    subj = rec.get("subject_reference") or rec.get("user_id") or ""
                    email = rec.get("email") or ""
                    ident = email.lower() if email else subj

                    if coll == "deleted_customer_references" or "tombstone" in rid:
                        has_pii = bool(rec.get("name") or rec.get("email") or rec.get("phone") or rec.get("email_hash"))
                        state_type = "exposed_pii" if has_pii else "redacted"
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="identity_service",
                            resource_id=rid,
                            captured_at=snap_time,
                            matched_identity=ident,
                            category="ACCOUNT_TOMBSTONE",
                            status_or_state=state_type,
                            details=rec
                        ))
                    elif coll == "security_audit_events" or "audit_record" in rid:
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="security_service",
                            resource_id=rid,
                            captured_at=snap_time,
                            matched_identity=ident,
                            category="SECURITY_AUDIT_LOG",
                            status_or_state="retained",
                            details=rec
                        ))
                    elif coll == "customer_profiles":
                        status = rec.get("account_status", "")
                        state_type = "present" if status != "DELETED" else "absent"
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="account_service",
                            resource_id=rid,
                            captured_at=snap_time,
                            matched_identity=ident,
                            category="USER_PROFILE",
                            status_or_state=state_type,
                            details=rec
                        ))

        # Type C: records array (connector_configurations, customer_export_jobs, etc.)
        elif "records" in data:
            for rec in data.get("records", []):
                rid = rec.get("resource_id", "")
                email = rec.get("owner_email") or rec.get("customer_email") or rec.get("email") or ""
                cust_ref = rec.get("customer_reference") or rec.get("subject_reference") or ""
                ident = email.lower() if email else cust_ref

                if "data_flow" in rid:
                    enabled = rec.get("enabled", False)
                    state_type = "data_flow_active" if enabled else "data_flow_disabled"
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="integration_service",
                        resource_id=rid,
                        captured_at=captured_at,
                        matched_identity=ident,
                        category="DATA_FLOW",
                        status_or_state=state_type,
                        details=rec
                    ))
                elif "export" in rid:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="export_service",
                        resource_id=rid,
                        captured_at=captured_at,
                        matched_identity=ident,
                        category="USER_EXPORT",
                        status_or_state="present",
                        details=rec
                    ))
                elif "audit_record" in rid:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="security_service",
                        resource_id=rid,
                        captured_at=captured_at,
                        matched_identity=ident,
                        category="SECURITY_AUDIT_LOG",
                        status_or_state="retained",
                        details=rec
                    ))
                elif "analytics" in rid:
                    has_pii = bool(email or rec.get("phone"))
                    state_type = "exposed_pii" if has_pii else "anonymized"
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="analytics_platform",
                        resource_id=rid,
                        captured_at=captured_at,
                        matched_identity=ident,
                        category="ANALYTICS_PROFILE",
                        status_or_state=state_type,
                        details=rec
                    ))

    def _parse_sql(self, fid: str, path: Path, captured_at: str):
        con = sqlite3.connect(":memory:")
        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            sql_text = f.read()

        con.executescript(sql_text)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in cur.fetchall()]

        for tbl in tables:
            cur.execute(f"PRAGMA table_info({tbl});")
            cols = [r[1] for r in cur.fetchall()]

            if "record_json" in cols:
                cur.execute(f"SELECT * FROM {tbl};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    raw_json = row_dict.get("record_json", "{}")
                    try:
                        rec = json.loads(raw_json)
                    except Exception:
                        rec = {}

                    rid = row_dict.get("resource_id") or rec.get("resource_id", "")
                    sys_name = row_dict.get("origin_system", "")
                    up_at = row_dict.get("updated_at", captured_at)

                    uid = rec.get("user_id") or rec.get("subject_reference") or rec.get("customer_reference") or ""
                    email = rec.get("email") or rec.get("owner_email") or rec.get("customer_email") or rec.get("subject_selector") or ""
                    ident = email.lower() if email else uid

                    if "analytics" in rid or sys_name == "analytics_platform":
                        has_pii = bool(rec.get("email") or rec.get("phone") or (rec.get("user_id") and not rec.get("user_id").startswith("anon_")))
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="analytics_platform",
                            resource_id=rid,
                            captured_at=up_at,
                            matched_identity=ident,
                            category="ANALYTICS_PROFILE",
                            status_or_state="exposed_pii" if has_pii else "anonymized",
                            details=rec
                        ))
                    elif "audit_record" in rid or sys_name == "security_service":
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="security_service",
                            resource_id=rid,
                            captured_at=up_at,
                            matched_identity=ident,
                            category="SECURITY_AUDIT_LOG",
                            status_or_state="retained",
                            details=rec
                        ))
                    elif "data_flow" in rid or sys_name == "integration_service":
                        enabled = rec.get("enabled", False)
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="integration_service",
                            resource_id=rid,
                            captured_at=up_at,
                            matched_identity=ident,
                            category="DATA_FLOW",
                            status_or_state="data_flow_active" if enabled else "data_flow_disabled",
                            details=rec
                        ))
                    elif "backup" in rid or sys_name == "backup_service":
                        restore_allowed = rec.get("restore_allowed", False)
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="backup_service",
                            resource_id=rid,
                            captured_at=up_at,
                            matched_identity=ident,
                            category="BACKUP_ARCHIVE",
                            status_or_state="restore_risk" if restore_allowed else "restore_blocked",
                            details=rec
                        ))
                    elif "search" in rid or sys_name == "search_service":
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="search_service",
                            resource_id=rid,
                            captured_at=up_at,
                            matched_identity=ident,
                            category="SEARCH_INDEX_ENTRY",
                            status_or_state="present",
                            details=rec
                        ))
                    elif "account" in rid or sys_name == "account_service":
                        self._add_fact(EvidenceFact(
                            file_id=fid,
                            system_id="account_service",
                            resource_id=rid,
                            captured_at=up_at,
                            matched_identity=ident,
                            category="USER_PROFILE",
                            status_or_state="present",
                            details=rec
                        ))
                continue

            if "customer_profiles" in tbl:
                is_failover = "failover" in tbl
                cur.execute(f"SELECT * FROM {tbl};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    rid = row_dict.get("resource_id", "")
                    uid = row_dict.get("user_id") or row_dict.get("customer_reference") or ""
                    email = row_dict.get("email") or ""
                    ident = email.lower() if email else uid
                    up_at = row_dict.get("updated_at", captured_at)

                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="account_service",
                        resource_id=rid,
                        captured_at=up_at or captured_at,
                        matched_identity=ident,
                        category="USER_PROFILE",
                        status_or_state="present",
                        details={"table": tbl, "is_failover": is_failover, **row_dict}
                    ))

            elif tbl == "customer_search_documents" or tbl == "search_documents_primary":
                cur.execute(f"SELECT * FROM {tbl};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    rid = row_dict.get("resource_id", "")
                    email = row_dict.get("email") or ""
                    ident = email.lower()
                    up_at = row_dict.get("updated_at", captured_at)
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="search_service",
                        resource_id=rid,
                        captured_at=up_at or captured_at,
                        matched_identity=ident,
                        category="SEARCH_INDEX_ENTRY",
                        status_or_state="present",
                        details=row_dict
                    ))

            elif tbl == "customer_analytics_profiles":
                cur.execute(f"SELECT * FROM {tbl};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    rid = row_dict.get("resource_id", "")
                    email = row_dict.get("email") or ""
                    cust_ref = row_dict.get("customer_reference") or ""
                    has_pii = bool(email or row_dict.get("phone"))
                    ident = email.lower() if email else cust_ref
                    up_at = row_dict.get("updated_at", captured_at)
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="analytics_platform",
                        resource_id=rid,
                        captured_at=up_at or captured_at,
                        matched_identity=ident,
                        category="ANALYTICS_PROFILE",
                        status_or_state="exposed_pii" if has_pii else "anonymized",
                        details=row_dict
                    ))

            elif tbl == "support_records":
                cur.execute(f"SELECT * FROM {tbl};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    rid = row_dict.get("resource_id", "")
                    email = row_dict.get("requester_email") or ""
                    cust_ref = row_dict.get("customer_reference") or ""
                    has_pii = bool(email or row_dict.get("requester_name") or row_dict.get("requester_phone"))
                    ident = email.lower() if email else cust_ref
                    up_at = row_dict.get("updated_at", captured_at)
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="support_platform",
                        resource_id=rid,
                        captured_at=up_at or captured_at,
                        matched_identity=ident,
                        category="SUPPORT_MESSAGE",
                        status_or_state="exposed_pii" if has_pii else "redacted",
                        details=row_dict
                    ))

            elif tbl == "backup_restore_entries":
                cur.execute(f"SELECT * FROM {tbl};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    rid = row_dict.get("resource_id", "")
                    email = row_dict.get("customer_email") or ""
                    cust_ref = row_dict.get("customer_reference") or ""
                    restore_allowed = bool(row_dict.get("restore_allowed"))
                    ident = email.lower() if email else cust_ref
                    up_at = row_dict.get("updated_at", captured_at)
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="backup_service",
                        resource_id=rid,
                        captured_at=up_at or captured_at,
                        matched_identity=ident,
                        category="BACKUP_ARCHIVE",
                        status_or_state="restore_risk" if restore_allowed else "restore_blocked",
                        details=row_dict
                    ))

            elif tbl == "security_audit_records":
                cur.execute(f"SELECT * FROM {tbl};")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    rid = row_dict.get("resource_id", "")
                    subj = row_dict.get("subject_reference") or row_dict.get("customer_reference") or ""
                    up_at = row_dict.get("updated_at", captured_at)
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="security_service",
                        resource_id=rid,
                        captured_at=up_at or captured_at,
                        matched_identity=subj,
                        category="SECURITY_AUDIT_LOG",
                        status_or_state="retained",
                        details=row_dict
                    ))
        con.close()

    def _parse_log(self, fid: str, path: Path, captured_at: str):
        # Two-pass parsing: first pass collects trace_id to identity mapping
        trace_to_ident: Dict[str, str] = {}
        trace_to_svc: Dict[str, str] = {}

        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]

        for line in lines:
            m_trace = re.search(r"trace_id=([\w\-]+)", line)
            m_key = (
                re.search(r'match_key="?([^"\s]+)"?', line) or
                re.search(r'subject_key="?([^"\s]+)"?', line) or
                re.search(r'lookup_key="?([^"\s]+)"?', line) or
                re.search(r'correlation_key="?([^"\s]+)"?', line) or
                re.search(r'matched_value="?([^"\s]+)"?', line) or
                re.search(r'subject_ref="?([^"\s]+)"?', line) or
                re.search(r'email="?([^"\s]+)"?', line)
            )
            m_svc = re.search(r"service=([\w\-]+)", line)

            if m_trace and m_key:
                trace_to_ident[m_trace.group(1)] = m_key.group(1).lower()
            if m_trace and m_svc:
                trace_to_svc[m_trace.group(1)] = m_svc.group(1)

        for line in lines:
            m_time = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", line)
            ts = m_time.group(1) if m_time else captured_at

            m_trace = re.search(r"trace_id=([\w\-]+)", line)
            tid = m_trace.group(1) if m_trace else ""

            m_key = (
                re.search(r'match_key="?([^"\s]+)"?', line) or
                re.search(r'subject_key="?([^"\s]+)"?', line) or
                re.search(r'lookup_key="?([^"\s]+)"?', line) or
                re.search(r'correlation_key="?([^"\s]+)"?', line) or
                re.search(r'matched_value="?([^"\s]+)"?', line) or
                re.search(r'subject_ref="?([^"\s]+)"?', line) or
                re.search(r'email="?([^"\s]+)"?', line)
            )
            ident = m_key.group(1).lower() if m_key else (trace_to_ident.get(tid, "") if tid else "")

            m_rid = re.search(r"resource_id=([\w\-]+)", line)
            rid = m_rid.group(1) if m_rid else ""

            m_svc = re.search(r"service=([\w\-]+)", line)
            svc = m_svc.group(1) if m_svc else (trace_to_svc.get(tid, "") if tid else "")

            # Pattern: record_lookup
            if "event=record_lookup" in line:
                m_sys = re.search(r'system="?([^"\s]+)"?', line)
                m_rid = re.search(r'resource_id="?([^"\s]+)"?', line)
                m_type = re.search(r'record_type="?([^"\s]+)"?', line)
                m_res = re.search(r'result="?([^"\s]+)"?', line)
                m_subj = re.search(r'subject_reference="?([^"\s]+)"?', line)

                sys_id = m_sys.group(1) if m_sys else ""
                rid = m_rid.group(1) if m_rid else ""
                rec_type = m_type.group(1) if m_type else ""
                res = m_res.group(1) if m_res else ""
                subj = m_subj.group(1).lower() if m_subj else ""

                state_type = "present"
                if res in ["NOT_FOUND", "ABSENT"]:
                    state_type = "absent"
                elif res in ["ANONYMIZED"]:
                    state_type = "anonymized"
                elif res in ["IDENTIFIABLE", "EXPOSED_PII"]:
                    state_type = "exposed_pii"
                elif res in ["REDACTED"]:
                    state_type = "redacted"
                elif res in ["RETAINED"]:
                    state_type = "retained"
                elif res in ["ACTIVE"]:
                    state_type = "data_flow_active" if rec_type == "DATA_FLOW" else "restore_risk"
                elif res in ["BLOCKED"]:
                    state_type = "restore_blocked"
                elif res in ["DISABLED"]:
                    state_type = "data_flow_disabled"

                if rid and sys_id:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id=sys_id,
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=subj,
                        category=rec_type,
                        status_or_state=state_type
                    ))

            # Pattern: audit_record_read_completed
            if "event=audit_record_read_completed" in line and rid:
                m_subj = re.search(r'subject_reference=([\w\-]+)', line)
                subj = m_subj.group(1).lower() if m_subj else ident
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="security_service",
                    resource_id=rid,
                    captured_at=ts,
                    matched_identity=subj,
                    category="SECURITY_AUDIT_LOG",
                    status_or_state="retained"
                ))

            # Pattern: analytics_profile_read_completed
            if "event=analytics_profile_read_completed" in line and rid:
                m_em = re.search(r'email=([^\s]+)', line)
                m_ph = re.search(r'phone=([^\s]+)', line)
                em = m_em.group(1) if (m_em and m_em.group(1) != "null") else ""
                ph = m_ph.group(1) if (m_ph and m_ph.group(1) != "null") else ""
                m_cust = re.search(r'customer_reference=([^\s]+)', line)
                cust = m_cust.group(1) if (m_cust and m_cust.group(1) != "null") else ""
                has_pii = bool(em or ph or (cust and not cust.startswith("anon_")))
                subj = em.lower() if em else (cust.lower() if cust else ident)
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="analytics_platform",
                    resource_id=rid,
                    captured_at=ts,
                    matched_identity=subj,
                    category="ANALYTICS_PROFILE",
                    status_or_state="exposed_pii" if has_pii else "anonymized"
                ))

            # Pattern: connector_config_read_completed
            if "event=connector_config_read_completed" in line and rid:
                m_en = re.search(r'enabled=([^\s]+)', line)
                enabled = m_en.group(1).lower() == "true" if m_en else False
                m_em = re.search(r'customer_email=([^\s]+)', line)
                em = m_em.group(1) if (m_em and m_em.group(1) != "null") else ""
                m_cust = re.search(r'customer_reference=([^\s]+)', line)
                cust = m_cust.group(1) if (m_cust and m_cust.group(1) != "null") else ""
                subj = em.lower() if em else (cust.lower() if cust else ident)
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="integration_service",
                    resource_id=rid,
                    captured_at=ts,
                    matched_identity=subj,
                    category="DATA_FLOW",
                    status_or_state="data_flow_active" if enabled else "data_flow_disabled"
                ))

            # Pattern: support_ticket_read_completed
            if "event=support_ticket_read_completed" in line and rid:
                m_em = re.search(r'requester_email=([^\s]+)', line)
                m_nm = re.search(r'requester_name=([^\s]+)', line)
                m_ph = re.search(r'requester_phone=([^\s]+)', line)
                em = m_em.group(1) if (m_em and m_em.group(1) != "null") else ""
                nm = m_nm.group(1) if (m_nm and m_nm.group(1) != "null") else ""
                ph = m_ph.group(1) if (m_ph and m_ph.group(1) != "null") else ""
                m_cust = re.search(r'customer_reference=([^\s]+)', line)
                cust = m_cust.group(1) if (m_cust and m_cust.group(1) != "null") else ""
                has_pii = bool(em or nm or ph)
                subj = em.lower() if em else (cust.lower() if cust else ident)
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="support_platform",
                    resource_id=rid,
                    captured_at=ts,
                    matched_identity=subj,
                    category="SUPPORT_MESSAGE",
                    status_or_state="exposed_pii" if has_pii else "redacted"
                ))

            # Pattern: restore_policy_read_completed
            if "event=restore_policy_read_completed" in line and rid:
                m_ra = re.search(r'restore_allowed=([^\s]+)', line)
                ra = m_ra.group(1).lower() == "true" if m_ra else False
                m_em = re.search(r'customer_email=([^\s]+)', line)
                em = m_em.group(1) if (m_em and m_em.group(1) != "null") else ""
                m_cust = re.search(r'customer_reference=([^\s]+)', line)
                cust = m_cust.group(1) if (m_cust and m_cust.group(1) != "null") else ""
                subj = em.lower() if em else (cust.lower() if cust else ident)
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="backup_service",
                    resource_id=rid,
                    captured_at=ts,
                    matched_identity=subj,
                    category="BACKUP_ARCHIVE",
                    status_or_state="restore_risk" if ra else "restore_blocked"
                ))

            # Pattern: export_metadata_read_completed
            if "event=export_metadata_read_completed" in line and rid:
                m_av = re.search(r'available=([^\s]+)', line)
                av = m_av.group(1).lower() == "true" if m_av else False
                m_em = re.search(r'owner_email=([^\s]+)', line)
                em = m_em.group(1) if (m_em and m_em.group(1) != "null") else ""
                subj = em.lower() if em else ident
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="export_service",
                    resource_id=rid,
                    captured_at=ts,
                    matched_identity=subj,
                    category="USER_EXPORT",
                    status_or_state="present" if av else "absent"
                ))

            if "support_replica" in line or svc == "support_replica":
                if "marker_found=false" in line and rid:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="support_platform",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="SUPPORT_MESSAGE",
                        status_or_state="present"
                    ))
                elif "rows=1" in line and rid:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="support_platform",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="SUPPORT_MESSAGE",
                        status_or_state="present"
                    ))

            if rid:
                if "http_status=404" in line or "rows=0" in line:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id=svc or "account_service",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="USER_PROFILE",
                        status_or_state="absent"
                    ))
                elif "event=message_pii_scan" in line or "event=attachment_pii_scan" in line:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id=svc or "support_platform",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="SUPPORT_MESSAGE",
                        status_or_state="exposed_pii"
                    ))
                elif "event=index_query_completed" in line and ("result=hit" in line or "total_hits=1" in line):
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id=svc or "search_service",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="SEARCH_INDEX_ENTRY",
                        status_or_state="present"
                    ))
                elif "restore_allowed=false" in line or "deletion_block=true" in line:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="backup_service",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="BACKUP_ARCHIVE",
                        status_or_state="restore_blocked"
                    ))
                elif "restore_allowed=true" in line or "deletion_block=false" in line or "restore_candidate_evaluated" in line:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="backup_service",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="BACKUP_ARCHIVE",
                        status_or_state="restore_risk"
                    ))
                elif "enabled=false" in line:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="integration_service",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="DATA_FLOW",
                        status_or_state="data_flow_disabled"
                    ))
                elif "enabled=true" in line:
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="integration_service",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="DATA_FLOW",
                        status_or_state="data_flow_active"
                    ))
                elif "contact_lookup_completed" in line and "analytics" in (svc or rid):
                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id="analytics_platform",
                        resource_id=rid,
                        captured_at=ts,
                        matched_identity=ident,
                        category="ANALYTICS_PROFILE",
                        status_or_state="present"
                    ))

    def _parse_txt(self, fid: str, path: Path, captured_at: str):
        with open(path, mode="r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                parts = [p.strip() for p in line[2:].split("|")]
                if len(parts) >= 6:
                    ts, sys_id, rid, cat, status, ident = parts[:6]
                    state_type = "present"
                    if status == "NOT_FOUND":
                        state_type = "absent"
                    elif status == "ANONYMIZED":
                        state_type = "anonymized"
                    elif status == "IDENTIFIABLE" or status == "EXPOSED_PII":
                        state_type = "exposed_pii"
                    elif status == "RETAINED":
                        state_type = "retained"
                    elif status == "ACTIVE":
                        state_type = "data_flow_active" if cat == "DATA_FLOW" else "restore_risk"
                    elif status == "BLOCKED":
                        state_type = "restore_blocked"
                    elif status == "DISABLED":
                        state_type = "data_flow_disabled"

                    self._add_fact(EvidenceFact(
                        file_id=fid,
                        system_id=sys_id,
                        resource_id=rid,
                        captured_at=ts or captured_at,
                        matched_identity=ident.lower(),
                        category=cat,
                        status_or_state=state_type
                    ))

    def _parse_pdf(self, fid: str, path: Path, captured_at: str):
        try:
            import pypdf
            reader = pypdf.PdfReader(path)
            text = ""
            for p in reader.pages:
                text += p.extract_text() + "\n"

            m_supp = re.search(r"support_\d+", text)
            m_email = re.search(r"([a-zA-Z0-9_\.\-]+@[a-zA-Z0-9_\.\-]+\.[a-zA-Z0-9_\-]+)", text)
            if m_supp and m_email:
                rid = m_supp.group(0)
                email = m_email.group(1).lower()
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="support_platform",
                    resource_id=rid,
                    captured_at=captured_at,
                    matched_identity=email,
                    category="SUPPORT_ATTACHMENT",
                    status_or_state="present"
                ))

            m_audit = re.search(r"audit_record_\d+", text)
            m_user = re.search(r"user_\d+", text)
            if m_audit and m_user:
                self._add_fact(EvidenceFact(
                    file_id=fid,
                    system_id="security_service",
                    resource_id=m_audit.group(0),
                    captured_at=captured_at,
                    matched_identity=m_user.group(0),
                    category="SECURITY_AUDIT_LOG",
                    status_or_state="retained"
                ))
        except Exception:
            pass
