"""
GhostTrace AI — Policy-Aware Action Advisor
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Guides operations teams on the 5 distinct data protection treatments:
DELETE, REDACT, ANONYMIZE, RETAIN, and BLOCK_RESTORE.
"""
from typing import Dict, List, Any

POLICY_TAXONOMY = {
    "DELETE": {
        "title": "Permanent Erasure (DELETE)",
        "definition": "Complete physical removal of data files, records, search indexes, or export bundles.",
        "northstar_examples": [
            "Customer account profile in customer_profiles primary table",
            "Customer entry in customer_directory_v3 search index",
            "Direct customer support attachment PDF (e.g. proof of address, ID photo)",
            "Downloadable GDPR customer export ZIP archive in object storage"
        ],
        "permitted_identifiers_remaining": "None. All records and pointers destroyed."
    },
    "REDACT": {
        "title": "Identifying Field Masking (REDACT)",
        "definition": "Preservation of business or conversational record structure while removing prohibited direct PII.",
        "northstar_examples": [
            "Support conversation ticket transcripts (preserves agent response and order issue, masks customer email/phone)",
            "Account tombstones (preserves internal user_id for referential integrity, purges name/email/phone/hash)",
            "Transactional email delivery logs (strips recipient email address)"
        ],
        "permitted_identifiers_remaining": "Pseudonymous reference or stable internal user_id only."
    },
    "ANONYMIZE": {
        "title": "Irreversible De-identification (ANONYMIZE)",
        "definition": "Transforming individual event records so they can never be linked back to the natural person.",
        "northstar_examples": [
            "Behavioral analytics profiles and browsing events (cohorts preserved for aggregate statistics)",
            "Product telemetry and purchase conversion funnel metrics"
        ],
        "permitted_identifiers_remaining": "Aggregate cohort label (e.g. 'home_lifestyle', 'mobile_shopper') only."
    },
    "RETAIN": {
        "title": "Authorized Legal Retention (RETAIN)",
        "definition": "Preserving designated audit and tax records under statutory retention obligations.",
        "northstar_examples": [
            "Security audit journal records (CJX-2026 compliance journal, retention until 2031-2034)",
            "Disputed order invoices and tax records register (disputed payments retained for financial audit)"
        ],
        "permitted_identifiers_remaining": "Statutory audit record and transaction metadata preserved."
    },
    "BLOCK_RESTORE": {
        "title": "Restore Path Quarantine (BLOCK_RESTORE)",
        "definition": "Blocking point-in-time disaster-recovery snapshots from reintroducing deleted records.",
        "northstar_examples": [
            "Revoking KMS customer decryption keys for cold archive segments",
            "Configuring restore filter masks in backup_service before spinning up recovery replicas"
        ],
        "permitted_identifiers_remaining": "Snapshot preserved in cold storage with restore path blocked."
    }
}

class PolicyActionAdvisor:
    def __init__(self):
        pass

    def get_advice_for_category(self, data_category: str) -> Dict[str, Any]:
        cat_upper = data_category.strip().upper()
        if "PROFILE" in cat_upper or "EXPORT" in cat_upper or "SEARCH" in cat_upper or "ATTACHMENT" in cat_upper:
            return POLICY_TAXONOMY["DELETE"]
        elif "SUPPORT_MESSAGE" in cat_upper or "TOMBSTONE" in cat_upper or "EMAIL_LOG" in cat_upper:
            return POLICY_TAXONOMY["REDACT"]
        elif "ANALYTICS" in cat_upper or "TELEMETRY" in cat_upper:
            return POLICY_TAXONOMY["ANONYMIZE"]
        elif "SECURITY" in cat_upper or "LEGAL" in cat_upper:
            return POLICY_TAXONOMY["RETAIN"]
        elif "BACKUP" in cat_upper or "ARCHIVE" in cat_upper:
            return POLICY_TAXONOMY["BLOCK_RESTORE"]
        return POLICY_TAXONOMY["DELETE"]

    def get_full_taxonomy(self) -> Dict[str, Any]:
        return POLICY_TAXONOMY
