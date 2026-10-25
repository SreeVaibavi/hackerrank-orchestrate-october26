"""
GhostTrace AI — Sensitive-Field Exposure Scanner
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Scans non-primary artifacts and logs for residual exposed PII, prioritizing risk with safe masking.
"""
import re
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class ExposureFinding:
    system_id: str
    resource_id: str
    field_category: str
    masked_preview: str
    sensitivity_tier: str
    exposure_risk: str
    recommended_action: str

class SensitiveFieldExposureScanner:
    def __init__(self):
        pass

    def scan_record_details(self, system_id: str, resource_id: str, details: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []

        # Check for Email
        email = details.get("email") or details.get("requester_email") or details.get("owner_email") or details.get("customer_email")
        if email and isinstance(email, str) and "@" in email:
            parts = email.split("@")
            masked = f"{parts[0][:2]}***@{parts[1]}"
            findings.append(ExposureFinding(
                system_id=system_id,
                resource_id=resource_id,
                field_category="DIRECT_EMAIL",
                masked_preview=masked,
                sensitivity_tier="CRITICAL",
                exposure_risk="HIGH",
                recommended_action="REDACT or PURGE email string from secondary data store."
            ))

        # Check for Phone Number
        phone = details.get("phone") or details.get("requester_phone")
        if phone and isinstance(phone, str) and len(phone) > 5:
            masked = f"{phone[:4]} **** {phone[-2:]}"
            findings.append(ExposureFinding(
                system_id=system_id,
                resource_id=resource_id,
                field_category="TELEPHONE_NUMBER",
                masked_preview=masked,
                sensitivity_tier="HIGH",
                exposure_risk="MEDIUM",
                recommended_action="Mask phone digits; unlink customer telephone index."
            ))

        # Check for Full Name
        name = details.get("full_name") or details.get("requester_name") or details.get("name")
        if name and isinstance(name, str) and len(name) > 1:
            masked = f"{name[0]}*** {name.split()[-1][0]}***" if len(name.split()) > 1 else f"{name[0]}***"
            findings.append(ExposureFinding(
                system_id=system_id,
                resource_id=resource_id,
                field_category="CUSTOMER_NAME",
                masked_preview=masked,
                sensitivity_tier="HIGH",
                exposure_risk="MEDIUM",
                recommended_action="Redact full name from conversational record."
            ))

        # Check for Email Hash
        email_hash = details.get("email_hash")
        if email_hash and isinstance(email_hash, str) and len(email_hash) == 64:
            masked = f"sha256:{email_hash[:6]}...{email_hash[-6:]}"
            findings.append(ExposureFinding(
                system_id=system_id,
                resource_id=resource_id,
                field_category="PSEUDONYMOUS_HASH",
                masked_preview=masked,
                sensitivity_tier="MEDIUM",
                exposure_risk="LOW",
                recommended_action="Purge hash lookup key to prevent rainbow-table correlation."
            ))

        return [f.__dict__ for f in findings]

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
        phones = re.findall(r'\+?\d[\d -]{8,}\d', text)

        for em in emails:
            parts = em.split("@")
            masked = f"{parts[0][:2]}***@{parts[1]}"
            findings.append({
                "field_category": "DIRECT_EMAIL",
                "masked_preview": masked,
                "sensitivity_tier": "CRITICAL"
            })
        for ph in phones:
            masked = f"{ph[:4]} **** {ph[-2:]}"
            findings.append({
                "field_category": "TELEPHONE_NUMBER",
                "masked_preview": masked,
                "sensitivity_tier": "HIGH"
            })
        return findings
