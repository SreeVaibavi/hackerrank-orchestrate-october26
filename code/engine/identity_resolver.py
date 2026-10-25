"""
GhostTrace AI — Identity Resolution Engine
Domain: Northstar Shop E-Commerce Data Deletion Assurance
Resolves current and historical customer identifiers across audit histories.
"""
import csv
import hashlib
from typing import Dict, Optional, Set
from pathlib import Path
from .models import UserIdentity

class IdentityResolver:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.users_by_id: Dict[str, UserIdentity] = {}
        self.email_to_id: Dict[str, str] = {}
        self.hash_to_id: Dict[str, str] = {}
        self._load_identities()
        self._load_audit_log()
        self._compute_all_hashes()

    def _compute_all_hashes(self):
        for uid, user in self.users_by_id.items():
            for em in user.all_emails:
                h = hashlib.sha256(em.encode("utf-8")).hexdigest()
                self.hash_to_id[h] = uid

    def _load_identities(self):
        identities_file = self.dataset_dir / "user_identities.csv"
        if not identities_file.exists():
            return

        with open(identities_file, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                name = row.get("name", "").strip() or None
                email = row.get("email", "").strip() or None
                phone = row.get("phone", "").strip() or None
                email_hash = row.get("email_hash", "").strip() or None
                updated_at = row.get("updated_at", "").strip() or None

                identity = UserIdentity(
                    user_id=uid,
                    name=name,
                    email=email,
                    phone=phone,
                    email_hash=email_hash,
                    updated_at=updated_at
                )
                if email:
                    identity.all_emails.add(email.lower())
                    self.email_to_id[email.lower()] = uid
                if phone:
                    identity.all_phones.add(phone)
                if name:
                    identity.all_names.add(name)

                self.users_by_id[uid] = identity

    def _load_audit_log(self):
        audit_file = self.dataset_dir / "user_audit_log.csv"
        if not audit_file.exists():
            return

        with open(audit_file, mode="r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row["user_id"].strip()
                field_name = row.get("field_name", "").strip()
                old_val = row.get("old_value", "").strip()
                new_val = row.get("new_value", "").strip()

                if uid not in self.users_by_id:
                    self.users_by_id[uid] = UserIdentity(user_id=uid)

                user = self.users_by_id[uid]
                if field_name == "email":
                    if old_val:
                        user.all_emails.add(old_val.lower())
                        self.email_to_id[old_val.lower()] = uid
                    if new_val:
                        user.all_emails.add(new_val.lower())
                        self.email_to_id[new_val.lower()] = uid
                elif field_name == "phone":
                    if old_val:
                        user.all_phones.add(old_val)
                    if new_val:
                        user.all_phones.add(new_val)
                elif field_name == "name":
                    if old_val:
                        user.all_names.add(old_val)
                    if new_val:
                        user.all_names.add(new_val)

    def resolve_by_email(self, email: str) -> Optional[UserIdentity]:
        if not email:
            return None
        norm_email = email.strip().lower()
        uid = self.email_to_id.get(norm_email)
        if uid and uid in self.users_by_id:
            return self.users_by_id[uid]
        return None

    def resolve_by_id(self, user_id: str) -> Optional[UserIdentity]:
        return self.users_by_id.get(user_id.strip())
