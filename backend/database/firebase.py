"""
ScamShield - Firebase Firestore Database Integration
Provides a clean abstraction for saving reports, retrieving community reports,
and computing threat statistics.
Includes automatic, resilient local JSON fallback when Firebase credentials are not provided.
"""

import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from ..config import Config

logger = logging.getLogger(__name__)

# Sample seed data for initial awareness display if storage is empty
DEFAULT_SEED_REPORTS = [
    {
        "id": "seed-1",
        "message": "Congratulations! You won Rs 1,00,000 lottery. Click bit.ly/prize99 to claim.",
        "category": "Prize/Lottery",
        "platform": "SMS",
        "sender": "+91 98765 43210",
        "url": "http://bit.ly/prize99",
        "description": "Received random SMS claiming I won a contest I never entered.",
        "anonymous": True,
        "created_at": "2026-03-01T10:30:00Z"
    },
    {
        "id": "seed-2",
        "message": "Dear customer, your electricity power will be disconnected at 9:30 PM today due to unpaid bill. Call 9821033441 immediately.",
        "category": "Threat/Urgency",
        "platform": "SMS",
        "sender": "VM-ELECT",
        "url": "",
        "description": "Threatening electricity disconnection scam asking to call personal number.",
        "anonymous": True,
        "created_at": "2026-03-02T14:15:00Z"
    },
    {
        "id": "seed-3",
        "message": "Part time job: Earn 5000 daily by liking YouTube videos. Pay 500 registration fee to join.",
        "category": "Fake Job",
        "platform": "WhatsApp",
        "sender": "+1 (555) 234-5678",
        "url": "https://telegram.me/fakejobtask",
        "description": "Telegram task scam asking for joining fee.",
        "anonymous": False,
        "created_at": "2026-03-03T09:00:00Z"
    },
    {
        "id": "seed-4",
        "message": "Your SBI account has been blocked due to pending KYC. Update immediately at http://192.168.1.5/sbi",
        "category": "KYC",
        "platform": "WhatsApp",
        "sender": "Unknown Number",
        "url": "http://192.168.1.5/sbi",
        "description": "Fake bank KYC update link hosted on an IP address.",
        "anonymous": True,
        "created_at": "2026-03-04T16:45:00Z"
    },
    {
        "id": "seed-5",
        "message": "Guaranteed 200% return in 48 hours with automated crypto mining pool. Invest minimum $100.",
        "category": "Investment",
        "platform": "Social Media",
        "sender": "@crypto_wizard_official",
        "url": "https://fast-crypto-wealth.xyz",
        "description": "Instagram DM offering doubled investment via crypto bot.",
        "anonymous": True,
        "created_at": "2026-03-05T18:20:00Z"
    },
    {
        "id": "seed-6",
        "message": "Order confirmed: iPhone 15 Pro for Rs 9,999 only. Limited flash sale. Pay advance to book.",
        "category": "Shopping",
        "platform": "Social Media",
        "sender": "FlashDealsIndia",
        "url": "http://flashdeal-offers.top",
        "description": "Fake shopping portal with unrealistic price discount.",
        "anonymous": True,
        "created_at": "2026-03-06T11:10:00Z"
    }
]


class DatabaseManager:
    """Firestore database adapter with local filesystem fallback."""

    def __init__(self):
        self.use_firebase = False
        self.firestore_client = None
        self.collection_name = Config.FIREBASE_COLLECTION_NAME
        self.local_file = Config.LOCAL_FALLBACK_FILE
        self._initialize_backend()

    def _initialize_backend(self):
        """Attempts to initialize Firebase Admin SDK. Fallbacks to local storage on error/absence."""
        cred_path = Config.FIREBASE_CREDENTIALS_PATH
        project_id = Config.FIREBASE_PROJECT_ID

        if cred_path and os.path.exists(cred_path):
            try:
                import firebase_admin
                from firebase_admin import credentials, firestore

                if not firebase_admin._apps:
                    cred = credentials.Certificate(cred_path)
                    firebase_admin.initialize_app(cred, {"projectId": project_id} if project_id else None)
                
                self.firestore_client = firestore.client()
                self.use_firebase = True
                logger.info("Firebase Firestore initialized successfully using service account.")
                return
            except Exception as e:
                logger.warning(f"Firebase initialization failed ({e}). Reverting to local fallback store.")

        # Ensure local store is seeded
        self._ensure_local_store()

    def _ensure_local_store(self):
        """Initialize local JSON store if it does not exist."""
        if not self.local_file.exists():
            try:
                with open(self.local_file, "w", encoding="utf-8") as f:
                    json.dump(DEFAULT_SEED_REPORTS, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to create local data store: {e}")

    def save_report(self, report_data: dict) -> dict:
        """Save a user-submitted scam report."""
        record = {
            "message": report_data.get("message", "").strip(),
            "category": report_data.get("category", "Other"),
            "platform": report_data.get("platform", "Other"),
            "sender": report_data.get("sender", "").strip(),
            "url": report_data.get("url", "").strip(),
            "description": report_data.get("description", "").strip(),
            "anonymous": bool(report_data.get("anonymous", True)),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        if self.use_firebase and self.firestore_client:
            try:
                doc_ref = self.firestore_client.collection(self.collection_name).document()
                record["id"] = doc_ref.id
                doc_ref.set(record)
                return {"success": True, "id": doc_ref.id, "backend": "firebase"}
            except Exception as e:
                logger.error(f"Firestore save error: {e}. Falling back to local storage.")

        # Local storage fallback
        try:
            records = []
            if self.local_file.exists():
                with open(self.local_file, "r", encoding="utf-8") as f:
                    try:
                        records = json.load(f)
                    except json.JSONDecodeError:
                        records = []

            record["id"] = f"rep-{int(datetime.now(timezone.utc).timestamp() * 1000)}"
            records.insert(0, record)  # Most recent first

            with open(self.local_file, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)

            return {"success": True, "id": record["id"], "backend": "local"}
        except Exception as e:
            logger.error(f"Local storage save failed: {e}")
            raise RuntimeError("Database storage error. Could not persist report.")

    def get_reports(self, limit: int = 50) -> list:
        """Retrieve recent reports with sensitive fields masked."""
        limit = min(limit, Config.MAX_REPORTS_PER_QUERY)

        if self.use_firebase and self.firestore_client:
            try:
                docs = (
                    self.firestore_client.collection(self.collection_name)
                    .order_by("created_at", direction="DESCENDING")
                    .limit(limit)
                    .stream()
                )
                results = []
                for d in docs:
                    data = d.to_dict()
                    data["id"] = d.id
                    results.append(self._sanitize_public_report(data))
                return results
            except Exception as e:
                logger.warning(f"Firestore retrieval error: {e}. Reading from local storage.")

        # Local fallback retrieval
        try:
            if self.local_file.exists():
                with open(self.local_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return [self._sanitize_public_report(r) for r in data[:limit]]
        except Exception as e:
            logger.error(f"Error reading local reports: {e}")

        return [self._sanitize_public_report(r) for r in DEFAULT_SEED_REPORTS[:limit]]

    def get_statistics(self) -> dict:
        """Compute aggregated awareness statistics without exposing private details."""
        reports = self.get_reports(limit=Config.MAX_REPORTS_PER_QUERY)
        total_count = len(reports)

        category_counts = {}
        platform_counts = {}

        for r in reports:
            cat = r.get("category", "Other")
            plat = r.get("platform", "Other")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            platform_counts[plat] = platform_counts.get(plat, 0) + 1

        top_category = max(category_counts, key=category_counts.get) if category_counts else "None"
        top_platform = max(platform_counts, key=platform_counts.get) if platform_counts else "None"

        return {
            "total_reports": total_count,
            "top_category": top_category,
            "top_platform": top_platform,
            "categories_breakdown": category_counts,
            "platforms_breakdown": platform_counts,
            "recent_reports": reports[:5],
            "database_mode": "firebase" if self.use_firebase else "local_resilient",
        }

    @staticmethod
    def _sanitize_public_report(report: dict) -> dict:
        """Never expose reporter identity or full sender data if marked anonymous."""
        sanitized = dict(report)
        if sanitized.get("anonymous", True):
            sanitized["sender"] = "Anonymous Sender" if sanitized.get("sender") else ""
        return sanitized


db_manager = DatabaseManager()
