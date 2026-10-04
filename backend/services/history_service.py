"""
PhishGuard AI - History Service
In-memory scan history with optional lightweight persistence.

Stores scan records for the current application session.
No credentials, cookies, passwords, or personal data are stored.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional


class HistoryService:
    """In-memory store for URL scan history."""

    def __init__(self):
        self._records: list[dict] = []

    def add_record(
        self,
        url: str,
        prediction: str,
        confidence: float,
        risk_score: int,
        risk_level: str,
    ) -> dict:
        """
        Add a scan result to history.

        Stored fields:
            id, url, prediction, confidence, risk_score, risk_level, timestamp
        """
        record = {
            "id": str(uuid.uuid4()),
            "url": url,
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._records.append(record)
        return record

    def get_all(self) -> list[dict]:
        """Return all history records, newest first."""
        return list(reversed(self._records))

    def clear(self) -> int:
        """Clear all history. Returns the count of cleared records."""
        count = len(self._records)
        self._records.clear()
        return count

    def get_statistics(self) -> dict:
        """
        Compute summary statistics for the dashboard.

        Returns:
            dict with total, phishing_count, legitimate_count
        """
        total = len(self._records)
        phishing_count = sum(1 for r in self._records if r["prediction"] == "PHISHING")
        legitimate_count = total - phishing_count

        # Last 10 records for the activity chart (oldest to newest)
        recent = list(self._records[-10:])
        activity = [
            {
                "timestamp": r["timestamp"],
                "prediction": r["prediction"],
                "risk_score": r["risk_score"],
            }
            for r in recent
        ]

        return {
            "total": total,
            "phishing_count": phishing_count,
            "legitimate_count": legitimate_count,
            "recent_activity": activity,
        }


# Module-level singleton used across the FastAPI app lifetime
history_service = HistoryService()
