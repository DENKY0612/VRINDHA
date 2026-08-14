"""CISA Known Exploited Vulnerabilities collector."""
from __future__ import annotations

from typing import Optional

from .base import CollectedItem, CollectionBatch, FeedCollector, FeedError, fetch_json


class CISAKEVCollector(FeedCollector):
    name = "cisa_kev"
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def collect(self, cursor: Optional[str] = None) -> CollectionBatch:
        data = await fetch_json(self.URL, allowed_hosts=["www.cisa.gov"], timeout=self.timeout, max_bytes=20_000_000)
        if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
            raise FeedError("CISA KEV schema is invalid")
        items = []
        for record in data["vulnerabilities"][:20_000]:
            if not isinstance(record, dict) or not record.get("cveID"):
                continue
            items.append(CollectedItem("vulnerability", {
                "cve_id": record["cveID"], "kev": True, "vendor": record.get("vendorProject"),
                "product": record.get("product"), "name": record.get("vulnerabilityName"),
                "description": record.get("shortDescription", ""), "action": record.get("requiredAction", ""),
                "date_added": record.get("dateAdded"), "kev_due_date": record.get("dueDate"),
                "ransomware_use": str(record.get("knownRansomwareCampaignUse", "")).lower() == "known",
                "notes": record.get("notes", ""), "affected_products": [f"{record.get('vendorProject','')} {record.get('product','')}".strip()],
                "references": [record.get("notes")] if str(record.get("notes", "")).startswith("http") else [],
                "source_url": self.URL,
            }))
        return CollectionBatch(items, cursor=str(data.get("dateReleased") or data.get("catalogVersion") or ""),
                               metadata={"catalog_version": data.get("catalogVersion"), "title": data.get("title")})
