"""NVD CVE 2.0 collector (disabled unless configured)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode
import os

from .base import CollectedItem, CollectionBatch, FeedCollector, FeedError, fetch_json


class NVDCollector(FeedCollector):
    name = "nvd"
    BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def collect(self, cursor: Optional[str] = None) -> CollectionBatch:
        end = datetime.now(timezone.utc)
        start = datetime.fromisoformat(cursor) if cursor else end - timedelta(hours=2)
        headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.getenv("NVD_API_KEY") else {}
        wrappers = []
        total_results = 0
        for page in range(10):
            params = urlencode({"lastModStartDate": start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                                "lastModEndDate": end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                                "resultsPerPage": 2000, "startIndex": page * 2000})
            data = await fetch_json(f"{self.BASE}?{params}", allowed_hosts=["services.nvd.nist.gov"], timeout=self.timeout, headers=headers, max_bytes=25_000_000)
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise FeedError("NVD schema is invalid")
            wrappers.extend(data["vulnerabilities"])
            total_results = int(data.get("totalResults", len(wrappers)))
            if len(wrappers) >= total_results or not data["vulnerabilities"]:
                break
        items = []
        for wrapper in wrappers:
            cve = wrapper.get("cve", {}) if isinstance(wrapper, dict) else {}
            cve_id = cve.get("id")
            if not cve_id:
                continue
            descriptions = cve.get("descriptions") or []
            description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "")
            metrics = cve.get("metrics") or {}
            cvss = None
            for name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(name):
                    cvss = metrics[name][0].get("cvssData", {}).get("baseScore")
                    break
            refs = [entry.get("url") for entry in cve.get("references", []) if entry.get("url")]
            products = []
            for configuration in cve.get("configurations", []):
                for node in configuration.get("nodes", []):
                    products.extend(match.get("criteria") for match in node.get("cpeMatch", []) if match.get("vulnerable") and match.get("criteria"))
            items.append(CollectedItem("vulnerability", {"cve_id": cve_id, "cvss": cvss, "description": description,
                "published": cve.get("published"), "modified": cve.get("lastModified"), "references": refs[:100],
                "affected_products": products[:500], "source_url": self.BASE}))
        return CollectionBatch(items, cursor=end.isoformat(), metadata={"total_results": total_results, "retrieved": len(wrappers), "truncated": len(wrappers) < total_results})
