"""Create explicit actor/campaign/malware/IOC relationships from evidence."""
from __future__ import annotations

from typing import Any, Dict, List
from uuid import NAMESPACE_URL, uuid5

from ..database import ThreatDatabase


class ThreatCorrelator:
    def __init__(self, database: ThreatDatabase):
        self.database = database

    @staticmethod
    def _id(source: str, relation: str, target: str) -> str:
        return f"relationship--{uuid5(NAMESPACE_URL, f'vrindha-ti:{source}|{relation}|{target}')}"

    def map_indicator(self, indicator: Dict[str, Any]) -> List[Dict[str, Any]]:
        source = indicator["indicator_id"]
        confidence = float(indicator.get("confidence", 0.5))
        created = []
        mappings = (
            ("indicates", "malware", indicator.get("malware_family", [])),
            ("attributed-to", "threat-actor", indicator.get("threat_actor", [])),
            ("related-to", "campaign", indicator.get("campaign", [])),
            ("uses", "attack-pattern", indicator.get("mitre_attack_ids", [])),
            ("related-to", "vulnerability", indicator.get("related_cves", [])),
        )
        for relation, target_type, values in mappings:
            for value in values:
                target = str(value)
                if "--" not in target:
                    target = f"{target_type}--{uuid5(NAMESPACE_URL, f'vrindha-ti:{target_type}:{target}')}"
                relationship_id = self._id(source, relation, target)
                evidence = [{"indicator_id": source, "field": target_type, "value": value}]
                self.database.add_relationship(relationship_id, source, relation, target, confidence, evidence)
                created.append({"relationship_id": relationship_id, "source_ref": source, "relationship_type": relation,
                                "target_ref": target, "confidence": confidence, "evidence": evidence})
        for related in indicator.get("related_indicators", []):
            relationship_id = self._id(source, "related-to", related)
            self.database.add_relationship(relationship_id, source, "related-to", related, confidence, [{"source": "indicator related_indicators"}])
            created.append({"relationship_id": relationship_id, "source_ref": source, "relationship_type": "related-to", "target_ref": related})
        return created
