"""SQLite persistence for Vrin_TI.

TI owns this database independently from the existing SOC database.  WAL,
foreign keys, bounded raw payloads, deterministic IOC uniqueness, sightings,
provenance, durable events and the transport outbox are all local-first.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, Iterator, List, Optional
import json
import sqlite3

from .models import FeedStatus, IntelligenceEvent, Sighting, ThreatIndicator, utcnow
from .normalization import canonical_type, deterministic_indicator_id, normalize_indicator

SCHEMA_VERSION = 1


def _iso(value: datetime | str | None) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _json(value: Any, limit: int = 262_144) -> str:
    encoded = json.dumps(value, default=str, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > limit:
        return json.dumps({"truncated": True, "sha256_note": "payload omitted because it exceeded retention limit"})
    return encoded


def _loads(value: Optional[str], default: Any) -> Any:
    if not value:
        return default
    try:
        parsed = json.loads(value)
        return parsed
    except json.JSONDecodeError:
        return default


class ThreatDatabase:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=15000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        statements = [
            """CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY, value TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_indicators (
                indicator_id TEXT PRIMARY KEY,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                normalized_value TEXT NOT NULL,
                source TEXT NOT NULL,
                source_url TEXT,
                source_reliability REAL NOT NULL CHECK(source_reliability BETWEEN 0 AND 1),
                confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
                threat_score REAL NOT NULL CHECK(threat_score BETWEEN 0 AND 100),
                severity TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                expires_at TEXT,
                ttl INTEGER,
                tags_json TEXT NOT NULL,
                malware_json TEXT NOT NULL,
                actors_json TEXT NOT NULL,
                campaigns_json TEXT NOT NULL,
                mitre_json TEXT NOT NULL,
                cves_json TEXT NOT NULL,
                related_json TEXT NOT NULL,
                description TEXT NOT NULL,
                false_positive_probability REAL NOT NULL CHECK(false_positive_probability BETWEEN 0 AND 1),
                verification_status TEXT NOT NULL,
                active INTEGER NOT NULL CHECK(active IN (0,1)),
                revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
                raw_data_json TEXT NOT NULL,
                UNIQUE(indicator_type, normalized_value)
            )""",
            """CREATE TABLE IF NOT EXISTS threat_sources (
                indicator_id TEXT NOT NULL REFERENCES threat_indicators(indicator_id) ON DELETE CASCADE,
                source_name TEXT NOT NULL,
                source_url TEXT,
                reliability REAL NOT NULL CHECK(reliability BETWEEN 0 AND 1),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                observations INTEGER NOT NULL DEFAULT 1,
                correct_observations INTEGER NOT NULL DEFAULT 0,
                false_positives INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(indicator_id, source_name)
            )""",
            """CREATE TABLE IF NOT EXISTS confidence_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_id TEXT NOT NULL REFERENCES threat_indicators(indicator_id) ON DELETE CASCADE,
                timestamp TEXT NOT NULL,
                confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
                reason TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_sightings (
                sighting_id TEXT PRIMARY KEY,
                indicator_id TEXT NOT NULL REFERENCES threat_indicators(indicator_id) ON DELETE CASCADE,
                asset_id TEXT,
                asset_ip TEXT,
                asset_hostname TEXT,
                asset_criticality REAL,
                asset_exposed INTEGER,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
                context_json TEXT NOT NULL,
                correlation_id TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_entities (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                external_ids_json TEXT NOT NULL DEFAULT '[]',
                data_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_relationships (
                relationship_id TEXT PRIMARY KEY,
                source_ref TEXT NOT NULL,
                relationship_type TEXT NOT NULL,
                target_ref TEXT NOT NULL,
                confidence REAL NOT NULL CHECK(confidence BETWEEN 0 AND 1),
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                UNIQUE(source_ref, relationship_type, target_ref)
            )""",
            """CREATE TABLE IF NOT EXISTS threat_vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                cvss REAL,
                affected_products_json TEXT NOT NULL,
                references_json TEXT NOT NULL,
                published TEXT,
                modified TEXT,
                kev INTEGER NOT NULL DEFAULT 0,
                kev_due_date TEXT,
                ransomware_use INTEGER NOT NULL DEFAULT 0,
                data_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_reports (
                report_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                created_at TEXT NOT NULL,
                report_json TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_feed_status (
                name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL,
                interval_seconds INTEGER NOT NULL,
                timeout_seconds INTEGER NOT NULL,
                retry_count INTEGER NOT NULL,
                reliability REAL NOT NULL,
                last_success TEXT,
                last_failure TEXT,
                status TEXT NOT NULL,
                last_error TEXT NOT NULL DEFAULT '',
                items_ingested INTEGER NOT NULL DEFAULT 0,
                cursor TEXT
            )""",
            """CREATE TABLE IF NOT EXISTS threat_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                processed_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS threat_correlations (
                correlation_id TEXT PRIMARY KEY,
                rule_name TEXT NOT NULL,
                indicator_id TEXT,
                asset_id TEXT,
                score REAL NOT NULL,
                severity TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )""",
            """CREATE TABLE IF NOT EXISTS transport_queue (
                queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                direction TEXT NOT NULL CHECK(direction IN ('inbound','outbound')),
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0,
                available_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                delivered_at TEXT,
                last_error TEXT,
                UNIQUE(event_id, direction)
            )""",
            """CREATE TABLE IF NOT EXISTS audit_log (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                outcome TEXT NOT NULL,
                correlation_id TEXT,
                detail_json TEXT NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS idx_indicator_lookup ON threat_indicators(indicator_type, normalized_value)",
            "CREATE INDEX IF NOT EXISTS idx_indicator_state ON threat_indicators(active, expires_at, threat_score DESC)",
            "CREATE INDEX IF NOT EXISTS idx_indicator_updated ON threat_indicators(updated_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sightings_indicator_time ON threat_sightings(indicator_id, timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sightings_asset_time ON threat_sightings(asset_id, timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_relationship_source ON threat_relationships(source_ref, relationship_type)",
            "CREATE INDEX IF NOT EXISTS idx_relationship_target ON threat_relationships(target_ref, relationship_type)",
            "CREATE INDEX IF NOT EXISTS idx_events_correlation ON threat_events(correlation_id, timestamp DESC)",
            "CREATE INDEX IF NOT EXISTS idx_queue_pending ON transport_queue(status, available_at)",
            "CREATE INDEX IF NOT EXISTS idx_correlation_asset ON threat_correlations(asset_id, created_at DESC)",
        ]
        with self.transaction() as connection:
            for statement in statements:
                connection.execute(statement)
            connection.execute("INSERT OR REPLACE INTO schema_meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))

    def upsert_indicator(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        kind = canonical_type(indicator.indicator_type).value
        normalized = normalize_indicator(kind, indicator.indicator_value)
        indicator_id = indicator.indicator_id or deterministic_indicator_id(kind, normalized)
        now = utcnow()
        expires_at = indicator.expires_at
        if expires_at is None and indicator.ttl:
            expires_at = indicator.last_seen + timedelta(seconds=indicator.ttl)
        with self._lock, self.transaction() as connection:
            existing = connection.execute("SELECT * FROM threat_indicators WHERE indicator_type=? AND normalized_value=?", (kind, normalized)).fetchone()
            created = existing is None
            if existing:
                indicator_id = existing["indicator_id"]
                indicator.first_seen = min(datetime.fromisoformat(existing["first_seen"]), indicator.first_seen)
                indicator.last_seen = max(datetime.fromisoformat(existing["last_seen"]), indicator.last_seen)
                indicator.created_at = datetime.fromisoformat(existing["created_at"])
                indicator.tags = sorted(set(_loads(existing["tags_json"], []) + indicator.tags))
                indicator.malware_family = sorted(set(_loads(existing["malware_json"], []) + indicator.malware_family))
                indicator.threat_actor = sorted(set(_loads(existing["actors_json"], []) + indicator.threat_actor))
                indicator.campaign = sorted(set(_loads(existing["campaigns_json"], []) + indicator.campaign))
                indicator.mitre_attack_ids = sorted(set(_loads(existing["mitre_json"], []) + indicator.mitre_attack_ids))
                indicator.related_cves = sorted(set(_loads(existing["cves_json"], []) + indicator.related_cves))
                indicator.related_indicators = sorted(set(_loads(existing["related_json"], []) + indicator.related_indicators))
                indicator.confidence = max(float(existing["confidence"]), indicator.confidence)
                indicator.threat_score = max(float(existing["threat_score"]), indicator.threat_score)
                if not indicator.description:
                    indicator.description = existing["description"]
            indicator.updated_at = now
            values = (
                indicator_id, kind, indicator.indicator_value, normalized, indicator.source, indicator.source_url,
                indicator.source_reliability, indicator.confidence, indicator.threat_score, indicator.severity,
                _iso(indicator.first_seen), _iso(indicator.last_seen), _iso(indicator.created_at), _iso(now), _iso(expires_at), indicator.ttl,
                _json(indicator.tags), _json(indicator.malware_family), _json(indicator.threat_actor), _json(indicator.campaign),
                _json(indicator.mitre_attack_ids), _json(indicator.related_cves), _json(indicator.related_indicators), indicator.description,
                indicator.false_positive_probability, indicator.verification_status, int(indicator.active), int(indicator.revoked), _json(indicator.raw_data),
            )
            connection.execute("""INSERT INTO threat_indicators (
                indicator_id, indicator_type, indicator_value, normalized_value, source, source_url,
                source_reliability, confidence, threat_score, severity, first_seen, last_seen, created_at,
                updated_at, expires_at, ttl, tags_json, malware_json, actors_json, campaigns_json,
                mitre_json, cves_json, related_json, description, false_positive_probability,
                verification_status, active, revoked, raw_data_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(indicator_id) DO UPDATE SET
                indicator_value=excluded.indicator_value, source=excluded.source, source_url=excluded.source_url,
                source_reliability=excluded.source_reliability, confidence=excluded.confidence,
                threat_score=excluded.threat_score, severity=excluded.severity, first_seen=excluded.first_seen,
                last_seen=excluded.last_seen, updated_at=excluded.updated_at, expires_at=excluded.expires_at,
                ttl=excluded.ttl, tags_json=excluded.tags_json, malware_json=excluded.malware_json,
                actors_json=excluded.actors_json, campaigns_json=excluded.campaigns_json,
                mitre_json=excluded.mitre_json, cves_json=excluded.cves_json, related_json=excluded.related_json,
                description=excluded.description, false_positive_probability=excluded.false_positive_probability,
                verification_status=excluded.verification_status, active=excluded.active, revoked=excluded.revoked,
                raw_data_json=excluded.raw_data_json""", values)
            connection.execute("""INSERT INTO threat_sources(
                indicator_id, source_name, source_url, reliability, first_seen, last_seen, observations
            ) VALUES(?,?,?,?,?,?,1)
            ON CONFLICT(indicator_id, source_name) DO UPDATE SET
                source_url=COALESCE(excluded.source_url, threat_sources.source_url),
                reliability=excluded.reliability, last_seen=excluded.last_seen,
                observations=threat_sources.observations+1""",
                (indicator_id, indicator.source, indicator.source_url, indicator.source_reliability, _iso(indicator.first_seen), _iso(indicator.last_seen)))
            for source_ref in indicator.sources:
                if source_ref.name == indicator.source:
                    continue
                connection.execute("""INSERT INTO threat_sources(
                    indicator_id, source_name, source_url, reliability, first_seen, last_seen, observations
                ) VALUES(?,?,?,?,?,?,1)
                ON CONFLICT(indicator_id, source_name) DO UPDATE SET
                    source_url=COALESCE(excluded.source_url, threat_sources.source_url),
                    reliability=excluded.reliability, last_seen=MAX(threat_sources.last_seen, excluded.last_seen),
                    observations=threat_sources.observations+1""",
                    (indicator_id, source_ref.name, source_ref.url, source_ref.reliability,
                     _iso(source_ref.first_seen), _iso(source_ref.last_seen)))
            connection.execute("INSERT INTO confidence_history(indicator_id,timestamp,confidence,reason) VALUES(?,?,?,?)",
                               (indicator_id, _iso(now), indicator.confidence, "created" if created else "source update"))
        for sighting in indicator.sightings:
            self.add_sighting(indicator_id, sighting)
        result = self.get_indicator_by_id(indicator_id)
        if result is None:
            raise RuntimeError("indicator write completed but could not be read back")
        result["created"] = created
        return result

    def _indicator_dict(self, row: sqlite3.Row, connection: sqlite3.Connection, include_sightings: bool = True) -> Dict[str, Any]:
        indicator_id = row["indicator_id"]
        source_rows = connection.execute("SELECT * FROM threat_sources WHERE indicator_id=? ORDER BY reliability DESC", (indicator_id,)).fetchall()
        confidence_rows = connection.execute("SELECT timestamp,confidence,reason FROM confidence_history WHERE indicator_id=? ORDER BY id DESC LIMIT 100", (indicator_id,)).fetchall()
        sightings: List[Dict[str, Any]] = []
        if include_sightings:
            sighting_rows = connection.execute("SELECT * FROM threat_sightings WHERE indicator_id=? ORDER BY timestamp DESC LIMIT 100", (indicator_id,)).fetchall()
            for item in sighting_rows:
                asset = None
                if item["asset_id"]:
                    asset = {"id": item["asset_id"], "ip": item["asset_ip"], "hostname": item["asset_hostname"],
                             "criticality": item["asset_criticality"] or 0.5, "exposed": bool(item["asset_exposed"])}
                sightings.append({"sighting_id": item["sighting_id"], "indicator_id": indicator_id, "asset": asset,
                                  "timestamp": item["timestamp"], "source": item["source"], "confidence": item["confidence"],
                                  "context": _loads(item["context_json"], {}), "correlation_id": item["correlation_id"]})
        return {
            "indicator_id": indicator_id, "indicator_type": row["indicator_type"], "indicator_value": row["indicator_value"],
            "normalized_value": row["normalized_value"], "source": row["source"], "source_url": row["source_url"],
            "source_reliability": row["source_reliability"], "confidence": row["confidence"], "threat_score": row["threat_score"],
            "severity": row["severity"], "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            "created_at": row["created_at"], "updated_at": row["updated_at"], "expires_at": row["expires_at"], "ttl": row["ttl"],
            "tags": _loads(row["tags_json"], []), "malware_family": _loads(row["malware_json"], []),
            "threat_actor": _loads(row["actors_json"], []), "campaign": _loads(row["campaigns_json"], []),
            "mitre_attack_ids": _loads(row["mitre_json"], []), "related_cves": _loads(row["cves_json"], []),
            "related_indicators": _loads(row["related_json"], []), "description": row["description"],
            "false_positive_probability": row["false_positive_probability"], "verification_status": row["verification_status"],
            "active": bool(row["active"]), "revoked": bool(row["revoked"]), "raw_data": _loads(row["raw_data_json"], {}),
            "sources": [{"name": item["source_name"], "url": item["source_url"], "reliability": item["reliability"],
                         "first_seen": item["first_seen"], "last_seen": item["last_seen"], "observations": item["observations"]} for item in source_rows],
            "confidence_history": [dict(item) for item in confidence_rows], "sightings": sightings,
        }

    def get_indicator(self, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
        kind = canonical_type(indicator_type).value
        normalized = normalize_indicator(kind, value)
        with self.read_connection() as connection:
            row = connection.execute("SELECT * FROM threat_indicators WHERE indicator_type=? AND normalized_value=?", (kind, normalized)).fetchone()
            return self._indicator_dict(row, connection) if row else None

    def get_indicator_by_id(self, indicator_id: str) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute("SELECT * FROM threat_indicators WHERE indicator_id=?", (indicator_id,)).fetchone()
            return self._indicator_dict(row, connection) if row else None

    def list_indicators(self, limit: int = 100, active: Optional[bool] = None, minimum_score: float = 0) -> List[Dict[str, Any]]:
        where = ["threat_score >= ?"]
        values: List[Any] = [minimum_score]
        if active is not None:
            where.append("active = ?")
            values.append(int(active))
        values.append(min(max(limit, 1), 1000))
        with self.read_connection() as connection:
            rows = connection.execute(f"SELECT * FROM threat_indicators WHERE {' AND '.join(where)} ORDER BY threat_score DESC, updated_at DESC LIMIT ?", values).fetchall()
            return [self._indicator_dict(row, connection, include_sightings=False) for row in rows]

    def mark_false_positive(self, indicator_id: str, probability: float = 1.0) -> bool:
        with self.transaction() as connection:
            cursor = connection.execute("UPDATE threat_indicators SET false_positive_probability=?, verification_status='false_positive', active=0, updated_at=? WHERE indicator_id=?",
                                        (max(0, min(1, probability)), _iso(utcnow()), indicator_id))
            return bool(cursor.rowcount)

    def record_source_outcome(self, source_name: str, correct: bool) -> int:
        """Apply auditable analyst feedback to a source's future reliability."""
        with self.transaction() as connection:
            rows = connection.execute("SELECT indicator_id,reliability,correct_observations,false_positives FROM threat_sources WHERE source_name=?", (source_name,)).fetchall()
            for row in rows:
                correct_count = int(row["correct_observations"]) + int(correct)
                false_count = int(row["false_positives"]) + int(not correct)
                historical = (correct_count + 1) / (correct_count + false_count + 2)
                adjusted = max(0.0, min(1.0, float(row["reliability"]) * 0.7 + historical * 0.3))
                connection.execute("UPDATE threat_sources SET reliability=?,correct_observations=?,false_positives=? WHERE indicator_id=? AND source_name=?",
                                   (adjusted, correct_count, false_count, row["indicator_id"], source_name))
            return len(rows)

    def expire_due(self, now: Optional[datetime] = None) -> int:
        timestamp = _iso(now or utcnow())
        with self.transaction() as connection:
            cursor = connection.execute("UPDATE threat_indicators SET active=0, verification_status='expired', updated_at=? WHERE active=1 AND expires_at IS NOT NULL AND expires_at<=?",
                                        (timestamp, timestamp))
            return cursor.rowcount

    def add_sighting(self, indicator_id: str, sighting: Sighting) -> Dict[str, Any]:
        asset = sighting.asset
        with self.transaction() as connection:
            connection.execute("""INSERT OR IGNORE INTO threat_sightings(
                sighting_id,indicator_id,asset_id,asset_ip,asset_hostname,asset_criticality,asset_exposed,
                timestamp,source,confidence,context_json,correlation_id
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (
                str(sighting.sighting_id), indicator_id, asset.id if asset else None, asset.ip if asset else None,
                asset.hostname if asset else None, asset.criticality if asset else None, int(asset.exposed) if asset else None,
                _iso(sighting.timestamp), sighting.source, sighting.confidence, _json(sighting.context, 65_536), str(sighting.correlation_id),
            ))
            connection.execute("UPDATE threat_indicators SET last_seen=MAX(last_seen,?), updated_at=? WHERE indicator_id=?",
                               (_iso(sighting.timestamp), _iso(utcnow()), indicator_id))
        return sighting.model_dump(mode="json")

    def list_sightings(self, limit: int = 100, indicator_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM threat_sightings"
        values: List[Any] = []
        if indicator_id:
            query += " WHERE indicator_id=?"
            values.append(indicator_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        values.append(min(max(limit, 1), 1000))
        with self.read_connection() as connection:
            return [{**dict(row), "context": _loads(row["context_json"], {})} for row in connection.execute(query, values).fetchall()]

    def save_event(self, event: IntelligenceEvent) -> bool:
        payload = event.model_dump(mode="json")
        with self.transaction() as connection:
            cursor = connection.execute("INSERT OR IGNORE INTO threat_events(event_id,event_type,timestamp,source,correlation_id,payload_json,processed_at) VALUES(?,?,?,?,?,?,?)",
                (str(event.event_id), event.event_type, _iso(event.timestamp), event.source, str(event.correlation_id), _json(payload, 131_072), _iso(utcnow())))
            return bool(cursor.rowcount)

    def event_exists(self, event_id: str) -> bool:
        with self.read_connection() as connection:
            return connection.execute("SELECT 1 FROM threat_events WHERE event_id=?", (event_id,)).fetchone() is not None

    def add_relationship(self, relationship_id: str, source_ref: str, relationship_type: str, target_ref: str,
                         confidence: float, evidence: Iterable[Any]) -> None:
        now = _iso(utcnow())
        with self.transaction() as connection:
            connection.execute("""INSERT INTO threat_relationships(relationship_id,source_ref,relationship_type,target_ref,confidence,first_seen,last_seen,evidence_json)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source_ref,relationship_type,target_ref) DO UPDATE SET
                confidence=MAX(threat_relationships.confidence,excluded.confidence),last_seen=excluded.last_seen,evidence_json=excluded.evidence_json""",
                (relationship_id, source_ref, relationship_type, target_ref, max(0, min(1, confidence)), now, now, _json(list(evidence))))

    def relationships(self, ref: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            if ref:
                rows = connection.execute("SELECT * FROM threat_relationships WHERE source_ref=? OR target_ref=? ORDER BY last_seen DESC LIMIT ?", (ref, ref, limit)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM threat_relationships ORDER BY last_seen DESC LIMIT ?", (limit,)).fetchall()
            return [{**dict(row), "evidence": _loads(row["evidence_json"], [])} for row in rows]

    def upsert_entity(self, entity_id: str, entity_type: str, name: str, description: str = "", external_ids: Any = None, data: Any = None) -> None:
        now = _iso(utcnow())
        with self.transaction() as connection:
            connection.execute("""INSERT INTO threat_entities(entity_id,entity_type,name,description,external_ids_json,data_json,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(entity_id) DO UPDATE SET name=excluded.name,description=excluded.description,
                external_ids_json=excluded.external_ids_json,data_json=excluded.data_json,updated_at=excluded.updated_at""",
                (entity_id, entity_type, name, description, _json(external_ids or []), _json(data or {}), now, now))

    def list_entities(self, entity_type: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            if entity_type:
                rows = connection.execute("SELECT * FROM threat_entities WHERE entity_type=? ORDER BY updated_at DESC LIMIT ?", (entity_type, limit)).fetchall()
            else:
                rows = connection.execute("SELECT * FROM threat_entities ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
            return [{**dict(row), "external_ids": _loads(row["external_ids_json"], []), "data": _loads(row["data_json"], {})} for row in rows]

    def upsert_vulnerability(self, cve_id: str, data: Dict[str, Any]) -> None:
        now = _iso(utcnow())
        with self.transaction() as connection:
            connection.execute("""INSERT INTO threat_vulnerabilities(cve_id,cvss,affected_products_json,references_json,published,modified,kev,kev_due_date,ransomware_use,data_json,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET cvss=COALESCE(excluded.cvss,threat_vulnerabilities.cvss),
                affected_products_json=excluded.affected_products_json,references_json=excluded.references_json,published=COALESCE(excluded.published,threat_vulnerabilities.published),
                modified=COALESCE(excluded.modified,threat_vulnerabilities.modified),kev=MAX(threat_vulnerabilities.kev,excluded.kev),
                kev_due_date=COALESCE(excluded.kev_due_date,threat_vulnerabilities.kev_due_date),ransomware_use=MAX(threat_vulnerabilities.ransomware_use,excluded.ransomware_use),
                data_json=excluded.data_json,updated_at=excluded.updated_at""", (
                    cve_id, data.get("cvss"), _json(data.get("affected_products", [])), _json(data.get("references", [])),
                    data.get("published"), data.get("modified"), int(bool(data.get("kev"))), data.get("kev_due_date"),
                    int(bool(data.get("ransomware_use"))), _json(data), now,
                ))

    def vulnerabilities(self, kev_only: bool = False, limit: int = 200) -> List[Dict[str, Any]]:
        query = "SELECT * FROM threat_vulnerabilities" + (" WHERE kev=1" if kev_only else "") + " ORDER BY kev DESC, modified DESC LIMIT ?"
        with self.read_connection() as connection:
            return [{**dict(row), "affected_products": _loads(row["affected_products_json"], []), "references": _loads(row["references_json"], []), "data": _loads(row["data_json"], {})}
                    for row in connection.execute(query, (limit,)).fetchall()]

    def set_feed_status(self, status: FeedStatus, cursor: Optional[str] = None) -> None:
        with self.transaction() as connection:
            connection.execute("""INSERT INTO threat_feed_status(name,enabled,interval_seconds,timeout_seconds,retry_count,reliability,last_success,last_failure,status,last_error,items_ingested,cursor)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled,interval_seconds=excluded.interval_seconds,
                timeout_seconds=excluded.timeout_seconds,retry_count=excluded.retry_count,reliability=excluded.reliability,last_success=excluded.last_success,
                last_failure=excluded.last_failure,status=excluded.status,last_error=excluded.last_error,items_ingested=excluded.items_ingested,cursor=COALESCE(excluded.cursor,threat_feed_status.cursor)""",
                (status.name, int(status.enabled), status.interval, status.timeout, status.retry_count, status.reliability,
                 _iso(status.last_success), _iso(status.last_failure), status.status, status.last_error, status.items_ingested, cursor))

    def feed_statuses(self) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM threat_feed_status ORDER BY name").fetchall()]

    def feed_cursor(self, name: str) -> Optional[str]:
        with self.read_connection() as connection:
            row = connection.execute("SELECT cursor FROM threat_feed_status WHERE name=?", (name,)).fetchone()
            return row["cursor"] if row else None

    def queue_event(self, event: IntelligenceEvent, direction: str = "outbound") -> bool:
        now = _iso(utcnow())
        with self.transaction() as connection:
            cursor = connection.execute("INSERT OR IGNORE INTO transport_queue(event_id,direction,payload_json,status,available_at,created_at) VALUES(?,?,?,'pending',?,?)",
                (str(event.event_id), direction, _json(event.model_dump(mode="json"), 131_072), now, now))
            return bool(cursor.rowcount)

    def dequeue(self, limit: int = 100, direction: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM transport_queue WHERE status='pending' AND available_at<=?"
        values: List[Any] = [_iso(utcnow())]
        if direction:
            query += " AND direction=?"
            values.append(direction)
        query += " ORDER BY queue_id LIMIT ?"
        values.append(limit)
        with self.read_connection() as connection:
            return [{**dict(row), "payload": _loads(row["payload_json"], {})} for row in connection.execute(query, values).fetchall()]

    def acknowledge_queue(self, queue_id: int) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE transport_queue SET status='delivered',delivered_at=? WHERE queue_id=?", (_iso(utcnow()), queue_id))

    def fail_queue(self, queue_id: int, error: str, delay_seconds: int = 30) -> None:
        available = utcnow() + timedelta(seconds=min(delay_seconds, 3600))
        with self.transaction() as connection:
            connection.execute("UPDATE transport_queue SET attempts=attempts+1,available_at=?,last_error=? WHERE queue_id=?", (_iso(available), error[:1024], queue_id))

    def queue_depth(self) -> int:
        with self.read_connection() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM transport_queue WHERE status='pending'").fetchone()[0])

    def save_correlation(self, correlation_id: str, rule_name: str, indicator_id: Optional[str], asset_id: Optional[str],
                         score: float, severity: str, evidence: Any) -> Dict[str, Any]:
        now = _iso(utcnow())
        with self.transaction() as connection:
            connection.execute("""INSERT INTO threat_correlations(correlation_id,rule_name,indicator_id,asset_id,score,severity,evidence_json,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(correlation_id) DO UPDATE SET score=excluded.score,severity=excluded.severity,evidence_json=excluded.evidence_json,updated_at=excluded.updated_at""",
                (correlation_id, rule_name, indicator_id, asset_id, score, severity, _json(evidence), now, now))
        return {"correlation_id": correlation_id, "rule_name": rule_name, "indicator_id": indicator_id, "asset_id": asset_id,
                "score": score, "severity": severity, "evidence": evidence, "created_at": now,
                "requires_human_approval": True, "action_taken": None}

    def correlations(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            return [{**dict(row), "evidence": _loads(row["evidence_json"], [])} for row in connection.execute("SELECT * FROM threat_correlations ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]

    def save_report(self, report_id: str, title: str, report: Dict[str, Any]) -> None:
        with self.transaction() as connection:
            connection.execute("INSERT OR REPLACE INTO threat_reports(report_id,title,created_at,report_json) VALUES(?,?,?,?)",
                               (report_id, title, _iso(utcnow()), _json(report, 524_288)))

    def reports(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            return [{"report_id": row["report_id"], "title": row["title"], "created_at": row["created_at"], "report": _loads(row["report_json"], {})}
                    for row in connection.execute("SELECT * FROM threat_reports ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()]

    def audit(self, actor: str, action: str, resource: str, outcome: str, detail: Any = None, correlation_id: Optional[str] = None) -> None:
        with self.transaction() as connection:
            connection.execute("INSERT INTO audit_log(timestamp,actor,action,resource,outcome,correlation_id,detail_json) VALUES(?,?,?,?,?,?,?)",
                               (_iso(utcnow()), actor[:128], action[:128], resource[:512], outcome[:32], correlation_id, _json(detail or {}, 32_768)))

    def metrics(self) -> Dict[str, float]:
        with self.read_connection() as connection:
            total, active, expired, high, critical = connection.execute("""SELECT COUNT(*),SUM(active),SUM(CASE WHEN verification_status='expired' THEN 1 ELSE 0 END),
                SUM(CASE WHEN threat_score>=60 THEN 1 ELSE 0 END),SUM(CASE WHEN threat_score>=80 THEN 1 ELSE 0 END) FROM threat_indicators""").fetchone()
            matches = connection.execute("SELECT COUNT(*) FROM threat_events WHERE event_type='ioc_match'").fetchone()[0]
            correlations = connection.execute("SELECT COUNT(*) FROM threat_correlations").fetchone()[0]
            received = connection.execute("SELECT COUNT(*) FROM transport_queue WHERE direction='inbound'").fetchone()[0]
            sent = connection.execute("SELECT COUNT(*) FROM transport_queue WHERE direction='outbound'").fetchone()[0]
        return {"indicators_total": total or 0, "indicators_active": active or 0, "indicators_expired": expired or 0,
                "ioc_matches_total": matches, "correlations_total": correlations, "high_risk_iocs": high or 0,
                "critical_iocs": critical or 0, "soc_messages_received": received, "soc_messages_sent": sent,
                "queue_depth": self.queue_depth()}
