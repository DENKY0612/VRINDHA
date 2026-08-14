"""Explainable, configurable threat and confidence scoring.

Threat score answers *how dangerous*; confidence answers *how sure*.  Neither
score authorizes a defensive action.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence
import math

from ..models import Severity


@dataclass(frozen=True)
class SourceReliability:
    name: str
    reliability: float
    observations: int = 0
    correct: int = 0
    false_positives: int = 0

    @property
    def adjusted(self) -> float:
        prior_weight = 10
        historical = (self.correct + 1) / (self.observations + 2) if self.observations else self.reliability
        false_penalty = min(0.35, self.false_positives / max(10, self.observations) * 0.4)
        return max(0.0, min(1.0, (self.reliability * prior_weight + historical * self.observations) / (prior_weight + self.observations) - false_penalty))


@dataclass(frozen=True)
class ScoreResult:
    score: float
    severity: str
    confidence: float
    factors: dict[str, float]
    explanation: list[str]


def severity_for(score: float) -> str:
    if score >= 80:
        return Severity.CRITICAL.value
    if score >= 60:
        return Severity.HIGH.value
    if score >= 40:
        return Severity.MEDIUM.value
    if score >= 20:
        return Severity.LOW.value
    return Severity.INFORMATIONAL.value


def calculate_confidence(
    source_reliabilities: Iterable[float],
    reported_confidence: float,
    independent_sources: int,
    verification_bonus: float = 0.0,
    false_positive_probability: float = 0.0,
) -> float:
    values = [max(0.0, min(1.0, value)) for value in source_reliabilities]
    reliability = sum(values) / len(values) if values else 0.3
    diversity = min(1.0, math.log2(max(1, independent_sources) + 1) / 3)
    score = reliability * 0.45 + max(0, min(1, reported_confidence)) * 0.35 + diversity * 0.20
    score += max(0, min(0.2, verification_bonus))
    score -= max(0, min(1, false_positive_probability)) * 0.45
    return round(max(0.0, min(1.0, score)), 4)


def calculate_threat_score(
    *,
    source_reliabilities: Sequence[float],
    reported_confidence: float,
    independent_sources: int = 1,
    last_seen: datetime | None = None,
    sightings: int = 0,
    malware_association: bool = False,
    campaign_association: bool = False,
    attack_relevance: float = 0.0,
    kev: bool = False,
    cvss: float | None = None,
    asset_exposure: float = 0.0,
    asset_criticality: float = 0.0,
    observed_exploitation: bool = False,
    false_positive_probability: float = 0.0,
    verification_bonus: float = 0.0,
) -> ScoreResult:
    confidence = calculate_confidence(
        source_reliabilities,
        reported_confidence,
        independent_sources,
        verification_bonus,
        false_positive_probability,
    )
    now = datetime.now(timezone.utc)
    seen = last_seen or now
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (now - seen).total_seconds() / 86400)
    recency = math.exp(-age_days / 90)
    sighting_signal = min(1.0, math.log1p(max(0, sightings)) / math.log(20))
    association = min(1.0, (0.55 if malware_association else 0) + (0.30 if campaign_association else 0))
    attack = max(0.0, min(1.0, attack_relevance))
    vulnerability = 0.0
    if cvss is not None:
        vulnerability += max(0.0, min(10.0, cvss)) / 10 * 0.35
    vulnerability += 0.35 if kev else 0
    vulnerability += max(0, min(1, asset_exposure)) * 0.10
    vulnerability += max(0, min(1, asset_criticality)) * 0.10
    vulnerability += 0.20 if observed_exploitation else 0
    vulnerability = min(1.0, vulnerability)

    factors = {
        "confidence": confidence * 28,
        "source_diversity": min(1.0, independent_sources / 4) * 10,
        "recency": recency * 14,
        "sightings": sighting_signal * 12,
        "malware_campaign": association * 12,
        "attack_relevance": attack * 10,
        "vulnerability_context": vulnerability * 14,
        "false_positive_penalty": -max(0, min(1, false_positive_probability)) * 30,
        "age_penalty": -min(15.0, age_days / 60 * 5),
    }
    score = round(max(0.0, min(100.0, sum(factors.values()))), 2)
    explanation = [
        f"confidence contribution {factors['confidence']:.1f}",
        f"{independent_sources} independent source(s)",
        f"last seen {age_days:.1f} day(s) ago",
        f"{sightings} internal/external sighting(s)",
    ]
    if kev:
        explanation.append("listed in CISA Known Exploited Vulnerabilities")
    if observed_exploitation:
        explanation.append("observed exploitation evidence present")
    if false_positive_probability:
        explanation.append(f"false-positive penalty {false_positive_probability:.0%}")
    return ScoreResult(score, severity_for(score), confidence, factors, explanation)
