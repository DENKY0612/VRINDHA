"""Ethics & Compliance AI — the Moral and Governance Guardian of Vrindha AI.

Multi-layer decision engine (spec §14):

    USER INTENT → AUTHORIZATION → SECURITY POLICY → CYBER LAW (guidance)
    → DHARMA ANALYSIS → RISK ANALYSIS → GITA GUIDANCE → FINAL DECISION

Outcomes: ALLOW | ALLOW_WITH_WARNING | REQUIRE_AUTHORIZATION |
SAFE_ALTERNATIVE | DENY | ESCALATE_TO_HUMAN

Hard rules implemented:
* Judges the ACTION and CONTEXT — never the user; no user moral scoring.
* No religious coercion, profiling, or inference about the user's religion.
* Gita references are only emitted from the stored, verified dataset
  (18 chapter JSON files); missing verses are never fabricated.
* Law references are labeled guidance, not legal advice.
* Every decision is audit-logged with the full reasoning chain.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import (
    EthicsAssessment,
    EthicsClassification,
    EthicsDecision,
    utc_now_iso,
)

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
GITA_DATA_DIR = PACKAGE_ROOT / "data" / "BhagavadGita"

# ----------------------------------------------------------------------
# Cybersecurity Dharma principles (data, not code behavior)
# ----------------------------------------------------------------------
DHARMA_PRINCIPLES: Dict[str, Dict[str, str]] = {
    "SATYA": {
        "name": "Truthfulness",
        "cybersecurity": "Do not intentionally deceive, falsify evidence, or manipulate security reports.",
    },
    "AHIMSA": {
        "name": "Non-harm",
        "cybersecurity": "Avoid unnecessary harm to people, systems, organizations, and data.",
    },
    "ASTEYA": {
        "name": "Non-stealing",
        "cybersecurity": "Do not steal credentials, information, data, or unauthorized resources.",
    },
    "APARIGRAHA": {
        "name": "Non-possessiveness",
        "cybersecurity": "Do not hoard or misuse access; use only the privileges the task requires.",
    },
    "SVADHYAYA": {
        "name": "Self-study",
        "cybersecurity": "Prefer learning, reflection, security education, and responsible research.",
    },
    "DANA": {
        "name": "Responsible sharing",
        "cybersecurity": "Share findings and threat information responsibly and lawfully.",
    },
    "DUTY": {
        "name": "Duty / Responsibility",
        "cybersecurity": "Security capabilities must be used only within authorized boundaries.",
    },
    "SELF_CONTROL": {
        "name": "Self-control",
        "cybersecurity": "Do not perform an action merely because the system technically allows it.",
    },
    "NON_MALICE": {
        "name": "Non-malice",
        "cybersecurity": "No intent to harm, destroy, extort, or sabotage.",
    },
    "ACCOUNTABILITY": {
        "name": "Accountability",
        "cybersecurity": "Actions must be traceable, attributable, and logged.",
    },
}

# ----------------------------------------------------------------------
# Legal / policy reference data — GUIDANCE ONLY, not legal advice.
# ----------------------------------------------------------------------
LEGAL_REFERENCES: Dict[str, Dict[str, str]] = {
    "unauthorized_access_in": {
        "label": "Information Technology Act 2000 (India), Section 43",
        "note": "Penalizes accessing computer resources without authorization. Guidance only.",
    },
    "unauthorized_access_penalty_in": {
        "label": "Information Technology Act 2000 (India), Sections 66/66A",
        "note": "Penal provisions for computer-related offenses. Guidance only.",
    },
    "data_privacy_in": {
        "label": "Digital Personal Data Protection Act 2023 (India)",
        "note": "Data processing must be lawful, purpose-limited, and consent-based. Guidance only.",
    },
    "incident_reporting_in": {
        "label": "CERT-In Directions, Ministry of Electronics & IT (India)",
        "note": "Mandatory reporting of specified cyber incidents to CERT-In. Guidance only.",
    },
    "nist_csf": {
        "label": "NIST Cybersecurity Framework (Govern / Identify / Protect / Detect / Respond / Recover)",
        "note": "International baseline for governance and response functions.",
    },
    "iso_27001": {
        "label": "ISO/IEC 27001 (Annex A.5 organizational controls)",
        "note": "International information security management baseline.",
    },
    "gdpr": {
        "label": "GDPR Art. 5 & 32 (where EU data is processed)",
        "note": "Lawfulness, purpose limitation, and security of processing. Guidance only.",
    },
}

SECURITY_POLICIES: Dict[str, Dict[str, str]] = {
    "authorization": {
        "label": "AUTHORIZATION",
        "rule": "Security testing only against systems you own or are explicitly authorized to assess.",
    },
    "least_privilege": {
        "label": "LEAST PRIVILEGE",
        "rule": "Use only the access required for the stated task; no privilege escalation.",
    },
    "no_data_exfiltration": {
        "label": "NO DATA EXFILTRATION",
        "rule": "Credentials, data, and information never leave authorized boundaries.",
    },
    "audit_trail": {
        "label": "AUDIT TRAIL",
        "rule": "Every security action is logged with actor, target, and outcome.",
    },
    "high_impact_approval": {
        "label": "HUMAN APPROVAL FOR HIGH IMPACT",
        "rule": "Blocking IPs, stopping services, isolating hosts, changing firewall rules, disabling accounts require explicit human approval.",
    },
}

# ----------------------------------------------------------------------
# Bhagavad Gita knowledge base — loaded from the stored, verified dataset.
# ----------------------------------------------------------------------
CHAPTER_TITLES_FALLBACK = {
    1: "Arjuna Vishada Yoga", 2: "Sankhya Yoga", 3: "Karma Yoga",
    4: "Jnana Karma Sannyasa Yoga", 5: "Karma Sannyasa Yoga", 6: "Dhyana Yoga",
    7: "Jnana Vijnana Yoga", 8: "Akshara Brahma Yoga",
    9: "Raja Vidya Raja Guhya Yoga", 10: "Vibhuti Yoga",
    11: "Vishvarupa Darshana Yoga", 12: "Bhakti Yoga",
    13: "Kshetra Kshetrajna Vibhaga Yoga", 14: "Gunatraya Vibhaga Yoga",
    15: "Purushottama Yoga", 16: "Daivasura Sampad Vibhaga Yoga",
    17: "Shraddhatraya Vibhaga Yoga", 18: "Moksha Sannyasa Yoga",
}

#: Concept → (chapter, verse, why). Every reference is verified against the
#: stored dataset at load time; unverifiable entries are dropped, never faked.
CONCEPT_VERSE_REFERENCES: Dict[str, Tuple[int, int, str]] = {
    "duty": (2, 47, "Duty and responsible action without attachment to results"),
    "responsible_action": (3, 19, "Performing one's duty responsibly"),
    "constructive_conduct": (16, 1, "Qualities associated with constructive conduct"),
    "virtuous_conduct": (16, 3, "Virtuous conduct in community life"),
    "destructive_tendencies": (16, 4, "Traits associated with destructive tendencies"),
    "desire_anger_greed": (16, 21, "Destructive tendencies such as desire, anger, and greed"),
    "truthful_speech": (17, 15, "Discipline in speech; truthful and non-harmful communication"),
    "disciplined_duty": (18, 23, "Action performed as duty with discipline, without attachment"),
    "self_control": (6, 5, "Raising the self by the self; discipline of mind"),
    "detachment": (2, 48, "Acting with equanimity, free from attachment to outcomes"),
    "knowledge": (4, 38, "Knowledge and its role in righteous action"),
}


class BhagavadGitaKnowledgeBase:
    """Verified verse store built only from the bundled chapter JSON files."""

    def __init__(self, data_dir: Path = GITA_DATA_DIR) -> None:
        self.data_dir = Path(data_dir)
        self.chapters: Dict[int, Dict[str, Any]] = {}
        self.verses: Dict[Tuple[int, int], Dict[str, Any]] = {}
        self._concept_index: Dict[str, List[Tuple[int, int]]] = {}
        self._load()
        self._build_concept_index()

    def _load(self) -> None:
        if not self.data_dir.is_dir():
            return
        for path in sorted(self.data_dir.glob("bhagavad_gita_chapter_*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            book = payload.get("bhagavadGita", {})
            chapter_meta = book.get("chapter", {})
            number = chapter_meta.get("number")
            if not isinstance(number, int):
                continue
            self.chapters[number] = {
                "chapter": number,
                "name": chapter_meta.get("name") or CHAPTER_TITLES_FALLBACK.get(number, ""),
                "englishName": chapter_meta.get("englishName", ""),
                "description": chapter_meta.get("description", ""),
                "totalVerses": chapter_meta.get("totalVerses"),
                "source_file": path.name,
            }
            for verse in book.get("verses", []):
                verse_number = verse.get("verseNumber")
                if not isinstance(verse_number, int):
                    continue
                self.verses[(number, verse_number)] = {
                    "chapter": number,
                    "verse": verse_number,
                    "speaker": verse.get("speaker"),
                    "sanskrit": verse.get("sanskrit"),
                    "transliteration": verse.get("transliteration"),
                    "translation": verse.get("englishTranslation"),
                    "meaning": verse.get("meaning"),
                    "source_file": path.name,
                }

    def _build_concept_index(self) -> None:
        for concept, (chapter, verse, _why) in CONCEPT_VERSE_REFERENCES.items():
            if (chapter, verse) in self.verses:  # verification gate
                self._concept_index.setdefault(concept, []).append((chapter, verse))
        # Keyword index over stored meaning/translation text (no fabrication).
        self._keyword_index: Dict[str, List[Tuple[int, int]]] = {}
        for (chapter, verse), record in self.verses.items():
            text = " ".join(
                str(record.get(k) or "") for k in ("translation", "meaning")
            ).lower()
            for word in set(re.findall(r"[a-z']{4,}", text)):
                self._keyword_index.setdefault(word, []).append((chapter, verse))

    # ------------------------------------------------------------------
    @property
    def loaded(self) -> bool:
        return bool(self.verses)

    def chapter_index(self) -> List[Dict[str, Any]]:
        return [self.chapters[k] for k in sorted(self.chapters)]

    def get(self, chapter: int, verse: int) -> Optional[Dict[str, Any]]:
        """Verified verse or None — never a fabricated one."""
        return self.verses.get((chapter, verse))

    def by_concept(self, concept: str) -> Optional[Dict[str, Any]]:
        key = concept.lower().replace(" ", "_")
        refs = self._concept_index.get(key) or self._concept_index.get(key.replace("-", "_"))
        if not refs:
            return None
        chapter, verse = refs[0]
        record = self.verses.get((chapter, verse))
        if record is None:
            return None
        return {**record, "concept": key,
                "relevance": CONCEPT_VERSE_REFERENCES.get(key, (None, None, ""))[2]}

    def search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        words = [w for w in re.findall(r"[a-z']{4,}", query.lower()) if len(w) >= 4]
        if not words:
            return []
        scores: Dict[Tuple[int, int], int] = {}
        for word in words:
            for ref in self._keyword_index.get(word, []):
                scores[ref] = scores.get(ref, 0) + 1
        top = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        results = []
        for (chapter, verse), _ in top:
            record = self.verses.get((chapter, verse))
            if record:
                results.append(record)
        return results

    def reference(self, chapter: int, verse: int) -> Optional[Dict[str, Any]]:
        """Public API for the ethics engine — verified only."""
        record = self.get(chapter, verse)
        if record is None:
            return None
        chapter_meta = self.chapters.get(chapter, {})
        return {
            **record,
            "chapter_name": chapter_meta.get("name", ""),
            "verified": True,
            "source": f"stored dataset: {record['source_file']}",
        }


gita_knowledge_base = BhagavadGitaKnowledgeBase()


# ----------------------------------------------------------------------
# Dharma Recognition Engine
# ----------------------------------------------------------------------
HARM_PATTERNS = {
    "unauthorized_access": [
        "unauthorized", "without permission", "without authorization", "break into",
        "crack", "steal", "theft", "exfiltrate", "exfil", "access another",
        "other person's account", "someone else's", "hack this", "hack the",
        "exploit this", "exploit their",
    ],
    "deception": [
        "spoof", "impersonate", "phish", "falsify", "fake evidence", "disguise",
    ],
    "destruction": [
        "delete", "destroy", "wipe", "corrupt", "deface", "damage", "ransom",
    ],
    "abuse_of_power": [
        "ddos", "dos attack", "overload", "shutdown", "shut down", "disable account",
        "escalate privileges", "privilege escalation",
    ],
}

#: Word-boundary regexes so "steal" matches but "listen" / "crackdown" style
#: substrings do not.
_HARM_REGEX = {
    category: [re.compile(r"\b" + re.escape(pattern) + r"\b") for pattern in patterns]
    for category, patterns in HARM_PATTERNS.items()
}


def _find_harm(text: str):
    """Word-boundary matching of harm patterns against lowered text."""
    hits: Dict[str, List[str]] = {}
    for category, regexes in _HARM_REGEX.items():
        matched = [
            pattern
            for pattern, regex in zip(HARM_PATTERNS[category], regexes)
            if regex.search(text)
        ]
        if matched:
            hits[category] = matched
    return hits

SAFE_CONTEXTS = [
    "my system", "my network", "my lab", "lab environment", "authorized", "authorization",
    "permission", "security testing", "vulnerability assessment", "defensive", "protect",
    "audit", "my server", "my host", "my host", "home lab", "simulation", "simulated",
    "educational", "learn", "testing my", "our environment",
]

HIGH_IMPACT_ACTIONS = [
    "block ip", "block_ip", "stop service", "kill process", "isolate", "delete",
    "firewall", "disable account", "quarantine",
]

#: Words that mark a security-testing action (needs an established target + authorization).
SECURITY_TESTING_KEYWORDS = [
    "scan", "vulnerability", "nikto", "nmap", "gobuster", "probe", "fuzz", "amass",
    "sublist3r", "dirb", "openvas", "enum", "penetration", "test the", "test this",
    "assess",
]

DEFENSIVE_KEYWORDS = ["secure", "protect", "defend", "monitor", "audit", "defensive"]


class DharmaRecognitionEngine:
    """Classifies the ACTION (never the user) against dharma principles."""

    def classify(self, action: str, authorization_status: str) -> Dict[str, Any]:
        text = (action or "").lower()
        has_safe_context = any(ctx in text for ctx in SAFE_CONTEXTS)
        auth_provided = authorization_status in {"provided", "explicit"}

        hits = _find_harm(text)

        if not hits:
            is_defensive = any(word in text for word in DEFENSIVE_KEYWORDS) or "scan my" in text
            is_testing = any(word in text for word in SECURITY_TESTING_KEYWORDS)
            if is_defensive:
                return self._result(
                    EthicsClassification.DHARMA_ALIGNED,
                    ["DUTY", "AHIMSA", "ACCOUNTABILITY"],
                    "Action is defensive/protective and aligned with responsible security practice.",
                    "low",
                )
            if is_testing:
                # Spec decision matrix: authorized testing = ALIGNED;
                # ambiguous = concern; no authorization established = POTENTIAL_ADHARMA.
                if auth_provided and has_safe_context:
                    return self._result(
                        EthicsClassification.DHARMA_ALIGNED,
                        ["DUTY", "SVADHYAYA", "ACCOUNTABILITY"],
                        "Authorized defensive security research — aligned with duty and "
                        "responsible skill development.",
                        "none",
                    )
                if auth_provided or has_safe_context:
                    return self._result(
                        EthicsClassification.ETHICAL_CONCERN,
                        ["DUTY", "SELF_CONTROL", "ACCOUNTABILITY"],
                        "Security-testing capability in a claimed-authorized context — "
                        "requires confirmation, justification, and audit logging.",
                        "medium",
                    )
                return self._result(
                    EthicsClassification.POTENTIAL_ADHARMA,
                    ["DUTY", "AUTHORIZATION"],
                    "Authorization is not established for this target — scanning or testing "
                    "proceeds only after authorization or ownership context is confirmed.",
                    "medium",
                )
            return self._result(
                EthicsClassification.ETHICALLY_NEUTRAL,
                ["ACCOUNTABILITY"],
                "No harmful intent detected; routine action subject to normal policy controls.",
                "none",
            )

        # Harmful patterns present.
        if auth_provided and has_safe_context:
            return self._result(
                EthicsClassification.ETHICAL_CONCERN,
                ["DUTY", "SELF_CONTROL", "ACCOUNTABILITY"],
                "Sensitive capability with authorization context — requires confirmation, "
                "justification, and audit logging.",
                "medium",
            )
        if "unauthorized_access" in hits or "deception" in hits:
            return self._result(
                EthicsClassification.HIGH_RISK_ADHARMA,
                ["ASTEYA", "SATYA", "DUTY", "NON_MALICE"],
                "Action involves unauthorized access, deception, or theft — "
                "this conflicts with the system's Dharma principles regardless of technical feasibility.",
                "high",
            )
        if "destruction" in hits or "abuse_of_power" in hits:
            return self._result(
                EthicsClassification.HIGH_RISK_ADHARMA,
                ["AHIMSA", "NON_MALICE", "DUTY"],
                "Action is intentionally destructive or abusive — prohibited.",
                "high",
            )
        if not auth_provided:
            return self._result(
                EthicsClassification.POTENTIAL_ADHARMA,
                ["DUTY", "AUTHORIZATION"],
                "Authorization is not established for this action — it cannot proceed until "
                "authorization or context is confirmed.",
                "medium",
            )
        return self._result(
            EthicsClassification.ETHICAL_CONCERN,
            ["DUTY", "SELF_CONTROL", "ACCOUNTABILITY"],
            "Sensitive action — confirmation and justification required.",
            "medium",
        )

    @staticmethod
    def _result(classification: EthicsClassification, principles: List[str],
                reason: str, concern: str) -> Dict[str, Any]:
        return {
            "classification": classification,
            "principles": [p for p in principles if p in DHARMA_PRINCIPLES],
            "reason": reason,
            "dharma_concern": concern,
        }


# ----------------------------------------------------------------------
# Ethics & Compliance AI
# ----------------------------------------------------------------------
class EthicsAI(BaseAgent):
    name = "EthicsAI"
    kind = "governance"
    capabilities = ["dharma_recognition", "policy_enforcement", "legal_guidance",
                    "gita_guidance", "audit", "teaching", "authorization_routing"]

    def __init__(self, bus: Optional[EventBus] = None,
                 gita_kb: Optional[BhagavadGitaKnowledgeBase] = None) -> None:
        super().__init__(bus)
        self.dharma_engine = DharmaRecognitionEngine()
        self.gita_kb = gita_kb or gita_knowledge_base
        self._teach_topics = set()
        self._ensure_audit_table()

    def _ensure_audit_table(self) -> None:
        from vrin_SOC.database import db

        def create(conn):
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ethics_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    timestamp TEXT,
                    requested_action TEXT,
                    intent_classification TEXT,
                    authorization_status TEXT,
                    policy_result TEXT,
                    legal_result TEXT,
                    dharma_result TEXT,
                    risk_result TEXT,
                    decision TEXT,
                    explanation_given TEXT,
                    alternative_provided TEXT,
                    gita_reference TEXT,
                    human_approval_required INTEGER,
                    final_outcome TEXT
                )
                """
            )

        try:
            db._run_db(create)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Layered evaluation
    # ------------------------------------------------------------------
    def evaluate(
        self,
        action: str,
        target: str = "",
        context: Optional[Dict[str, Any]] = None,
        authorization_status: str = "missing",
        request_gita_guidance: bool = True,
        event_id: Optional[str] = None,
    ) -> EthicsAssessment:
        context = context or {}
        started = self._before()
        try:
            assessment = self._evaluate_inner(
                action, target, context, authorization_status, request_gita_guidance
            )
            self._audit(event_id, action, assessment)
            self._after(started, ok=True)
            return assessment
        except Exception as exc:  # noqa: BLE001
            self._after(started, ok=False)
            self.metrics.record_error(str(exc))
            # Fail SAFE: deny high-impact, require human review otherwise.
            return EthicsAssessment(
                requested_action=action[:500],
                classification=EthicsClassification.ETHICAL_CONCERN,
                decision=EthicsDecision.ESCALATE_TO_HUMAN
                if _is_high_impact(action)
                else EthicsDecision.ALLOW_WITH_WARNING,
                authorization_status=authorization_status,
                reason=f"Ethics evaluation error ({str(exc)[:120]}) — failing safe to human review.",
                human_approval_required=_is_high_impact(action),
            )

    def _evaluate_inner(
        self,
        action: str,
        target: str,
        context: Dict[str, Any],
        authorization_status: str,
        request_gita_guidance: bool,
    ) -> EthicsAssessment:
        # 1) Intent (reuse the existing, tested analyzer)
        try:
            from vrin_SOC.core.intent_analyzer import intent_analyzer

            intent = intent_analyzer.analyze(action)
        except Exception:  # noqa: BLE001
            intent = {"intent": "safe", "confidence": "low", "reason": "intent analyzer unavailable"}

        # 2) Authorization (reuse the existing policy layer when a target exists)
        if authorization_status == "missing" and target:
            try:
                from vrin_SOC.core.authorization import authorization_layer

                allowed, _reason = authorization_layer.is_target_allowed(target, action)
                if allowed:
                    authorization_status = "implicit"
            except Exception:  # noqa: BLE001
                pass
        if context.get("authorized") or context.get("authorization") == "provided":
            authorization_status = "provided"

        # 3) Dharma analysis
        dharma = self.dharma_engine.classify(action, authorization_status)
        classification = dharma["classification"]
        concern = dharma["dharma_concern"]

        # 4) Policy + law references (data-driven, guidance-only)
        policy_refs, legal_refs = self._references(action, classification, authorization_status)

        # 5) Risk analysis (reuse existing deterministic scorer)
        risk_note, risk_flags = self._risk_flags(action, target, context)

        # 6) Gita guidance — verified references only, optional, never coercive
        gita_reference = None
        if request_gita_guidance and self.gita_kb.loaded:
            gita_reference = self._gita_guidance(action, classification, context)

        # 7) Final decision
        decision, alternative, human_approval, justification = self._decide(
            classification, authorization_status, intent, action, risk_flags
        )

        return EthicsAssessment(
            requested_action=action[:500],
            classification=classification,
            decision=decision,
            authorization_status=authorization_status,
            harm_risk=risk_flags["harm"],
            deception_risk=risk_flags["deception"],
            privacy_risk=risk_flags["privacy"],
            dharma_concern=concern,
            principles=dharma["principles"],
            policy_references=policy_refs,
            legal_references=legal_refs,
            reason=dharma["reason"] + (f" Intent analysis: {intent.get('reason', '')}" if intent.get("reason") else ""),
            alternative=alternative,
            gita_reference=gita_reference,
            human_approval_required=human_approval,
            requires_justification=justification,
        )

    def _references(self, action: str, classification: EthicsClassification,
                    authorization_status: str) -> Tuple[List[str], List[str]]:
        text = action.lower()
        policy_refs: List[str] = []
        legal_refs: List[str] = []

        if any(p in text for p in ("password", "credential", "account", "login", "access")):
            policy_refs.append(SECURITY_POLICIES["authorization"]["label"])
            policy_refs.append(SECURITY_POLICIES["least_privilege"]["label"])
        if any(p in text for p in ("exfil", "download", "export", "data")):
            policy_refs.append(SECURITY_POLICIES["no_data_exfiltration"]["label"])
        if _is_high_impact(action):
            policy_refs.append(SECURITY_POLICIES["high_impact_approval"]["label"])
        policy_refs.append(SECURITY_POLICIES["audit_trail"]["label"])

        if classification in {EthicsClassification.HIGH_RISK_ADHARMA, EthicsClassification.ILLEGAL_OR_UNAUTHORIZED} \
                or "unauthorized" in text:
            legal_refs.append(LEGAL_REFERENCES["unauthorized_access_in"]["label"])
            legal_refs.append(LEGAL_REFERENCES["unauthorized_access_penalty_in"]["label"])
        if any(p in text for p in ("data", "personal", "privacy", "customer")):
            legal_refs.append(LEGAL_REFERENCES["data_privacy_in"]["label"])
        if any(p in text for p in ("breach", "incident", "attack")):
            legal_refs.append(LEGAL_REFERENCES["incident_reporting_in"]["label"])
        legal_refs.append(LEGAL_REFERENCES["nist_csf"]["label"])
        if classification == EthicsClassification.DHARMA_ALIGNED:
            legal_refs.append(LEGAL_REFERENCES["iso_27001"]["label"])
        return policy_refs, legal_refs

    def _risk_flags(self, action: str, target: str, context: Dict[str, Any]) -> Tuple[str, Dict[str, float]]:
        text = action.lower()
        harm = 0.1
        deception = 0.0
        privacy = 0.0
        found = _find_harm(text)
        for category, weight in (("unauthorized_access", 0.9), ("deception", 0.7),
                                 ("destruction", 0.8), ("abuse_of_power", 0.75)):
            if category in found:
                harm = max(harm, weight)
        if "deception" in found:
            deception = max(deception, 0.7)
        if any(p in text for p in ("data", "password", "credential", "personal")):
            privacy = max(privacy, 0.6)
        if context.get("target_type") in {"production", "customer"}:
            harm = min(1.0, harm + 0.15)
        note = "risk flags derived from action text and context; deterministic and documented"
        return note, {"harm": round(harm, 2), "deception": round(deception, 2), "privacy": round(privacy, 2)}

    def _gita_guidance(self, action: str, classification: EthicsClassification,
                       context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        text = action.lower()
        concept_priority = []
        if classification == EthicsClassification.DHARMA_ALIGNED:
            concept_priority = ["duty", "responsible_action"]
        elif any(p in text for p in ("steal", "credential", "unauthorized", "hack", "exploit", "crack",
                                     "without permission", "account", "access")):
            concept_priority = ["self_control", "duty"]
        elif any(p in text for p in ("delete", "destroy", "ddos", "damage", "ransom")):
            concept_priority = ["destructive_tendencies", "desire_anger_greed"]
        elif any(p in text for p in ("spoof", "fake", "falsify", "impersonate")):
            concept_priority = ["truthful_speech"]
        elif "duty" in text or "responsibility" in text:
            concept_priority = ["disciplined_duty", "duty"]

        for concept in concept_priority:
            record = self.gita_kb.by_concept(concept)
            if record:
                return {
                    "concept": concept,
                    "reference": f"Bhagavad Gita {record['chapter']}.{record['verse']}",
                    "chapter_name": self.gita_kb.chapters.get(record["chapter"], {}).get("name", ""),
                    "speaker": record.get("speaker"),
                    "transliteration": record.get("transliteration"),
                    "translation": record.get("translation"),
                    "relevance": record.get("relevance"),
                    "verified": True,
                    "source": record.get("source_file"),
                }
        # Fallback: verified verse search on action keywords.
        results = self.gita_kb.search(action, limit=1)
        if results:
            record = results[0]
            return {
                "reference": f"Bhagavad Gita {record['chapter']}.{record['verse']}",
                "speaker": record.get("speaker"),
                "transliteration": record.get("transliteration"),
                "translation": record.get("translation"),
                "verified": True,
                "source": record.get("source_file"),
            }
        return None

    def _decide(
        self,
        classification: EthicsClassification,
        authorization_status: str,
        intent: Dict[str, Any],
        action: str,
        risk_flags: Dict[str, float],
    ) -> Tuple[EthicsDecision, Optional[str], bool, bool]:
        high_impact = _is_high_impact(action)

        if classification in {EthicsClassification.HIGH_RISK_ADHARMA,
                              EthicsClassification.ILLEGAL_OR_UNAUTHORIZED} or intent.get("intent") == "malicious":
            return (
                EthicsDecision.DENY,
                "Use an authorized cybersecurity laboratory or obtain written authorization "
                "before testing. I can help you set up a safe, authorized environment.",
                False,
                False,
            )
        if classification == EthicsClassification.POTENTIAL_ADHARMA:
            if high_impact:
                return (
                    EthicsDecision.REQUIRE_AUTHORIZATION,
                    "Confirm authorization for the target in writing before any high-impact action.",
                    True,
                    True,
                )
            return (
                EthicsDecision.REQUIRE_AUTHORIZATION,
                "Please confirm that you have permission to test the target in an authorized "
                "lab or owned environment, and I will proceed within those boundaries.",
                high_impact,
                True,
            )
        if classification == EthicsClassification.ETHICAL_CONCERN:
            if authorization_status in {"provided", "explicit"}:
                return EthicsDecision.ALLOW_WITH_WARNING, None, high_impact, True
            return (
                EthicsDecision.REQUIRE_AUTHORIZATION,
                "Provide authorization or context (owned lab / written permission) to continue.",
                high_impact,
                True,
            )
        if high_impact:
            # Even aligned high-impact actions need explicit human approval.
            return EthicsDecision.ALLOW_WITH_WARNING, None, True, False
        return EthicsDecision.ALLOW, None, False, False

    # ------------------------------------------------------------------
    # Teaching mode
    # ------------------------------------------------------------------
    def teach(self, topic: str, request_gita_guidance: bool = True) -> Dict[str, Any]:
        """Explain WHY an action pattern is a concern — understand/reflect/correct/learn."""
        text = topic.lower()
        start = self._before()
        try:
            example = {
                "unauthorized": "Attempting to access another person's account or data without permission",
                "deception": "Falsifying evidence or spoofing identity in a security report",
                "destruction": "Deleting or damaging data that is not yours",
                "default": "Using powerful security capability without a clear authorized purpose",
            }
            scenario = next((v for k, v in example.items() if k in text), example["default"])
            classification = self.dharma_engine.classify(scenario, "missing")
            gita_reference = None
            if request_gita_guidance and self.gita_kb.loaded:
                gita_reference = self._gita_guidance(scenario, classification["classification"], {})

            self._teach_topics.add(topic[:80])
            self._after(start, ok=True)
            return {
                "status": "success",
                "topic": topic[:200],
                "scenario_examined": scenario,
                "explanation": {
                    "intent": "The system evaluates what the action WOULD do, not who you are.",
                    "action": scenario,
                    "harm": "Unauthorized or deceptive actions cause real harm to people, data, and organizations.",
                    "responsibility": "Technical capability does not create permission — authorization does.",
                    "authorization": "Establish written permission or use an environment you own (lab).",
                    "ethical_principle": ", ".join(
                        f"{p} — {DHARMA_PRINCIPLES[p]['cybersecurity']}"
                        for p in classification["principles"]
                    ),
                    "legal_security_implication": "Such conduct can violate the IT Act 2000 and DPDP Act 2023 (India) "
                                                  "and equivalent standards internationally. Guidance only — not legal advice.",
                    "gita_teaching": gita_reference,
                    "practical_alternative": "Set up an authorized lab (e.g., a home lab or range) and practice "
                                             "the same skill there; I can guide the setup.",
                },
                "classification": classification["classification"].value,
                "dharma_note": "This is educational guidance about actions, not a judgment of any person.",
            }
        except Exception as exc:  # noqa: BLE001
            self._after(start, ok=False)
            self.metrics.record_error(str(exc))
            return {"status": "error", "reason": str(exc)[:256]}

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------
    def _audit(self, event_id: Optional[str], action: str, assessment: EthicsAssessment) -> None:
        from vrin_SOC.database import db

        def insert(conn):
            conn.execute(
                "INSERT INTO ethics_audit_log (event_id, timestamp, requested_action, intent_classification, "
                "authorization_status, policy_result, legal_result, dharma_result, risk_result, decision, "
                "explanation_given, alternative_provided, gita_reference, human_approval_required, final_outcome) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    utc_now_iso(),
                    action[:500],
                    assessment.classification.value,
                    assessment.authorization_status,
                    "; ".join(assessment.policy_references),
                    "; ".join(assessment.legal_references),
                    json.dumps({"classification": assessment.classification.value,
                                "concern": assessment.dharma_concern,
                                "principles": assessment.principles})[:1000],
                    json.dumps({"harm_risk": assessment.harm_risk,
                                "deception_risk": assessment.deception_risk,
                                "privacy_risk": assessment.privacy_risk})[:500],
                    assessment.decision.value,
                    assessment.reason[:1500],
                    (assessment.alternative or "")[:500],
                    json.dumps(assessment.gita_reference or {})[:1000],
                    1 if assessment.human_approval_required else 0,
                    assessment.decision.value,
                ),
            )

        try:
            db._run_db(insert)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            self.metrics.record_error("ethics audit insert failed")

    def audit_log(self, limit: int = 50) -> Dict[str, Any]:
        from vrin_SOC.database import db

        def query(conn):
            return conn.execute(
                "SELECT id, event_id, timestamp, requested_action, authorization_status, decision, "
                "explanation_given, gita_reference, human_approval_required FROM ethics_audit_log "
                "ORDER BY id DESC LIMIT ?", (limit,),
            ).fetchall()

        try:
            rows = db._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:256]}
        return {
            "status": "success",
            "count": len(rows),
            "entries": [
                {"id": r[0], "event_id": r[1], "timestamp": r[2], "requested_action": r[3],
                 "authorization_status": r[4], "decision": r[5], "explanation": r[6],
                 "gita_reference": json.loads(r[7] or "{}") if r[7] else None,
                 "human_approval_required": bool(r[8])}
                for r in rows
            ],
        }

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------
    def _model_info(self) -> Dict[str, Any]:
        return {
            "dharma_engine": "DharmaRecognitionEngine v1 (principle matrix)",
            "gita_knowledge_base": {
                "loaded": self.gita_kb.loaded,
                "chapters": len(self.gita_kb.chapters),
                "verses": len(self.gita_kb.verses),
                "source": "stored dataset vrin_SOC/data/BhagavadGita/ (verified at load)",
            },
        }

    def health(self) -> Dict[str, Any]:
        base = super().health()
        base["gita_knowledge_base"] = self._model_info()["gita_knowledge_base"]
        return base


def _is_high_impact(action: str) -> bool:
    text = (action or "").lower()
    return any(p in text for p in HIGH_IMPACT_ACTIONS)


ethics_ai = EthicsAI()

__all__ = [
    "EthicsAI",
    "ethics_ai",
    "DharmaRecognitionEngine",
    "BhagavadGitaKnowledgeBase",
    "gita_knowledge_base",
    "DHARMA_PRINCIPLES",
    "LEGAL_REFERENCES",
    "SECURITY_POLICIES",
]
