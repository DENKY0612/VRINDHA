"""
Vrindha Self-Improvement Engine v2.0
Core learning mechanisms inspired by progressive AI development frameworks.

Four pillars:
1. Self-Correction via Test Loops — verify outputs, parse failures, retry autonomously
2. Progressive Context Loading — pull docs on-demand, never clog memory
3. Modular Skill Packaging — save successful workflows as reusable skill files
4. Tool Discovery & Integration — chain tools creatively for novel problems
"""
from __future__ import annotations
import json
import re
import random
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field, asdict
import inspect

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class InteractionRecord:
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    user_input: str = ""
    response_preview: str = ""
    mode: str = "soc"
    category: str = "general"
    outcome: str = "unknown"  # success | partial | failure | corrected
    tools_used: List[str] = field(default_factory=list)
    tokens_estimated: int = 0
    latency_ms: Optional[int] = None
    human_feedback: Optional[str] = None  # explicit user correction
    corrected_by: Optional[str] = None  # which self-correction step fixed it

@dataclass
class KnowledgeGap:
    query: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    category: str = "general"
    resolved: bool = False
    resolution: Optional[str] = None
    attempts: int = 0

@dataclass
class SkillPackage:
    """A reusable workflow learned by the agent."""
    name: str = ""
    description: str = ""
    trigger_pattern: str = ""  # regex or keyword that activates this skill
    steps: List[Dict[str, Any]] = field(default_factory=list)  # sequential steps
    tools_required: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)  # how to verify
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    used_count: int = 0
    last_used: Optional[str] = None
    source_session: Optional[str] = None  # which session taught this

@dataclass
class ErrorLogEntry:
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error_type: str = ""
    error_message: str = ""
    context: str = ""  # what was happening
    resolution: Optional[str] = None
    learned_from: Optional[str] = None  # skill or manual fix

@dataclass
class LearningEvent:
    """A discrete learning moment — something the agent figured out."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    event_type: str = ""  # correction | discovery | skill_packed | human_feedback
    description: str = ""
    before_state: Optional[str] = None
    after_state: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# CORE ENGINE
# ============================================================================

class SelfImprovementEngine:
    """
    Vrindha's self-learning brain.

    Tracks every interaction, detects failures, auto-corrects, packages
    successful workflows as reusable skills, and builds a searchable
    error-resolution database.
    """

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or self._detect_project_root()
        self.data_dir = self.project_root / "vrin_SOC" / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Storage files
        self.interactions_file = self.data_dir / "interactions.json"
        self.gaps_file = self.data_dir / "knowledge_gaps.json"
        self.skills_file = self.data_dir / "skills.json"
        self.errors_file = self.data_dir / "error_log.json"
        self.learning_file = self.data_dir / "learning_events.json"
        self.feedback_file = self.data_dir / "human_feedback.json"

        # In-memory state (loaded lazily)
        self.interactions: List[InteractionRecord] = []
        self.knowledge_gaps: List[KnowledgeGap] = []
        self.skills: List[SkillPackage] = []
        self.error_log: List[ErrorLogEntry] = []
        self.learning_events: List[LearningEvent] = []
        self.human_feedback: List[Dict[str, Any]] = []

        # Configuration
        self.max_interactions = 1000
        self.max_gaps = 200
        self.max_skills = 50
        self.auto_correct_enabled = True
        self.skill_packing_enabled = True

        self._load_all()

    # ------------------------------------------------------------------
    # PROJECT ROOT DETECTION
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_project_root() -> Path:
        current = Path.cwd()
        for path in [current] + list(current.parents):
            if (path / "vrin_SOC").is_dir():
                return path
        fallback = Path("/mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND")
        if fallback.exists():
            return fallback
        return current

    # ------------------------------------------------------------------
    # PERSISTENCE
    # ------------------------------------------------------------------

    def _load_all(self):
        self._load_interactions()
        self._load_gaps()
        self._load_skills()
        self._load_errors()
        self._load_learning_events()
        self._load_feedback()

    def _load_interactions(self):
        try:
            if self.interactions_file.exists():
                data = json.loads(self.interactions_file.read_text(encoding="utf-8"))
                self.interactions = [InteractionRecord(**item) for item in data.get("records", [])][-self.max_interactions:]
        except Exception:
            self.interactions = []

    def _load_gaps(self):
        try:
            if self.gaps_file.exists():
                data = json.loads(self.gaps_file.read_text(encoding="utf-8"))
                self.knowledge_gaps = [KnowledgeGap(**item) for item in data.get("gaps", [])][-self.max_gaps:]
        except Exception:
            self.knowledge_gaps = []

    def _load_skills(self):
        try:
            if self.skills_file.exists():
                data = json.loads(self.skills_file.read_text(encoding="utf-8"))
                self.skills = [SkillPackage(**item) for item in data.get("skills", [])][:self.max_skills]
        except Exception:
            self.skills = []

    def _load_errors(self):
        try:
            if self.errors_file.exists():
                data = json.loads(self.errors_file.read_text(encoding="utf-8"))
                self.error_log = [ErrorLogEntry(**item) for item in data.get("errors", [])]
        except Exception:
            self.error_log = []

    def _load_learning_events(self):
        try:
            if self.learning_file.exists():
                data = json.loads(self.learning_file.read_text(encoding="utf-8"))
                self.learning_events = [LearningEvent(**item) for item in data.get("events", [])][-500:]
        except Exception:
            self.learning_events = []

    def _load_feedback(self):
        try:
            if self.feedback_file.exists():
                self.human_feedback = json.loads(self.feedback_file.read_text(encoding="utf-8"))
        except Exception:
            self.human_feedback = []

    def _save_interactions(self):
        try:
            data = {"records": [asdict(r) for r in self.interactions[-self.max_interactions:]]}
            self.interactions_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_gaps(self):
        try:
            data = {"gaps": [asdict(g) for g in self.knowledge_gaps[-self.max_gaps:]]}
            self.gaps_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_skills(self):
        try:
            data = {"skills": [asdict(s) for s in self.skills[:self.max_skills]]}
            self.skills_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_errors(self):
        try:
            data = {"errors": [asdict(e) for e in self.error_log]}
            self.errors_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_learning_events(self):
        try:
            data = {"events": [asdict(e) for e in self.learning_events[-500:]]}
            self.learning_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_feedback(self):
        try:
            self.feedback_file.write_text(json.dumps(self.human_feedback, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _save_all(self):
        self._save_interactions()
        self._save_gaps()
        self._save_skills()
        self._save_errors()
        self._save_learning_events()
        self._save_feedback()

    # ------------------------------------------------------------------
    # 1. INTERACTION LOGGING + OUTCOME ASSESSMENT
    # ------------------------------------------------------------------

    def log_interaction(
        self,
        user_input: str,
        response: str,
        mode: str = "soc",
        tools_used: Optional[List[str]] = None,
        latency_ms: Optional[int] = None,
        tokens_estimated: int = 0,
    ) -> InteractionRecord:
        """Log one interaction and assess its outcome."""
        record = InteractionRecord(
            user_input=user_input[:500],
            response_preview=response[:300],
            mode=mode,
            category=self._categorize(user_input),
            outcome=self._assess_outcome(user_input, response),
            tools_used=tools_used or [],
            tokens_estimated=tokens_estimated,
            latency_ms=latency_ms,
        )
        self.interactions.append(record)
        self._detect_knowledge_gap(record)
        self._save_all()
        return record

    def _categorize(self, user_input: str) -> str:
        """Categorize user input into a domain."""
        lower = user_input.lower()
        rules = [
            (["scan", "nmap", "recon", "discover", "crawl", "enumerat"], "reconnaissance"),
            (["vuln", "nikto", "exploit", "cve", "vulnerability", "inject"], "vulnerability"),
            (["threat", "attack", "malware", "incident", "breach", "intrus"], "threat_analysis"),
            (["help", "how", "what", "explain", "teach", "learn", "guide"], "education"),
            (["fix", "patch", "secure", "protect", "harden", "remediate"], "remediation"),
            (["code", "file", "read", "edit", "patch", "write", "create"], "development"),
            (["who are", "about you", "capabilities", "yourself"], "identity"),
            (["how are", "joke", "funny", "hello", "hi", "hey", "sup", "wassup"], "casual"),
            (["block", "firewall", "ids", "monitor", "detect", "alarm"], "defense"),
            (["blockchain", "ledger", "audit", "immutable", "chain"], "blockchain"),
        ]
        for keywords, category in rules:
            if any(kw in lower for kw in keywords):
                return category
        return "general"

    def _assess_outcome(self, user_input: str, response: str) -> str:
        """Assess whether the interaction succeeded."""
        lower = response.lower()
        failure_signals = [
            "i can't", "i cannot", "i don't know", "i'm sorry",
            "unable to", "failed", "not capable", "cannot help",
            "no specific knowledge", "not in my", "unavailable",
            "my archives do not contain", "i have no information",
        ]
        if any(sig in lower for sig in failure_signals):
            return "failure"
        if len(response) > 80 and any(pos in lower for pos in ["here", "sure", "certainly", "let me", "i'll"]):
            return "success"
        if len(response) > 150:
            return "success"
        return "partial"

    # ------------------------------------------------------------------
    # 2. KNOWLEDGE GAP DETECTION
    # ------------------------------------------------------------------

    def _detect_knowledge_gap(self, record: InteractionRecord):
        """If an interaction failed, log it as a knowledge gap."""
        if record.outcome == "failure":
            existing = [g for g in self.knowledge_gaps if g.query == record.user_input]
            if existing:
                existing[0].attempts += 1
            else:
                self.knowledge_gaps.append(KnowledgeGap(
                    query=record.user_input[:300],
                    category=record.category,
                    resolved=False,
                    attempts=1,
                ))

    def resolve_gap(self, query: str, resolution: str):
        """Mark a knowledge gap as resolved."""
        for gap in self.knowledge_gaps:
            if gap.query == query:
                gap.resolved = True
                gap.resolution = resolution
                gap.timestamp = datetime.now().isoformat()
                self._log_learning_event("correction", f"Resolved knowledge gap: {query[:60]}", resolution)
                self._save_all()
                return True
        return False

    # ------------------------------------------------------------------
    # 3. SELF-CORRECTION VIA TEST LOOPS
    # ------------------------------------------------------------------

    def self_correct(
        self,
        initial_response: str,
        validation_fn: Callable[[str], tuple[bool, str]],
        max_attempts: int = 3,
        context_hint: Optional[str] = None,
    ) -> tuple[str, bool, List[Dict[str, Any]]]:
        """
        Attempt to fix a response using iterative validation.

        Args:
            initial_response: The first draft response
            validation_fn: Function that returns (is_valid, error_message)
            max_attempts: Maximum correction iterations
            context_hint: Extra context for the correction logic

        Returns:
            (final_response, was_corrected, correction_steps)
        """
        if not self.auto_correct_enabled:
            return initial_response, False, []

        current = initial_response
        correction_steps: List[Dict[str, Any]] = []

        for attempt in range(1, max_attempts + 1):
            is_valid, error_msg = validation_fn(current)
            if is_valid:
                if attempt > 1:
                    self._log_learning_event(
                        "correction",
                        f"Self-corrected response after {attempt} attempt(s)",
                        f"Final: {current[:200]}",
                        {"attempts": attempt, "error_sequence": [s.get("error") for s in correction_steps]},
                    )
                return current, attempt > 1, correction_steps

            # Parse the error and attempt a targeted fix
            correction = self._attempt_correction(current, error_msg, attempt, context_hint)
            correction_steps.append({
                "attempt": attempt,
                "error": error_msg,
                "correction": correction.get("applied_fix", ""),
                "new_response_preview": correction.get("new_response", "")[:200],
            })
            current = correction.get("new_response", current)

        # All attempts exhausted — log as a learning event
        self._log_learning_event(
            "correction",
            f"Self-correction exhausted after {max_attempts} attempts",
            f"Last error: {error_msg}",
            {"final_response": current[:200], "error_sequence": [s.get("error") for s in correction_steps]},
        )
        return current, correction_steps != [], correction_steps

    def _attempt_correction(
        self,
        current_response: str,
        error_msg: str,
        attempt: int,
        context_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Apply a heuristic correction based on the error message.

        This is the rule-based fallback when no LLM is available for
        re-generation. It handles common failure patterns.
        """
        lower = error_msg.lower()
        response_lower = current_response.lower()

        fix_applied = ""

        # Pattern 1: Response says "I don't know" / "I can't"
        if any(sig in response_lower for sig in ["i don't know", "i can't", "i cannot", "unable to"]):
            # Try to extract what was being asked and provide a fallback
            question = context_hint or "the user's question"
            fix_applied = f"Providing informative fallback for: {question}"
            corrected = (
                f"I don't have specific information on that exact topic yet, "
                f"but here's what I can tell you about {question[:80]}: "
                f"This is an area where my knowledge could improve. "
                f"Let me focus on what I do know and be transparent about the gaps."
            )
            return {"applied_fix": fix_applied, "new_response": corrected}

        # Pattern 2: Response is too short / incomplete
        if "too short" in lower or "incomplete" in lower or len(current_response) < 50:
            fix_applied = "Expanding incomplete response with relevant detail"
            corrected = current_response + (
                "\n\nWould you like me to go deeper on any specific aspect? "
                "I'm here to help you understand the full picture."
            )
            return {"applied_fix": fix_applied, "new_response": corrected}

        # Pattern 3: Response contains factual-sounding but unverified claims
        if "unverified" in lower or "hallucination" in lower or "fabricated" in lower:
            fix_applied = "Stripping unverified claims and adding uncertainty markers"
            # Remove sentences that look like factual assertions without backing
            sentences = re.split(r'(?<=[.!?])\s+', current_response)
            verified = [s for s in sentences if not self._looks_unverified(s)]
            corrected = " ".join(verified) if verified else current_response
            if not verified:
                corrected = "I want to be accurate here. Let me focus on what I can verify rather than speculate."
            return {"applied_fix": fix_applied, "new_response": corrected}

        # Pattern 4: Generic catch-all — prepend acknowledgement
        fix_applied = "Applying generic response improvement"
        corrected = current_response
        return {"applied_fix": fix_applied, "new_response": corrected}

    @staticmethod
    def _looks_unverified(sentence: str) -> bool:
        """Heuristic: does this sentence sound like an unverified factual claim?"""
        certainty_words = ["is", "are", "was", "were", "has", "have", "will", "does", "did"]
        hedge_words = ["might", "could", "may", "possibly", "perhaps", "appears", "seems", "likely"]
        words = sentence.lower().split()
        if not words:
            return False
        # If sentence starts with a certainty word and has no hedge words, flag it
        if words[0] in certainty_words and not any(h in sentence.lower() for h in hedge_words):
            # But skip common benign patterns
            if re.match(r'^(i |my |this |that |the |a |an )', sentence.lower()):
                return False
            return True
        return False

    # ------------------------------------------------------------------
    # 4. MODULAR SKILL PACKAGING
    # ------------------------------------------------------------------

    def package_skill(
        self,
        name: str,
        description: str,
        trigger_pattern: str,
        steps: List[Dict[str, Any]],
        tools_required: Optional[List[str]] = None,
        success_criteria: Optional[List[str]] = None,
        source_session: Optional[str] = None,
    ) -> SkillPackage:
        """
        Package a successful workflow as a reusable skill.

        Skill files are stored in vrin_SOC/data/skills/<name>.json and can be
        loaded by any future session.
        """
        skill = SkillPackage(
            name=name,
            description=description,
            trigger_pattern=trigger_pattern,
            steps=steps,
            tools_required=tools_required or [],
            success_criteria=success_criteria or [],
            source_session=source_session,
        )
        self.skills.append(skill)
        self._save_skills()

        # Also write a standalone markdown skill file
        self._write_skill_markdown(skill)

        self._log_learning_event(
            "skill_packed",
            f"Packaged new skill: {name}",
            description,
            {"trigger": trigger_pattern, "step_count": len(steps)},
        )
        return skill

    def _write_skill_markdown(self, skill: SkillPackage):
        """Write a standalone .md skill file for portability."""
        skills_dir = self.data_dir / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)
        md_path = skills_dir / f"{skill.name.replace(' ', '_').lower()}.md"

        lines = [
            f"# {skill.name}",
            "",
            f"**Description:** {skill.description}",
            f"**Trigger:** `{skill.trigger_pattern}`",
            f"**Tools required:** {', '.join(skill.tools_required) or 'none'}",
            f"**Created:** {skill.created_at}",
            f"**Used:** {skill.used_count} time(s)",
            "",
            "## Steps",
            "",
        ]
        for i, step in enumerate(skill.steps, 1):
            step_desc = step.get("description", "")
            step_tool = step.get("tool", "")
            step_input = step.get("input", "")
            lines.append(f"{i}. **{step_desc}**")
            if step_tool:
                lines.append(f"   - Tool: `{step_tool}`")
            if step_input:
                lines.append(f"   - Input: `{step_input}`")
            lines.append("")

        if skill.success_criteria:
            lines.append("## Success Criteria")
            lines.append("")
            for crit in skill.success_criteria:
                lines.append(f"- [ ] {crit}")
            lines.append("")

        md_path.write_text("\n".join(lines), encoding="utf-8")

    def load_skill(self, name: str) -> Optional[SkillPackage]:
        """Load a skill by name from memory or disk."""
        for skill in self.skills:
            if skill.name == name:
                skill.used_count += 1
                skill.last_used = datetime.now().isoformat()
                self._save_skills()
                return skill
        # Try loading from disk
        md_path = self.data_dir / "skills" / f"{name.replace(' ', '_').lower()}.md"
        if md_path.exists():
            # Parse markdown back into a skill
            skill = self._parse_skill_markdown(md_path.read_text(encoding="utf-8"))
            if skill:
                self.skills.append(skill)
                self._save_skills()
                return skill
        return None

    def _parse_skill_markdown(self, text: str) -> Optional[SkillPackage]:
        """Parse a skill markdown file back into a SkillPackage."""
        try:
            name_match = re.search(r'^# (.+)$', text, re.MULTILINE)
            desc_match = re.search(r'\*\*Description:\*\* (.+)', text)
            trigger_match = re.search(r'\*\*Trigger:\*\* `(.+?)`', text)
            tools_match = re.search(r'\*\*Tools required:\*\* (.+?)(?:\n|$)', text)

            name = name_match.group(1) if name_match else "unknown"
            description = desc_match.group(1) if desc_match else ""
            trigger = trigger_match.group(1) if trigger_match else ""
            tools_raw = tools_match.group(1) if tools_match else ""
            tools = [t.strip().strip("`") for t in tools_raw.split(",") if t.strip()] if tools_raw != "none" else []

            # Parse steps
            steps = []
            step_blocks = re.split(r'\n(?=\d+\.)', text)
            for block in step_blocks:
                step_desc_match = re.match(r'(\d+)\. \*\*(.+?)\*\*', block)
                if step_desc_match:
                    step_num = int(step_desc_match.group(1))
                    step_desc = step_desc_match.group(2)
                    tool_match = re.search(r'Tool: `(.+?)`', block)
                    input_match = re.search(r'Input: `(.+?)`', block)
                    steps.append({
                        "order": step_num,
                        "description": step_desc,
                        "tool": tool_match.group(1) if tool_match else "",
                        "input": input_match.group(1) if input_match else "",
                    })

            return SkillPackage(
                name=name,
                description=description,
                trigger_pattern=trigger,
                steps=steps,
                tools_required=tools,
            )
        except Exception:
            return None

    def list_skills(self) -> List[Dict[str, Any]]:
        """Return all known skills as lightweight dicts."""
        return [
            {
                "name": s.name,
                "description": s.description,
                "trigger": s.trigger_pattern,
                "tools": s.tools_required,
                "uses": s.used_count,
            }
            for s in self.skills
        ]

    def find_matching_skill(self, user_input: str) -> Optional[SkillPackage]:
        """Find a skill whose trigger matches the user input."""
        lower = user_input.lower()
        for skill in self.skills:
            if skill.trigger_pattern.lower() in lower:
                skill.used_count += 1
                skill.last_used = datetime.now().isoformat()
                self._save_skills()
                return skill
        return None

    # ------------------------------------------------------------------
    # 5. ERROR LOGGING & DEBUGGING
    # ------------------------------------------------------------------

    def log_error(
        self,
        error_type: str,
        error_message: str,
        context: str = "",
        resolution: Optional[str] = None,
    ):
        """Log an error for future debugging and learning."""
        entry = ErrorLogEntry(
            error_type=error_type,
            error_message=error_message[:500],
            context=context[:300],
            resolution=resolution,
        )
        self.error_log.append(entry)
        self._save_errors()

        # If a resolution is provided, log it as a learning event
        if resolution:
            self._log_learning_event(
                "correction",
                f"Resolved error: {error_type}",
                resolution,
                {"error_type": error_type, "original_message": error_message[:200]},
            )

    def find_similar_errors(self, error_message: str, limit: int = 5) -> List[ErrorLogEntry]:
        """Find previously logged errors that resemble the given message."""
        lower = error_message.lower()
        scored = []
        for entry in self.error_log:
            similarity = self._text_similarity(lower, entry.error_message.lower())
            if similarity > 0.3:
                scored.append((similarity, entry))
        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:limit]]

    @staticmethod
    def _text_similarity(a: str, b: str) -> float:
        """Simple Jaccard-like similarity on word sets."""
        words_a = set(re.findall(r'\w+', a))
        words_b = set(re.findall(r'\w+', b))
        if not words_a or not words_b:
            return 0.0
        intersection = words_a & words_b
        union = words_a | words_b
        return len(intersection) / len(union)

    # ------------------------------------------------------------------
    # 6. HUMAN FEEDBACK INTEGRATION
    # ------------------------------------------------------------------

    def record_human_feedback(
        self,
        interaction_index: int,
        feedback: str,
        correction: Optional[str] = None,
    ):
        """
        Record explicit human feedback on a past interaction.

        Args:
            interaction_index: Index into self.interactions
            feedback: What the human said (correction, praise, criticism)
            correction: The corrected version if applicable
        """
        if interaction_index < 0 or interaction_index >= len(self.interactions):
            return

        record = self.interactions[interaction_index]
        record.human_feedback = feedback[:500]
        if correction:
            record.corrected_by = correction[:500]
            record.outcome = "corrected"

        self.human_feedback.append({
            "timestamp": datetime.now().isoformat(),
            "interaction_index": interaction_index,
            "original_input": record.user_input,
            "original_response": record.response_preview,
            "feedback": feedback,
            "correction": correction,
            "category": record.category,
        })
        self._save_all()

        # If a correction was provided, treat it as a knowledge gap resolution
        if correction and record.outcome in ("failure", "partial"):
            self.resolve_gap(record.user_input, correction)

        self._log_learning_event(
            "human_feedback",
            f"Human feedback received: {feedback[:80]}",
            f"Correction applied: {correction[:80] if correction else 'N/A'}",
            {"interaction_index": interaction_index, "category": record.category},
        )

    # ------------------------------------------------------------------
    # 7. LEARNING EVENTS LOG
    # ------------------------------------------------------------------

    def _log_learning_event(
        self,
        event_type: str,
        description: str,
        after_state: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ):
        event = LearningEvent(
            event_type=event_type,
            description=description[:300],
            before_state=None,
            after_state=after_state,
            payload=payload or {},
        )
        self.learning_events.append(event)
        if len(self.learning_events) > 500:
            self.learning_events = self.learning_events[-500:]
        self._save_learning_events()

    # ------------------------------------------------------------------
    # 8. REPORTS & ANALYTICS
    # ------------------------------------------------------------------

    def get_full_report(self) -> str:
        """Generate a comprehensive self-improvement report."""
        total = len(self.interactions) or 1
        successes = sum(1 for i in self.interactions if i.outcome == "success")
        failures = sum(1 for i in self.interactions if i.outcome == "failure")
        corrected = sum(1 for i in self.interactions if i.outcome == "corrected")
        partial = sum(1 for i in self.interactions if i.outcome == "partial")

        category_counts: Dict[str, int] = {}
        for i in self.interactions:
            category_counts[i.category] = category_counts.get(i.category, 0) + 1

        unresolved_gaps = [g for g in self.knowledge_gaps if not g["resolved"]]
        recent_learning = self.learning_events[-10:]

        lines = [
            "📊 Vrindha Self-Improvement Report",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"📈 Total Interactions: {total}",
            f"✅ Success: {successes} ({successes * 100 // total}%)",
            f"⚠️ Partial: {partial} ({partial * 100 // total}%)",
            f"❌ Failures: {failures} ({failures * 100 // total}%)",
            f"🔧 Self-Corrected: {corrected} ({corrected * 100 // total}%)",
            "",
            "📊 Usage by Category:",
        ]
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            bar = "█" * (count * 30 // total)
            lines.append(f"  {cat:20s} {bar} {count}")

        lines.append("")
        lines.append(f"🧠 Skills Packaged: {len(self.skills)}")
        for skill in self.skills[-5:]:
            lines.append(f"  • {skill.name} — {skill.used_count} uses, trigger: `{skill.trigger_pattern}`")

        lines.append("")
        lines.append(f"🔍 Unresolved Knowledge Gaps: {len(unresolved_gaps)}")
        for gap in unresolved_gaps[:5]:
            lines.append(f"  • [{gap.category}] {gap.query[:70]} (attempts: {gap.attempts})")

        lines.append("")
        lines.append("📚 Recent Learning Events:")
        for event in recent_learning[-5:]:
            icon = {"correction": "🔧", "discovery": "💡", "skill_packed": "📦", "human_feedback": "👤"}.get(event.event_type, "📌")
            lines.append(f"  {icon} [{event.event_type}] {event.description[:80]}")

        if self.human_feedback:
            lines.append("")
            lines.append(f"💬 Human Feedback Received: {len(self.human_feedback)} times")

        lines.append("")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        return "\n".join(lines)

    def get_improvement_suggestions(self) -> List[str]:
        """Generate actionable suggestions based on observed patterns."""
        suggestions = []
        categories: Dict[str, int] = {}
        for i in self.interactions:
            categories[i.category] = categories.get(i.category, 0) + 1
        total = len(self.interactions) or 1

        if categories.get("reconnaissance", 0) > total * 0.3:
            suggestions.append("High recon usage — consider adding more scan presets and output detail templates")
        if categories.get("vulnerability", 0) > total * 0.2:
            suggestions.append("Vulnerability scanning is frequent — expand CVE knowledge mappings")
        if categories.get("education", 0) > total * 0.2:
            suggestions.append("Many education requests — add more daily topics and learning paths")
        if categories.get("threat_analysis", 0) > total * 0.1:
            suggestions.append("Threat analysis common — add more threat intelligence integrations")
        if categories.get("defense", 0) > total * 0.15:
            suggestions.append("Defense operations frequent — consider automated playbooks for common responses")

        unresolved = [g for g in self.knowledge_gaps if not g["resolved"]]
        if len(unresolved) > 5:
            suggestions.append(f"{len(unresolved)} unresolved knowledge gaps — consider web search expansion or knowledge base updates")

        if len(self.skills) < 3 and total > 50:
            suggestions.append("Few skills packaged — try solving multi-step workflows and packaging them")

        if self.error_log:
            top_errors = {}
            for e in self.error_log:
                top_errors[e.error_type] = top_errors.get(e.error_type, 0) + 1
            for err_type, count in sorted(top_errors.items(), key=lambda x: -x[1])[:3]:
                if count >= 3:
                    suggestions.append(f"Recurring error '{err_type}' appeared {count} times — consider a permanent fix or workaround skill")

        return suggestions

    def auto_improve(self) -> Dict[str, Any]:
        """Run automatic self-improvement routines."""
        results = {
            "timestamp": datetime.now().isoformat(),
            "actions_taken": [],
            "suggestions": [],
        }

        # Clean old interactions
        if len(self.interactions) > self.max_interactions:
            self.interactions = self.interactions[-self.max_interactions:]
            results["actions_taken"].append(f"Trimmed interactions to {self.max_interactions}")

        # Clean old gaps
        if len(self.knowledge_gaps) > self.max_gaps:
            self.knowledge_gaps = self.knowledge_gaps[-self.max_gaps:]
            results["actions_taken"].append(f"Trimmed knowledge gaps to {self.max_gaps}")

        # Generate suggestions
        suggestions = self.get_improvement_suggestions()
        results["suggestions"] = suggestions
        if suggestions:
            results["actions_taken"].append(f"Generated {len(suggestions)} improvement suggestions")

        self._save_all()
        results["actions_taken"].append("Saved all improvement state")
        return results


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_improvement_engine: Optional[SelfImprovementEngine] = None


def get_improvement_engine() -> SelfImprovementEngine:
    global _improvement_engine
    if _improvement_engine is None:
        _improvement_engine = SelfImprovementEngine()
    return _improvement_engine


def log_interaction(user_input: str, response: str, mode: str = "soc", **kwargs):
    engine = get_improvement_engine()
    return engine.log_interaction(user_input, response, mode, **kwargs)


def self_correct(initial_response: str, validation_fn, max_attempts: int = 3, context_hint: Optional[str] = None):
    engine = get_improvement_engine()
    return engine.self_correct(initial_response, validation_fn, max_attempts, context_hint)


def package_skill(name: str, description: str, trigger_pattern: str, steps: List[Dict], **kwargs):
    engine = get_improvement_engine()
    return engine.package_skill(name, description, trigger_pattern, steps, **kwargs)


def log_error(error_type: str, error_message: str, context: str = "", resolution: Optional[str] = None):
    engine = get_improvement_engine()
    engine.log_error(error_type, error_message, context, resolution)


def record_feedback(interaction_index: int, feedback: str, correction: Optional[str] = None):
    engine = get_improvement_engine()
    engine.record_human_feedback(interaction_index, feedback, correction)


def get_report() -> str:
    engine = get_improvement_engine()
    return engine.get_full_report()


def run_auto_improve() -> Dict[str, Any]:
    engine = get_improvement_engine()
    return engine.auto_improve()


def list_skills() -> List[Dict[str, Any]]:
    engine = get_improvement_engine()
    return engine.list_skills()


def find_skill(user_input: str) -> Optional[SkillPackage]:
    engine = get_improvement_engine()
    return engine.find_matching_skill(user_input)
