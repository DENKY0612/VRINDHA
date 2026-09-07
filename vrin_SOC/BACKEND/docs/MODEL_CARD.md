# Model Cards — HIVE Coordination Models

Models in the coordination layer are **versioned, documented, and
deterministic-by-default**. The registry (`DataScienceAI.registry`, exposed
via `GET /data-science/models`) stores per model: name, version, algorithm,
features, hyperparameters, status (`production | candidate | retired`),
training date, and training dataset provenance. Production models are never
silently replaced: `promote()` retires the previous production version, and
re-registering the same version with different metadata is rejected.

---

## anomaly@v1 — Interpretable anomaly detector

- **Intended use:** flag unusual security/telemetry events in real time and
  explain *why*, feeding the risk engine and SOC triage.
- **Algorithm:** three interpretable signals, final score = max of the
  available signals (threshold 0.6):
  1. rolling-baseline z-score (1 h window; per-feature ≥3σ deviations are
     named in the explanation),
  2. deterministic rule signals (failed logins ≥5, unusual port, severity),
  3. IsolationForest — **only** when scikit-learn is installed and ≥20
     baseline rows exist.
- **Data:** rolling operational baseline built from ingested events; no
  external labels required.
- **Hyperparameters:** `baseline_window: 200`, `baseline_min_samples: 5`,
  `threshold: 0.6`.
- **Evaluation:** see §Evaluation below (validated labels only).
- **Limitations:**
  - Below 5 baseline rows the z-score is unavailable and the explanation
    says so (`fallback_mode: true`); rules carry the decision.
  - z-score assumes near-normal baselines; constant-variance features are
    skipped (documented behavior).
  - Scores are recommendation-grade, not truth.

## risk@v1 — Explainable weighted risk engine

- **Intended use:** combine anomaly, threat intelligence, severity,
  authentication, and network signals into one 0–1 risk score with a
  hand-recomputable explanation.
- **Algorithm:** normalized weighted linear combination:

  | factor | weight |
  |---|---|
  | anomaly | 0.35 |
  | threat_intel | 0.25 |
  | event_severity | 0.20 |
  | auth_anomaly | 0.15 |
  | network_anomaly | 0.05 |

  Severity mapping: low 0.1 / medium 0.45 / high 0.75 / critical 1.0.
  Output bands: ≥0.80 critical, ≥0.60 high, ≥0.30 medium, else low.
- **Data:** no learned weights — the "training dataset" is the rule
  documentation itself (deterministic).
- **Honesty rules:**
  - `threat_intel` contributes 1.0 **only** on a confirmed malicious IOC;
    when TI is unavailable the factor is a small explicit signal and the
    explainability notes the degradation (unavailable ≠ clean).
  - Every `RiskResult` lists each factor's contribution and a Σ line, so the
    score can be recomputed from the explanation alone.
- **Limitations:** weights are hand-set and documented, not learned; changing
  them is a versioned model change (`risk@v2`), not runtime drift.

## dharma@v1 — Ethics & compliance decision engine

- **Intended use:** classify a *requested action + context* (never a person)
  and produce a governance decision (allow / allow_with_warning /
  require_authorization / safe_alternative / deny / escalate_to_human).
- **Method:** layered rule matrix — intent → authorization → security policy
  → cyber-law guidance (labeled "not legal advice") → Dharma principle
  mapping (SATYA, AHIMSA, ASTEYA, DUTY, NON_MALICE, …) → verified Gita
  reference → decision. Word-boundary pattern matching avoids substring
  false-positives (e.g. "listen" ≠ "steal").
- **Gita knowledge base:** loaded only from the stored dataset
  `vrin_SOC/data/BhagavadGita/chapter_1..18.json` (18 chapters, 700 verses,
  verified at load). Any cited verse must exist in the dataset; the
  knowledge base returns `None` for anything else, and the API answers
  `404` rather than fabricating a verse.
- **Guarantees:** no user moral scoring, no religious profiling, no
  permanent moral ranking; guidance is optional and can be declined
  (secular fallback = the policy/legal/principle reasoning without Gita).
- **Audit:** every decision is persisted (`ethics_audit_log`).

## Feedback & evaluation protocol (applies to anomaly@v1 / risk@v1)

- Only **human-validated** outcomes (`confirmed_attack` / `false_positive`)
  with provenance (`validated_by`) enter evaluation. Model self-predictions
  are rejected — the contamination guard prevents label noise from feeding
  back into the system.
- Metrics: per-class counts and score statistics, class **separation**, and a
  threshold scan reporting precision/recall/F1 (accuracy is explicitly *not*
  the headline metric). Without sufficient labels the API returns
  `insufficient_data` with empty metrics — numbers are never invented.
