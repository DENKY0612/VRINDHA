# Data Science AI — Pipeline & Model Documentation

`vrin_SOC/coordination/data_science_ai.py` implements the full data-science
pipeline mandated by the implementation plan:

```text
ingest → validate → clean → integrate → EDA → features → anomaly
       → risk → evaluate → explain → feedback
```

The agent is **analytical only**: it attaches explanations to events and
publishes them on the event bus. It never executes high-impact actions — that
authority belongs to the human approval gate (see `docs/SECURITY.md`).

## 1. Ingestion & validation

`ingest(payload) -> (SecurityEvent | None, DataQualityReport)`

Checks (in order): payload type → `event_type` present → timestamp parseable
and not >5 min in the future (clock-skew guard) → severity in
`{low, medium, high, critical}` → entity IP syntactically valid (via
`ipaddress`) → full Pydantic schema validation → **deduplication** by explicit
`event_id` or a stable SHA-256 content hash
(`event_type | entity.primary | timestamp | flattened data`).

Every rejection is **recorded** (`DataQualityReport.rejected_records` with
payload excerpt, reason, timestamp; in-process bounded buffer) — nothing is
silently discarded, and rejections are visible through `/data-science/status`
and the coordinator dashboard.

## 2. Feature engineering (no leakage)

16 features per event, computed over **rolling time windows** that only include
events *strictly before* the current event's timestamp:

```
failed_login_count, successful_login_count, unique_source_ips,
connection_count, unusual_port_count, bytes_sent_kb, bytes_received_kb,
process_count, new_process_count, cpu_usage, memory_usage, disk_usage,
authentication_frequency, hour_of_day, is_weekend
```

- Windows: 1 min / 5 min / 15 min / 1 h / 24 h (row counts exposed per event).
- **No-label guarantee:** features are derived from raw telemetry only; the
  outcome label (`confirmed_attack` / `false_positive`) is never part of any
  feature. `build_features()` reads the window *before* appending the event's
  own row, so an event never contributes to its own feature vector.
- Unusual ports: fixed, documented set `{4444, 6666, 1337, 31337, 31338}`.

## 3. Anomaly detection (interpretable first)

`detect_anomaly(event)` combines three interpretable signals; the score is the
max of the available signals, threshold **0.6**:

1. **Rolling-baseline z-score** over the 1 h window (needs ≥5 baseline rows).
   Features deviating ≥3σ are named in the explanation
   (`"failed_login_count=20.00 deviates 39.0σ from rolling baseline"`).
2. **Deterministic rule signals** (always available, no model):
   failed logins ≥5 in window (+0.4), unusual port seen (+0.3),
   severity ≥ high (+0.2).
3. **IsolationForest** (only when scikit-learn is installed **and** ≥20
   baseline rows). When sklearn is absent the system does **not** pretend —
   the explanation states which signals were used.

`AnomalyResult` carries `anomaly_score`, `is_anomaly`, `confidence`,
`explanation[]`, `model_version`, and `fallback_mode` (true only when the
baseline is too small for z-score — then rule signals carry the decision).

## 4. Risk engine (weighted, explainable)

`score_risk(event)` — a weighted linear combination with **documented**
weights (`RiskConfig`, normalized before use):

| Factor | Weight | Meaning |
|---|---|---|
| `anomaly` | 0.35 | anomaly score from §3 |
| `threat_intel` | 0.25 | 1.0 only when TI confirmed a **malicious** IOC; 0 when clean; small explicit signal + honest note when TI is *unavailable* (unavailable ≠ clean) |
| `event_severity` | 0.20 | low 0.1 / medium 0.45 / high 0.75 / critical 1.0 |
| `auth_anomaly` | 0.15 | normalized failed-login count in window |
| `network_anomaly` | 0.05 | unusual ports + outbound volume signals |

Severity thresholds on the combined score: ≥0.80 `critical`, ≥0.60 `high`,
≥0.30 `medium`, else `low`.

`RiskResult` exposes every `factor` with its `contribution` plus an
`explainability` list ending in the Σ line, so any score can be recomputed by
hand from the explanation.

## 5. Model registry & versioning

`_ModelRegistry` (in-process, thread-safe):

- `register(ModelMetadata)` — same `(name, version)` with *different*
  metadata is **rejected** (no silent artifact swap); seeded production
  models register as the active production version.
- `promote(name, version)` — sets the target to `production` and **retires**
  (does not delete) any other production version of that model.
- `production(name)` — active version; `all()` — full history with statuses
  (`production | candidate | retired`).

Seeded models: `anomaly@v1` (z-score + rolling baseline, + IsolationForest
when sklearn present) and `risk@v1` (documented weighted factors) — both
deterministic and inspectable. `GET /data-science/models` returns the
registry contents including hyperparameters and training provenance.

## 6. Evaluation (metrics, not just accuracy)

`evaluate()` compares stored anomaly scores (from bus history) against
**validated** labels:

- Requires both classes present for separation metrics; otherwise
  `insufficient_data` with `metrics: {}` — **metrics are never fabricated**.
- Reports: `labeled_samples`, `positive_count`, `negative_count`,
  mean/σ per class, `separation` (positive vs negative mean gap), and
  threshold scan with `precision`, `recall`, `f1` at the best F1
  `best_threshold`. The response note states that accuracy is intentionally
  not the headline metric.
- Empty-class means are `null`, never 0-filled.

## 7. Feedback loop (contamination guard)

`record_outcome(event_id, label, validated_by, validated=True)` is the only
path into the learning store:

- `validated=False` (e.g. an ML self-prediction) → **rejected**, counted.
- missing `validated_by` provenance → **rejected**.
- accepted outcomes are stored in `incident_outcomes` (SQLite) and become
  `validated_samples()` — the *only* rows `evaluate()` may use.

After human approval of an incident, the Commander records the validated
conclusion into Knowledge AI **and** feeds the labeled event ids to
`record_outcome`, closing the loop: human decision → validated lesson →
model evaluation improvement, all auditable.

## 8. What is deliberately not done

- No training on raw, unvalidated data; no label leakage into features.
- No online weight changes; changing `RiskConfig` weights is a documented,
  versioned model change, not runtime drift.
- No prediction served as fact: anomaly/risk scores are always
  *recommendation-grade* signals with explanations and confidence.
