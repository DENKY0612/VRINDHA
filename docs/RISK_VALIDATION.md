# Risk-based, human-validated cybersecurity model

Vrindha does **not** claim that AI can be 100% accurate. Instead, it reduces the impact of false positives and false negatives by separating detection from authority.

## Operating principle

> Vrindha does not attempt to eliminate AI errors; it reduces their impact through multi-layer detection, risk scoring, threat-intelligence correlation, continuous feedback, explainable alerts, and human validation before critical responses.

## Architecture flow

```text
Data Collection
  ↓
Multi-Layer Detection
  ↓
Threat Intelligence + Correlation
  ↓
AI Analysis
  ↓
Risk & Confidence Score
  ↓
Human Validation
  ↓
Controlled Response
  ↓
Feedback & Continuous Improvement
```

## Multi-layer detection

The core risk engine combines independent signals instead of depending on one model:

- rule/signature-based detection
- anomaly detection
- threat-intelligence reputation
- behavioral analysis
- SIEM/log correlation
- AI/threat-agent reasoning

When several layers independently support the same finding, Vrindha increases both risk and confidence. Missing evidence is not treated as proof that something is clean.

## Risk scoring instead of yes/no labels

Vrindha returns scores such as:

```text
Risk Score: 87/100 — High
Confidence: 82/100 — High
```

The score can consider severity, confidence, threat-intelligence reputation, frequency, user/system behavior, and number of correlated alerts.

## Human-in-the-loop validation

Low-impact actions can happen immediately:

- log
- alert
- monitor
- collect more evidence

High-impact actions are parked until an analyst approves or rejects them:

- block IP
- isolate/quarantine host
- kill process
- disable account
- firewall deny/drop changes

Implementation entry points:

- `vrin_SOC/ml/risk_scoring.py` — explainable multi-layer score
- `vrin_SOC/automation/response_engine.py` — validation gate and controlled response
- `POST /incident/respond` — prepare response recommendation
- `POST /incident/respond/validate` — analyst approval/rejection gate
- `POST /ml/risk/feedback` — store analyst verdicts for continuous improvement

## Continuous learning

Analyst decisions are stored separately from raw AI output:

```text
AI Alert → Analyst: True Positive / False Positive / Benign / Unknown
        → Feedback Database
        → Model/rule evaluation and improvement
```

Only validated analyst outcomes should be used for future rule/model tuning. This avoids training on unverified AI guesses.

## Explainable alert example

```text
Risk: 91/100 — High
Confidence: 88/100 — High

Reasons:
- Suspicious login behavior detected
- Source IP associated with known malicious activity
- Multiple failed authentication attempts
- Abnormal access time
- SIEM/log correlation found related alerts

Recommended action:
Investigate immediately and require analyst validation before blocking, isolating,
or killing processes related to the source.
```
