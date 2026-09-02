# Vrindha AI — Controlled Autonomous Response & Safety

> **"The higher the potential impact of an action, the stronger the verification required."**
>
> Autonomous where safe. Assisted where uncertain. Human-controlled where dangerous.

Vrindha does **not** claim that "our AI autonomously controls cybersecurity".
Vrindha implements **controlled autonomy**: the level of automation is
proportional to the **risk** and the **reversibility** of the action.

| Situation risk | What Vrindha does |
|---|---|
| **LOW** | Auto-monitor (LEVEL 1: read-only actions, automatic under policy) |
| **MEDIUM** | Recommend a reversible, time-limited action → **human approval** → execute → monitor |
| **HIGH** | Verify → policy → **human approval** → controlled containment → audit → rollback |
| **CRITICAL** | Multi-source verification → **human approval** — or an *explicitly configured* emergency policy for temporary, reversible containment with immediate human notification and automatic expiry |

The full contract text is `VRINDHA_RESPONSE_PROMPT` in
[`vrin_SOC/coordination/controlled_response.py`](../vrin_SOC/coordination/controlled_response.py)
and is served verbatim by `GET /response/prompt`, so the rules the engine
follows are themselves auditable. The engine is **deterministic** — no
free-text LLM decides whether something is executed.

## Where it sits in the pipeline

```
event → ingest → threat intel → data science → SOC analyst → ethics
      → CONTROLLED RESPONSE ENGINE  (Detect → Verify → Assess Risk → Check Policy)
            ├─ LEVEL 1 / AUTOMATIC ........ read-only action runs, monitoring continues
            ├─ LEVEL 2 / AUTOMATIC ........ only under an explicit emergency policy:
            │                               temporary containment → immediate alert →
            │                               incident CONTAINED → human confirms / rejects (rollback)
            ├─ LEVEL 2/3 / HUMAN APPROVAL . incident AWAITING_APPROVAL with ACTION PREVIEW
            └─ BLOCKED ..................... allowlist conflict → high-priority alert →
                                             human verification (justification required)
      → human approval → controlled execution (rollback record + expiry) → knowledge/feedback
```

The engine sits **between** "the AI recommended an action" and "the action
happened". It may *raise* an action's autonomy level (critical asset,
allowlist, low confidence, degraded inputs) but can never lower one.

## The 15 sections and where they are implemented

| § | Rule | Implementation |
|---|------|----------------|
| 1 | Never act irreversibly on an AI classification alone | `ControlledResponseEngine.decide` — a state-changing action can only be `AUTOMATIC` under an explicit emergency policy, and only if reversible, time-limited and LEVEL ≤ 2 |
| 2 | Three-level autonomy model | `ACTION_CATALOG` assigns every known action a base level (1 read-only · 2 reversible/time-limited · 3 high impact); unknown actions are never executed |
| 3 | Protect critical assets | `AutonomyPolicy.asset_criticality` — explicit metadata (`asset_criticality`, `asset_role`, `target_type`) first, labeled heuristics second (hostname hints, RFC-1918 targets, admin accounts, essential processes); critical ⇒ LEVEL 3 + human approval + higher confidence bar |
| 4 | Trusted-asset allowlist | `AutonomyPolicy.allowlist_conflict` — trusted IPs/domains, critical servers, security tools, admin accounts, essential processes, internal networks; conflict ⇒ `BLOCKED` + HIGH-PRIORITY alert; only a human with a recorded justification can proceed; only a human can edit the allowlist |
| 5 | Reversibility first | `_select_action` walks the `reversible_alternative` chain: `block_ip → temporary_ip_restriction`, `delete_file → quarantine_file`, `disable_account → restrict_session`, … The original recommendation stays visible (`original_action`) and a human may escalate to it with a justification |
| 6 | Confidence + risk | Risk tier = risk score + verified TI + count of *independent* evidence sources; asset criticality raises the confidence threshold (`+15`) |
| 7 | Emergency response | `EmergencyPolicy` — must be explicitly configured (file or admin API), validated (reversible, LEVEL ≤ 2, ≤ 240 min, risk/conf ≥ 70, ≥ 2 sources), scoped, disabled by default; the engine never creates or repairs one |
| 8 | Action preview | `render_action_preview` — stored on the incident (`action_preview`) and shown by the dashboard **Preview** button before approval |
| 9 | Rollback system | `RollbackRecord` (action id, previous/new state, reason, evidence, policy, AI recommendation, execution result, rollback procedure); `rollback()` / `POST /commander/incidents/{id}/rollback`; failed executions stop further autonomous actions and alert |
| 10 | Time limits | LEVEL 2 actions carry `expires_at` (default 15 min); `expire_due()` rolls them back and asks for re-evaluation; `extend()` requires a human |
| 11 | Never chain unsafe actions | One automatic state change per incident per cooldown (10 min); a second is refused until a human re-evaluates |
| 12 | Fail-safe / SAFE MODE | Degraded inputs (TI unavailable, model/investigation failure, conflicting evidence), DB failure or an engine exception ⇒ safe mode: LEVEL 1 continues, every state change needs a human; exiting safe mode requires a human |
| 13 | Audit everything | `response_audit` table — the decision JSON is **immutable**; only *Execution Result*, *Rollback Information* and *Human Review* (append-only list) are updated |
| 14 | Learn from mistakes | `record_review` (was the threat real / risk appropriate / action appropriate / asset critical / response successful / collateral / rollback required); only `validated=true` reviews are marked eligible for learning |
| 15 | Required response format | `render_response` — the `[VRINDHA RESPONSE]` block is returned by the pipeline (`vrindha_response`) and stored in the audit row |

## Action catalog (excerpt)

| Action | Level | Reversible | State change | Default duration | Reversible alternative |
|---|---|---|---|---|---|
| `continue_monitoring`, `collect_logs`, `create_alert`, `record_ioc`, `investigate_host`, … | 1 | yes | no | — | — |
| `rate_limit` | 2 | yes | yes | 15 min | `increase_monitoring` |
| `temporary_ip_restriction` | 2 | yes | yes | 15 min | `rate_limit` |
| `quarantine_file` | 2 | yes | yes | — | `record_ioc` |
| `restrict_session`, `temporary_rule`, `temporary_isolation` | 2 | yes | yes | 15 min | … |
| `block_ip` | 3 | yes | yes | permanent | `temporary_ip_restriction` |
| `isolate_host` | 3 | yes | yes | permanent | `temporary_isolation` |
| `disable_account` | 3 | yes | yes | permanent | `restrict_session` |
| `kill_process` | 3 | **no** | yes | — | `temporary_isolation` |
| `delete_file` | 3 | **no** | yes | — | `quarantine_file` |

`GET /response/policy` returns the complete catalog.

## Policy file

[`vrin_SOC/config/autonomy_policy.json`](../vrin_SOC/config/autonomy_policy.json)
(override with `VRINDHA_AUTONOMY_POLICY=/path/to/policy.json`):

```json
{
  "allowlist": {"trusted_ips": ["127.0.0.1"], "critical_servers": ["dc01"], "internal_networks": []},
  "thresholds": {"medium": 40, "high": 70, "critical": 85,
                 "min_confidence_automatic": 70, "critical_confidence_bonus": 15,
                 "min_independent_sources_irreversible": 2},
  "auto_level1": true,
  "protect_private_ranges": true,
  "default_duration_minutes": 15,
  "chain_cooldown_minutes": 10,
  "emergency_policies": [{
    "name": "confirmed-c2-temporary-restriction",
    "enabled": false,
    "triggers": {"min_risk": 90, "min_confidence": 90, "min_independent_sources": 3, "require_ti_confirmed": true},
    "allowed_actions": ["temporary_ip_restriction", "rate_limit"],
    "scope": {"target_kinds": ["ip"], "exclude_critical": true},
    "max_duration_minutes": 15
  }]
}
```

The shipped emergency policy is **disabled**. Enabling it is a human decision.

## API

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/response/prompt` | user | Verbatim contract |
| GET | `/response/policy` | user | Allowlist, thresholds, action catalog, emergency policies, safe mode |
| PUT | `/response/policy/allowlist` | admin | Human-configured allowlist |
| POST | `/response/policy/emergency` | admin | Register an explicit emergency policy (validated, may be rejected) |
| GET / POST | `/response/safe-mode` | user / admin | Read / enter / exit SAFE MODE |
| POST | `/response/decide` | user | Classify a proposed response **without executing** (decision + ACTION PREVIEW + `[VRINDHA RESPONSE]`) |
| GET | `/response/audit` · `/response/{decision_id}` | user | Immutable decisions + execution / rollback / review columns |
| GET | `/response/rollbacks?active_only=true` | user | Rollback records / active temporary actions |
| POST | `/response/rollbacks/{action_id}/rollback` · `/extend` | admin | Roll back / extend (human re-evaluation) |
| POST | `/response/expire` | admin | Roll back all expired temporary actions |
| POST | `/response/{decision_id}/review` · GET `/response/reviews` | user | §14 review loop |
| POST | `/commander/approve` (`action_override`) | admin | Human approval; controlled execution; optional escalation with justification |
| POST | `/commander/incidents/{id}/rollback` | admin | Roll back every action of an incident |

### Example: the safe demo under controlled autonomy

```
SOC Analyst recommends:  block_ip 203.0.113.77   (impact high)
Response engine:         risk tier HIGH, 3 independent sources, TI not confirmed,
                         external address, asset criticality LOW
                       → reversibility first: temporary_ip_restriction (15 min)
                       → LEVEL 2 · HUMAN APPROVAL · rollback AVAILABLE
Human approves         → executes (labeled SIMULATION) → rollback record act-… with expires_at
Human may instead      → approve with action_override=block_ip + justification (audited LEVEL 3)
                       → reject (nothing executed) · roll back later · extend after re-evaluation
```

## Worked decisions

| Input | Decision |
|---|---|
| risk 30, `investigate_host` | LEVEL 1 · AUTOMATIC — read-only |
| risk 20, `block_ip` external IP | downgraded to `increase_monitoring` — LOW tier never justifies a state change |
| risk 55, `block_ip` external IP | `temporary_ip_restriction` · LEVEL 2 · HUMAN APPROVAL · 15 min |
| risk 92 / conf 95 / TI confirmed / 4 sources, `block_ip` external IP | `block_ip` · LEVEL 3 · HUMAN APPROVAL — *"Human approval required before blocking."* |
| risk 90, `block_ip`, only 1 evidence source | `temporary_ip_restriction` — multi-source verification required first |
| risk 95, `kill_process sshd` | BLOCKED — essential process on the allowlist, high-priority alert |
| risk 95, `disable_account root` | BLOCKED — administrative account |
| risk 95, `temporary_ip_restriction 192.168.1.20` | LEVEL 3 · HUMAN APPROVAL — private range = possible internal infrastructure |
| risk 93 / conf 95 / TI confirmed / 3 sources, `temporary_ip_restriction`, emergency policy **enabled** | LEVEL 2 · AUTOMATIC for ≤ 15 min → alert → incident `contained` → human confirms or rejects (auto rollback) |
| same, but TI unavailable | SAFE MODE — HUMAN APPROVAL |

## Testing

`vrin_SOC/tests/test_controlled_response.py` covers every section above
(autonomy levels, critical assets, allowlist, reversibility, emergency policy
validation and matching, preview/response format, rollback, expiry/extension,
anti-chaining, safe mode, audit immutability, review loop, Commander
integration). API coverage lives in `test_api_coordination.py`.
