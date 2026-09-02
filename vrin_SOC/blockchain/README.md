# Local blockchain ledger

A **local, dependency-free blockchain** for the Vrindha SOC host. It runs
entirely on `localhost` with **zero device burden**: no network, no daemon, no
third-party packages, no large data files. Only the Python standard library
(`hashlib`, `json`, `threading`, `os`).

## What it does

- **Append-only ledger** of JSON records, each block linked by SHA-256 to the
  previous block's hash.
- **Proof-of-work mining** with an adjustable difficulty (default `2` ≈ a few
  hundred hashes, well under a millisecond; `0` disables it entirely).
- **Tamper-evident verification** — `verify()` recomputes every hash and every
  link and reports exactly which block was altered, whether by data edit,
  index change, timestamp change, nonce change, or a broken link.
- **Optional persistence** to a single JSON file, written atomically with
  `0600` permissions (same pattern as the SOC user store).

## What it is *not*

It is not a cryptocurrency, not a distributed consensus network, and it does
not store the SOC's raw data. It is an **integrity anchor**: you append
*hashes / summaries* of records (audit decisions, approvals, lessons) so their
existence and order can be proven later and any retro-editing is detected.

## Usage (CLI)

From the repository root:

```bash
# create a ledger file
python3 -m vrin_SOC.blockchain init --path ledger.json --difficulty 2

# append records (JSON object or key=value pairs)
python3 -m vrin_SOC.blockchain add --path ledger.json '{"event":"login","user":"admin"}'
python3 -m vrin_SOC.blockchain add --path ledger.json event=ethics_decision action=block_ip ok=false

# inspect + verify
python3 -m vrin_SOC.blockchain show   --path ledger.json
python3 -m vrin_SOC.blockchain verify --path ledger.json

# self-contained show-and-tell (build → verify → tamper → detect)
python3 -m vrin_SOC.blockchain demo
```

## Usage (library)

```python
from vrin_SOC.blockchain.chain import LocalChain

chain = LocalChain()                      # in-memory: zero disk I/O
chain.record(event="login", user="admin", ok=True)
chain.add_block({"event": "block_ip", "target": "203.0.113.7", "simulated": True})

print(chain.verify())   # {'valid': True, 'blocks': 3, ...}

chain = LocalChain("ledger.json", difficulty=2)   # persistent
```

## Usage (localhost HTTP API)

Mounted in the existing SOC app — start it as usual and hit the endpoints:

```bash
python3 -m uvicorn vrin_SOC.api.main:app --host 0.0.0.0 --port 8000
```

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/blockchain` | open | summary + integrity status |
| `GET` | `/blockchain/blocks` | open | list blocks (`offset`, `limit`) |
| `GET` | `/blockchain/blocks/{index}` | open | one block |
| `POST` | `/blockchain/add` | SOC login | append + mine a block |
| `GET` | `/blockchain/verify` | open | full integrity report |

Reads are open so any local process can verify integrity without credentials;
appending requires a valid SOC login.

Environment variables (all optional):

| Variable | Default | Effect |
|---|---|---|
| `VRINDHA_LEDGER_PATH` | unset | unset = in-memory chain; set = persist to this JSON file |
| `VRINDHA_LEDGER_DIFFICULTY` | `2` | proof-of-work leading zeros; `0` disables mining |

> Multi-worker note: an in-memory chain is per-process. For a shared ledger
> across workers, set `VRINDHA_LEDGER_PATH` (writes are atomic) or run a
> single worker for the blockchain API.

## Suggested integration points

Append a *digest*, never raw sensitive data:

- **Incident approvals** — `POST /commander/approve` → `chain.record(event="approval", incident_id=…, approved_by=…, conclusion=…)`
- **Ethics decisions** — each `ethics_audit_log` row → `chain.record(event="ethics_decision", decision=…, principles=…)`
- **Knowledge lessons** — each validated lesson → `chain.record(event="lesson", lesson_id=…)`
- **Model registry changes** — each `promote()` → `chain.record(event="model_promote", model=…, version=…)`

Because the ledger stores only summaries, it never expands the device's
sensitive-data footprint; it only makes the record of *what happened* and *in
what order* unforgeable.
