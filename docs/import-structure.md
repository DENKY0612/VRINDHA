# Import structure

Vrindha is two first-party packages that live side by side in the repository
root. Library code imports them by those names. Tests, launchers, and systemd
units do the same.

| Package | Role | Canonical import |
|---|---|---|
| `vrin_SOC` | CLI, FastAPI, agents, tools, ML | `from vrin_SOC.core.brain import brain` |
| `Vrin_TI` | Independent STIX threat-intelligence service | `from Vrin_TI.engine import ThreatIntelligenceEngine` |

`pytest.ini` only adds the repository root to `pythonpath`. It no longer also
adds `vrin_SOC/`, which previously let the same file be imported as both
`core.brain` and `vrin_SOC.core.brain` — two module objects, two singletons.

## How to run modules

```bash
# from the repository root
python3 -m vrin_SOC
python3 -m vrin_SOC.api.main
python3 -m uvicorn vrin_SOC.api.main:app --host 0.0.0.0 --port 8000
python3 -m Vrin_TI
python3 -m Vrin_TI.cli doctor
python3 -m uvicorn Vrin_TI.api:app --host 127.0.0.1 --port 8010
```

`./vrin_SOC/run.sh` and `./Vrin_TI/vrindha-ti` already use this layout.

`python vrin_SOC/main.py` and `python Vrin_TI/cli.py` still work: those entry
points put the repository root on `sys.path` (or re-exec as
`python -m …`) before importing the package.

## Compatibility

These spellings remain supported and resolve to the **same** module objects
once `vrin_SOC` has been imported (tests do this in `conftest.py`):

```python
from core.brain import brain          # == vrin_SOC.core.brain.brain
from api.auth import AuthModule       # == vrin_SOC.api.auth.AuthModule
from database.db import get_logs
```

`uvicorn api.main:app` still works if the repository root is on `PYTHONPATH`
and the process has imported `vrin_SOC` (the package `__init__` files install
the alias finder). New launchers should use `vrin_SOC.api.main:app`.

## Compatibility changes

- `vrin_SOC/` is now a regular package (`vrin_SOC/__init__.py`).
- Library modules no longer mutate `sys.path`.
- Docker image is built from the **repository root**:
  `docker build -f vrin_SOC/Dockerfile .`
- systemd SOC unit `WorkingDirectory` is the repository root;
  `ExecStart` is `uvicorn vrin_SOC.api.main:app`.
- `presentation/build_pptx.py` resolves assets next to itself instead of a
  hardcoded `/home/user/Vrindha_SOC/...` path.

Public HTTP routes, CLI commands, and exported class/function names are
unchanged.
