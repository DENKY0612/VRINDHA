"""Local, dependency-free blockchain ledger for Vrindha SOC.

A minimal-but-real blockchain that runs entirely on the local host with no
network, no daemon, and no third-party packages (only the Python standard
library). It is designed for *integrity*, not for distributed consensus or
currency:

* Every block is linked by its SHA-256 hash to the previous block's hash.
* Blocks are mined with a configurable proof-of-work difficulty. The default
  (``difficulty=2``, ~256 hashes ≈ well under a millisecond) keeps the device
  burden negligible while still exercising a genuine nonce search; set it to
  ``0`` to disable mining entirely, or raise it for stronger tamper evidence.
* ``verify()`` recomputes every hash and every link, so any tampering with a
  block's data, index, timestamp, nonce, or link is detected.
* Persistence (optional) is a single JSON file written atomically with 0600
  permissions — the same pattern the rest of the SOC uses for its user store.

Typical use on localhost:

    from vrin_SOC.blockchain.chain import LocalChain

    chain = LocalChain()                 # in-memory (zero disk/network burden)
    chain.add_block({"event": "login", "user": "admin", "ok": True})
    chain.add_block({"event": "block_ip", "target": "203.0.113.7"})
    print(chain.verify())                # {'valid': True, ...}

    # Persist across restarts by giving it a path:
    chain = LocalChain("vrin_SOC/ledger/chain.json")
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

GENESIS_PREVIOUS_HASH = "0" * 64
DEFAULT_DIFFICULTY = 2


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_hash(
    index: int,
    timestamp: str,
    data: Dict[str, Any],
    previous_hash: str,
    nonce: int,
) -> str:
    """Deterministic SHA-256 over a block's canonical JSON payload.

    ``sort_keys`` makes the hash independent of dictionary insertion order, so
    two logically identical blocks always hash identically.
    """
    payload = json.dumps(
        {
            "index": index,
            "timestamp": timestamp,
            "data": data,
            "previous_hash": previous_hash,
            "nonce": nonce,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _mine(
    index: int,
    timestamp: str,
    data: Dict[str, Any],
    previous_hash: str,
    difficulty: int,
) -> Tuple[int, str]:
    """Find a nonce whose hash starts with ``difficulty`` zero hex digits."""
    prefix = "0" * difficulty
    nonce = 0
    while True:
        digest = compute_hash(index, timestamp, data, previous_hash, nonce)
        if digest.startswith(prefix):
            return nonce, digest
        nonce += 1


@dataclass
class Block:
    index: int
    timestamp: str
    data: Dict[str, Any]
    previous_hash: str
    nonce: int
    hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Block":
        return cls(
            index=int(raw["index"]),
            timestamp=str(raw["timestamp"]),
            data=dict(raw.get("data") or {}),
            previous_hash=str(raw["previous_hash"]),
            nonce=int(raw["nonce"]),
            hash=str(raw["hash"]),
        )

    def recompute_hash(self) -> str:
        return compute_hash(self.index, self.timestamp, self.data, self.previous_hash, self.nonce)


class LocalChain:
    """A local, tamper-evident append-only ledger.

    Parameters
    ----------
    path:
        Optional JSON file for persistence. When ``None`` the chain lives only
        in memory (zero disk I/O) — ideal for demos and for anchoring records
        that are also stored elsewhere. When a path is given, the chain loads
        from it if it exists, and every mutation is written back atomically.
    difficulty:
        Proof-of-work difficulty = number of leading zero hex digits in each
        block hash. Default 2 (negligible CPU). 0 disables mining.
    """

    def __init__(self, path: Optional[str | Path] = None, difficulty: int = DEFAULT_DIFFICULTY):
        self.path = Path(path) if path else None
        self.difficulty = max(0, int(difficulty))
        self._blocks: List[Block] = []
        self._lock = threading.RLock()

        if self.path is not None and self.path.exists():
            self._load()
        else:
            self._append_genesis()
            if self.path is not None:
                self.save()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    def _append_genesis(self) -> Block:
        """Create (and mine) the genesis block that anchors the chain."""
        data = {
            "genesis": True,
            "note": "Vrindha local integrity ledger",
            "created_at": utc_now(),
        }
        block = self._make_block(data, previous_hash=GENESIS_PREVIOUS_HASH)
        self._blocks.append(block)
        return block

    def _make_block(self, data: Dict[str, Any], previous_hash: str) -> Block:
        # Fail fast if the payload can't be canonicalized — the chain must
        # always be reproducible from its JSON representation.
        try:
            json.dumps(data, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"block data must be JSON-serializable: {exc}") from exc
        index = len(self._blocks)
        timestamp = utc_now()
        nonce, digest = _mine(index, timestamp, data, previous_hash, self.difficulty)
        return Block(
            index=index,
            timestamp=timestamp,
            data=data,
            previous_hash=previous_hash,
            nonce=nonce,
            hash=digest,
        )

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------
    def add_block(self, data: Dict[str, Any]) -> Block:
        """Append and mine a new block, returning it."""
        with self._lock:
            block = self._make_block(dict(data), previous_hash=self.last_block().hash)
            self._blocks.append(block)
            if self.path is not None:
                self.save()
            return block

    def record(self, **data: Any) -> Block:
        """Convenience: ``chain.record(event="login", user="admin")``."""
        return self.add_block(data)

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------
    def last_block(self) -> Block:
        return self._blocks[-1]

    def blocks(self) -> List[Block]:
        with self._lock:
            return list(self._blocks)

    def get(self, index: int) -> Optional[Block]:
        with self._lock:
            return self._blocks[index] if 0 <= index < len(self._blocks) else None

    def __len__(self) -> int:
        return len(self._blocks)

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------
    def verify(self) -> Dict[str, Any]:
        """Recompute every hash and link; report tampering in detail."""
        with self._lock:
            problems: List[str] = []
            blocks = list(self._blocks)

            if not blocks:
                return {
                    "valid": False,
                    "blocks": 0,
                    "difficulty": self.difficulty,
                    "problems": ["chain is empty (missing genesis block)"],
                }

            genesis = blocks[0]
            if genesis.index != 0 or genesis.previous_hash != GENESIS_PREVIOUS_HASH:
                problems.append("genesis block has invalid index or previous_hash")

            for i, block in enumerate(blocks):
                prefix = f"block {i}"
                if block.index != i:
                    problems.append(f"{prefix}: index discontinuity (stored {block.index})")
                if block.recompute_hash() != block.hash:
                    problems.append(f"{prefix}: stored hash does not match recomputed hash")
                if self.difficulty and not block.hash.startswith("0" * self.difficulty):
                    problems.append(f"{prefix}: hash does not satisfy proof-of-work difficulty")
                if i > 0 and block.previous_hash != blocks[i - 1].hash:
                    problems.append(f"{prefix}: previous_hash does not link to block {i - 1}")

            return {
                "valid": not problems,
                "blocks": len(blocks),
                "difficulty": self.difficulty,
                "genesis_hash": genesis.hash,
                "last_hash": blocks[-1].hash,
                "problems": problems,
            }

    def is_valid(self) -> bool:
        return bool(self.verify()["valid"])

    # ------------------------------------------------------------------
    # Persistence (atomic, 0600 — mirrors vrin_SOC.api.auth)
    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "difficulty": self.difficulty,
                "blocks": [block.to_dict() for block in self._blocks],
            }

    def save(self) -> None:
        if self.path is None:
            return
        with self._lock:
            directory = self.path.parent
            directory.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=str(directory), prefix=".chain-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self.to_dict(), handle, indent=2)
                    handle.write("\n")
                os.chmod(tmp_path, 0o600)
                os.replace(tmp_path, self.path)
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"corrupt or unreadable ledger file {self.path}: {exc}") from exc
        if not isinstance(payload, dict) or "blocks" not in payload:
            raise ValueError(f"ledger file {self.path} is missing a 'blocks' array")
        self.difficulty = max(0, int(payload.get("difficulty", DEFAULT_DIFFICULTY)))
        self._blocks = [Block.from_dict(raw) for raw in payload["blocks"]]


__all__ = [
    "Block",
    "LocalChain",
    "compute_hash",
    "GENESIS_PREVIOUS_HASH",
    "DEFAULT_DIFFICULTY",
    "utc_now",
]
