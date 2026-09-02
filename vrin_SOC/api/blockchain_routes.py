"""Localhost HTTP API for the local blockchain ledger.

These endpoints are served by the existing SOC app (no second process):

    GET    /blockchain                 chain summary + integrity status
    GET    /blockchain/blocks          list blocks (paged)
    GET    /blockchain/blocks/{index}  one block
    POST   /blockchain/add             append + mine a block (authenticated)
    GET    /blockchain/verify          full integrity report

Persistence is opt-in and zero-burden by default:

* With ``VRINDHA_LEDGER_PATH`` unset, the chain is **in-memory** — no files are
  written and the device load is a few microseconds of hashing per block.
* Set ``VRINDHA_LEDGER_PATH`` to a JSON file to persist the chain across
  restarts (written atomically with 0600 permissions).
* ``VRINDHA_LEDGER_DIFFICULTY`` controls proof-of-work (default 2; 0 disables).

Read endpoints are intentionally open so any local process can verify
integrity without credentials; appending requires a valid SOC login.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .deps import get_current_user
from vrin_SOC.blockchain.chain import DEFAULT_DIFFICULTY, LocalChain

router = APIRouter(tags=["blockchain"])

_chain: Optional[LocalChain] = None
_chain_lock = threading.Lock()


def get_chain() -> LocalChain:
    """Process-wide ledger, created lazily so importing the app writes nothing.

    Configured from the environment:
      VRINDHA_LEDGER_PATH        → persistent JSON file (unset = in-memory)
      VRINDHA_LEDGER_DIFFICULTY  → proof-of-work difficulty (default 2)
    """
    global _chain
    with _chain_lock:
        if _chain is None:
            raw_path = os.getenv("VRINDHA_LEDGER_PATH", "").strip()
            path = Path(raw_path) if raw_path else None
            try:
                difficulty = int(os.getenv("VRINDHA_LEDGER_DIFFICULTY", str(DEFAULT_DIFFICULTY)))
            except ValueError:
                difficulty = DEFAULT_DIFFICULTY
            _chain = LocalChain(path=path, difficulty=difficulty)
        return _chain


class LedgerAddRequest(BaseModel):
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON-serializable record to append (e.g. an audit event).",
    )


@router.get("/blockchain")
async def blockchain_summary() -> Dict[str, Any]:
    chain = get_chain()
    report = chain.verify()
    return {
        "status": "success",
        "persisted": chain.path is not None,
        "path": str(chain.path) if chain.path else None,
        "difficulty": chain.difficulty,
        "length": len(chain),
        "valid": report["valid"],
        "genesis_hash": report.get("genesis_hash"),
        "last_hash": report.get("last_hash"),
        "integrity_problems": report["problems"],
    }


@router.get("/blockchain/blocks")
async def blockchain_blocks(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    chain = get_chain()
    blocks = chain.blocks()[offset : offset + limit]
    return {
        "status": "success",
        "offset": offset,
        "limit": limit,
        "count": len(blocks),
        "total": len(chain),
        "blocks": [block.to_dict() for block in blocks],
    }


@router.get("/blockchain/blocks/{index}")
async def blockchain_block(index: int) -> Dict[str, Any]:
    block = get_chain().get(index)
    if block is None:
        raise HTTPException(status_code=404, detail=f"no block at index {index}")
    return {"status": "success", "block": block.to_dict()}


@router.post("/blockchain/add", status_code=201)
async def blockchain_add(req: LedgerAddRequest, user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    try:
        block = get_chain().add_block(req.data)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "status": "success",
        "recorded_by": user.get("sub"),
        "block": block.to_dict(),
    }


@router.get("/blockchain/verify")
async def blockchain_verify() -> Dict[str, Any]:
    chain = get_chain()
    report = chain.verify()
    return {"status": "success", **report}


__all__ = ["router", "get_chain"]
