"""Local blockchain ledger for Vrindha SOC.

Exposes the core :class:`~vrin_SOC.blockchain.chain.LocalChain` plus the
``cli`` module. See ``vrin_SOC/blockchain/README.md`` for usage, and
``vrin_SOC/api/blockchain_routes.py`` for the localhost HTTP API.
"""

from .chain import (
    GENESIS_PREVIOUS_HASH,
    DEFAULT_DIFFICULTY,
    Block,
    LocalChain,
    compute_hash,
    utc_now,
)

__all__ = [
    "Block",
    "LocalChain",
    "compute_hash",
    "GENESIS_PREVIOUS_HASH",
    "DEFAULT_DIFFICULTY",
    "utc_now",
]
