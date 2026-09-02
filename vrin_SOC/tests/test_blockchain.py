"""Tests for the local, dependency-free blockchain ledger."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from vrin_SOC.blockchain.chain import (
    GENESIS_PREVIOUS_HASH,
    Block,
    LocalChain,
    compute_hash,
)


def test_new_chain_starts_with_mined_genesis():
    chain = LocalChain()
    assert len(chain) == 1
    genesis = chain.blocks()[0]
    assert genesis.index == 0
    assert genesis.previous_hash == GENESIS_PREVIOUS_HASH
    assert genesis.hash == compute_hash(0, genesis.timestamp, genesis.data, genesis.previous_hash, genesis.nonce)
    assert chain.is_valid()


def test_add_block_links_to_previous():
    chain = LocalChain(difficulty=0)
    first = chain.add_block({"event": "login", "user": "admin"})
    second = chain.add_block({"event": "logout", "user": "admin"})
    assert first.index == 1
    assert second.index == 2
    assert second.previous_hash == first.hash
    assert len(chain) == 3  # genesis + 2
    assert chain.is_valid()


def test_record_kwargs_convenience():
    chain = LocalChain(difficulty=0)
    block = chain.record(event="block_ip", target="203.0.113.7", simulated=True)
    assert block.data == {"event": "block_ip", "target": "203.0.113.7", "simulated": True}


def test_add_block_rejects_non_serializable_data():
    chain = LocalChain(difficulty=0)
    with pytest.raises(ValueError):
        chain.add_block({"bad": object()})


def test_difficulty_is_respected():
    chain = LocalChain(difficulty=3)
    for block in chain.blocks():
        assert block.hash.startswith("000"), "every block must satisfy difficulty=3"


def test_difficulty_zero_disables_mining():
    chain = LocalChain(difficulty=0)
    block = chain.add_block({"event": "no_mining"})
    assert block.nonce == 0
    assert chain.is_valid()


def test_verify_detects_tampered_data():
    chain = LocalChain(difficulty=1)
    chain.add_block({"event": "human_approval", "conclusion": "confirmed_attack"})
    # Tamper in memory: change the stored data without re-mining.
    block = chain.blocks()[1]
    block.data["conclusion"] = "false_positive"
    report = chain.verify()
    assert report["valid"] is False
    assert any("block 1" in problem for problem in report["problems"])


def test_verify_detects_broken_link():
    chain = LocalChain(difficulty=1)
    chain.add_block({"a": 1})
    chain.add_block({"b": 2})
    chain.blocks()[2].previous_hash = "f" * 64
    assert chain.is_valid() is False
    assert any("previous_hash" in problem for problem in chain.verify()["problems"])


def test_verify_detects_forged_hash():
    chain = LocalChain(difficulty=1)
    chain.add_block({"a": 1})
    chain.blocks()[1].hash = "0" * 64
    assert chain.is_valid() is False


def test_persistence_roundtrip(tmp_path):
    path = tmp_path / "chain.json"
    chain = LocalChain(path, difficulty=2)
    chain.add_block({"event": "lesson", "conclusion": "false_positive"})

    reloaded = LocalChain(path, difficulty=2)
    assert len(reloaded) == len(chain)
    assert [b.hash for b in reloaded.blocks()] == [b.hash for b in chain.blocks()]
    assert reloaded.is_valid()


def test_persistence_detects_disk_tampering(tmp_path):
    path = tmp_path / "chain.json"
    chain = LocalChain(path, difficulty=2)
    chain.add_block({"event": "audit", "ok": True})

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["blocks"][1]["data"]["ok"] = False  # retro-edit on disk
    path.write_text(json.dumps(payload), encoding="utf-8")

    tampered = LocalChain(path, difficulty=2)
    assert tampered.is_valid() is False


def test_corrupt_file_raises_clear_error(tmp_path):
    path = tmp_path / "chain.json"
    path.write_text("{ not json", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt or unreadable"):
        LocalChain(path)


def test_verify_reports_genesis_problem():
    chain = LocalChain(difficulty=0)
    chain.blocks()[0].previous_hash = "0" * 63 + "1"
    report = chain.verify()
    assert report["valid"] is False
    assert any("genesis" in problem for problem in report["problems"])


def test_thread_safe_appends():
    chain = LocalChain(difficulty=0)

    def add(i: int) -> None:
        chain.add_block({"event": "login", "seq": i})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add, range(50)))

    assert len(chain) == 51
    assert chain.is_valid()
    indices = [b.index for b in chain.blocks()]
    assert indices == list(range(51)), "indices must be contiguous under concurrency"


def test_block_roundtrip_dict():
    block = Block(index=7, timestamp="2026-01-01T00:00:00+00:00",
                  data={"x": 1}, previous_hash="a" * 64, nonce=3, hash="b" * 64)
    assert Block.from_dict(block.to_dict()) == block


def test_compute_hash_is_deterministic_and_order_independent():
    a = compute_hash(1, "t", {"x": 1, "y": 2}, "p", 0)
    b = compute_hash(1, "t", {"y": 2, "x": 1}, "p", 0)
    assert a == b
