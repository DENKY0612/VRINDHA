"""Command-line interface for the local blockchain ledger.

Run from the repository root:

    python -m vrin_SOC.blockchain init --path ledger.json --difficulty 2
    python -m vrin_SOC.blockchain add   --path ledger.json '{"event":"login","user":"admin"}'
    python -m vrin_SOC.blockchain add   --path ledger.json event=login user=admin ok=true
    python -m vrin_SOC.blockchain show  --path ledger.json
    python -m vrin_SOC.blockchain verify --path ledger.json
    python -m vrin_SOC.blockchain demo

``demo`` runs a self-contained show-and-tell: it builds a chain, records a few
SOC-style audit events, verifies it, then corrupts a block and shows that
verification detects the tampering — all in a temporary directory.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from .chain import Block, LocalChain, compute_hash


def _default_path() -> Path:
    # Lives next to the SOC package data so the default is reproducible from
    # any working directory without polluting the checkout on accidental use.
    return Path(__file__).resolve().parent / "ledger.json"


def _parse_value(raw: str) -> Any:
    """Best-effort JSON literal for a ``key=value`` argument."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _parse_data(args: List[str]) -> Dict[str, Any]:
    if not args:
        raise SystemExit("add: provide a JSON object or key=value pairs (e.g. event=login ok=true)")
    if len(args) == 1 and args[0].lstrip().startswith("{"):
        value = json.loads(args[0])
        if not isinstance(value, dict):
            raise SystemExit("add: JSON payload must be an object")
        return value
    data: Dict[str, Any] = {}
    for token in args:
        if "=" not in token:
            raise SystemExit(f"add: invalid argument {token!r} (expected key=value)")
        key, _, raw = token.partition("=")
        if not key:
            raise SystemExit(f"add: invalid argument {token!r} (empty key)")
        data[key.strip()] = _parse_value(raw.strip())
    return data


def cmd_init(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if path.exists() and not args.force:
        print(f"{path} already exists; use --force to overwrite")
        return 1
    chain = LocalChain(path=None, difficulty=args.difficulty)  # fresh, in memory
    chain.path = path  # then persist to the requested location
    chain.save()
    print(f"Initialized ledger at {path} (difficulty={args.difficulty}, 1 genesis block)")
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    data = _parse_data(args.args)
    chain = LocalChain(args.path)
    block = chain.add_block(data)
    print(f"Added block {block.index}")
    print(json.dumps(block.to_dict(), indent=2, sort_keys=True))
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    chain = LocalChain(args.path)
    report = chain.verify()
    print(f"Chain: {len(chain)} block(s), difficulty={chain.difficulty}, valid={report['valid']}")
    print(f"Last hash: {report['last_hash']}")
    print()
    for block in chain.blocks():
        if args.verbose:
            print(json.dumps(block.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"  [{block.index}] {block.hash[:16]}…  data={json.dumps(block.data, sort_keys=True)}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    chain = LocalChain(args.path)
    report = chain.verify()
    if report["valid"]:
        print("✓ VALID — every hash and link checks out.")
        print(f"  blocks={report['blocks']} difficulty={report['difficulty']} last={report['last_hash'][:24]}…")
        return 0
    print("✗ TAMPERED / INVALID — integrity problems detected:")
    for problem in report["problems"]:
        print(f"  - {problem}")
    return 1


def cmd_demo(args: argparse.Namespace) -> int:
    print("=== Vrindha local blockchain — integrity demo (no network, temp dir) ===\n")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "chain.json"
        chain = LocalChain(path, difficulty=args.difficulty)

        for event in (
            {"event": "user_login", "user": "analyst-1", "ok": True},
            {"event": "ethics_decision", "action": "block_ip 203.0.113.7", "decision": "require_authorization"},
            {"event": "human_approval", "incident": "inc-0001", "approved_by": "admin"},
            {"event": "knowledge_lesson", "conclusion": "confirmed_attack"},
        ):
            block = chain.add_block(event)
            print(f"  mined block {block.index}: {block.hash[:24]}…  {json.dumps(event, sort_keys=True)}")

        print("\n1) Verify the intact chain:")
        print("   ", chain.verify())

        # 2) Tamper with a block on disk, then load a fresh chain and verify.
        corrupted = Path(tmp) / "corrupted.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["blocks"][2]["data"]["decision"] = "allow"  # retro-edit the record
        corrupted.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tampered = LocalChain(corrupted, difficulty=args.difficulty)

        print("\n2) After retro-editing block 2's data on disk, verify reports:")
        report = tampered.verify()
        print("   valid =", report["valid"])
        for problem in report["problems"]:
            print("   -", problem)

        print("\n=== demo complete ===")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vrin_SOC.blockchain",
        description="Local, dependency-free blockchain ledger for Vrindha SOC.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def path_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--path", default=str(_default_path()), help="ledger JSON file (default: <package>/ledger.json)")

    p_init = sub.add_parser("init", help="create a new ledger file")
    p_init.add_argument("--path", default=str(_default_path()))
    p_init.add_argument("--difficulty", type=int, default=2)
    p_init.add_argument("--force", action="store_true", help="overwrite an existing ledger")
    p_init.set_defaults(func=cmd_init)

    p_add = sub.add_parser("add", help="append a block (JSON object or key=value pairs)")
    path_args(p_add)
    p_add.add_argument("args", nargs="*", help="e.g. '{\"event\":\"login\"}' or event=login ok=true")
    p_add.set_defaults(func=cmd_add)

    p_show = sub.add_parser("show", help="print the chain")
    path_args(p_show)
    p_show.add_argument("--verbose", "-v", action="store_true", help="print full block JSON")
    p_show.set_defaults(func=cmd_show)

    p_verify = sub.add_parser("verify", help="recompute hashes/links and report integrity")
    path_args(p_verify)
    p_verify.set_defaults(func=cmd_verify)

    p_demo = sub.add_parser("demo", help="self-contained tamper-evidence demo")
    p_demo.add_argument("--difficulty", type=int, default=2)
    p_demo.set_defaults(func=cmd_demo)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
