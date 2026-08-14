"""`vrindha-ti` analyst CLI."""
from __future__ import annotations

from typing import Any
import argparse
import asyncio
import json

from .engine import engine
from .normalization import InvalidIndicator


def output(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str, ensure_ascii=False))


async def run(args: argparse.Namespace) -> int:
    try:
        if args.command == "status":
            await engine.start()
            output(await engine.health())
        elif args.command == "feeds":
            output({"feeds": engine.feeds.status()})
        elif args.command == "sync":
            await engine.bus.connect()
            output(await engine.feeds.sync_all() if args.feed == "all" else await engine.feeds.sync(args.feed))
        elif args.command == "lookup":
            output(engine.lookup(args.indicator, args.type))
        elif args.command == "enrich":
            await engine.bus.connect()
            output(await engine.enrich(args.indicator, args.type, args.external))
        elif args.command == "sightings":
            output({"sightings": engine.database.list_sightings(args.limit)})
        elif args.command == "correlations":
            output({"correlations": engine.database.correlations(args.limit)})
        elif args.command == "mitre":
            entities = engine.database.list_entities("attack-pattern", 10_000)
            if args.technique:
                entities = [item for item in entities if args.technique.upper() in str(item).upper()]
            output({"attack_patterns": entities[:args.limit]})
        elif args.command == "vulnerabilities":
            output({"vulnerabilities": engine.database.vulnerabilities(args.kev, args.limit)})
        elif args.command == "report":
            output(engine.make_report(args.indicator_id))
        elif args.command == "doctor":
            await engine.bus.connect()
            result = await engine.monitor.doctor()
            output(result)
            return 0 if result["status"] == "healthy" else 2
        else:
            return 1
        return 0
    except (InvalidIndicator, ValueError, KeyError) as exc:
        output({"status": "error", "error": str(exc)})
        return 2
    finally:
        if engine.started:
            await engine.stop()
        elif engine.bus.state != "disconnected":
            await engine.bus.close()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="vrindha-ti", description="Vrindha defensive threat-intelligence CLI")
    sub = value.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("feeds")
    sync = sub.add_parser("sync"); sync.add_argument("feed", nargs="?", default="all")
    lookup = sub.add_parser("lookup"); lookup.add_argument("indicator"); lookup.add_argument("--type")
    enrich = sub.add_parser("enrich"); enrich.add_argument("indicator"); enrich.add_argument("--type"); enrich.add_argument("--external", action="store_true")
    sightings = sub.add_parser("sightings"); sightings.add_argument("--limit", type=int, default=100)
    correlations = sub.add_parser("correlations"); correlations.add_argument("--limit", type=int, default=100)
    mitre = sub.add_parser("mitre"); mitre.add_argument("technique", nargs="?"); mitre.add_argument("--limit", type=int, default=100)
    vulnerabilities = sub.add_parser("vulnerabilities"); vulnerabilities.add_argument("--kev", action="store_true"); vulnerabilities.add_argument("--limit", type=int, default=100)
    report = sub.add_parser("report"); report.add_argument("indicator_id")
    sub.add_parser("doctor")
    return value


def main() -> None:
    raise SystemExit(asyncio.run(run(parser().parse_args())))


if __name__ == "__main__":
    main()
