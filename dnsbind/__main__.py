from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import admit_chain, inspect_message
from .load import load_json, load_msgid_store, save_msgid_store


def cmd_inspect(args: argparse.Namespace) -> int:
    message = load_json(args.message)
    report = inspect_message(message)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        Path(args.report).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


def cmd_admit(args: argparse.Namespace) -> int:
    try:
        message = load_json(args.message)
        keys = load_json(args.keys)
        policy = load_json(args.policy)
        store = load_msgid_store(args.msgid_store)
        report = admit_chain(message, keys, policy, store)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
        print(f"load failure: {e}", file=sys.stderr)
        return 2

    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    Path(args.report).write_text(text, encoding="utf-8")
    decision = report.get("decision")
    if decision == "allow":
        save_msgid_store(args.msgid_store, store)
        return 0
    if decision == "deny":
        return 1
    return 2


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dnsbind")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_i = sub.add_parser("inspect")
    p_i.add_argument("--message", required=True)
    p_i.add_argument("--report")
    p_i.set_defaults(func=cmd_inspect)

    p_a = sub.add_parser("admit")
    p_a.add_argument("--message", required=True)
    p_a.add_argument("--keys", required=True)
    p_a.add_argument("--policy", required=True)
    p_a.add_argument("--msgid-store", required=True)
    p_a.add_argument("--report", required=True)
    p_a.set_defaults(func=cmd_admit)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
