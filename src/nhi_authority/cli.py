"""Command line interface.

    nhi-authority list       INVENTORY
    nhi-authority authority  INVENTORY --identity ID [--format md|json]
    nhi-authority plan       INVENTORY --identity ID [--as-of DATE] [--window 90] [--format md|json]
    nhi-authority check      INVENTORY --identity ID --action ACTION --scope SCOPE
    nhi-authority collect azure --subscription SUB_ID -o azure.json
    nhi-authority collect aws   [--profile NAME] -o aws.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date

from . import __version__
from .graph import can_perform, effective_authority, summarise
from .loader import load_inventory, to_jsonable
from .report import authority_markdown, plan_markdown
from .revocation import plan_for_identity


def _cmd_list(args: argparse.Namespace) -> int:
    inv = load_inventory(args.inventory)
    print(f"{'identity':40} {'type':18} {'direct':>6} {'inherited':>9} {'privileged':>10}")
    for ident in inv.identities.values():
        s = summarise(inv, ident.id)
        print(f"{ident.id:40} {ident.type:18} {s.direct_grants:>6} {s.inherited_grants:>9} "
              f"{s.privileged_direct + s.privileged_inherited:>10}")
    return 0


def _cmd_authority(args: argparse.Namespace) -> int:
    inv = load_inventory(args.inventory)
    ents = effective_authority(inv, args.identity)
    if args.format == "json":
        print(json.dumps({"summary": to_jsonable(summarise(inv, args.identity)),
                          "entitlements": to_jsonable(ents)}, indent=2))
    else:
        print(authority_markdown(inv, args.identity, ents))
    return 0


def _cmd_plan(args: argparse.Namespace) -> int:
    inv = load_inventory(args.inventory)
    as_of = date.fromisoformat(args.as_of) if args.as_of else date.today()
    plan = plan_for_identity(inv, args.identity, as_of, args.window)
    if args.format == "json":
        print(json.dumps(to_jsonable(plan), indent=2))
    else:
        print(plan_markdown(plan))
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    inv = load_inventory(args.inventory)
    hits = can_perform(inv, args.identity, args.action, args.scope)
    if not hits:
        print(f"DENIED: {args.identity} cannot perform {args.action} on {args.scope}")
        return 1
    print(f"ALLOWED: {args.identity} can perform {args.action} on {args.scope}")
    for e in hits:
        print(f"  via {e.grant.source or e.grant.id} held by {e.holder} [{e.describe_path()}]")
    return 0


def _cmd_collect(args: argparse.Namespace) -> int:
    if args.platform == "azure":
        from .collectors.azure import collect_azure
        data = collect_azure(args.subscription)
    else:
        from .collectors.aws import collect_aws
        data = collect_aws(args.profile)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"Wrote {len(data['identities'])} identities and {len(data['grants'])} grants to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nhi-authority", description=__doc__.split("\n")[0])
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("list", help="Summarise every identity in an inventory")
    s.add_argument("inventory")
    s.set_defaults(func=_cmd_list)

    for name, func, helptext in (
        ("authority", _cmd_authority, "Show effective authority for one identity"),
        ("plan", _cmd_plan, "Build a safe revocation plan for one identity"),
    ):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("inventory")
        s.add_argument("--identity", required=True)
        s.add_argument("--format", choices=("md", "json"), default="md")
        if name == "plan":
            s.add_argument("--as-of", help="Analysis date, YYYY-MM-DD (default: today)")
            s.add_argument("--window", type=int, default=90, help="Usage window in days")
        s.set_defaults(func=func)

    s = sub.add_parser("check", help="Can this identity perform this action on this scope?")
    s.add_argument("inventory")
    s.add_argument("--identity", required=True)
    s.add_argument("--action", required=True)
    s.add_argument("--scope", required=True)
    s.set_defaults(func=_cmd_check)

    s = sub.add_parser("collect", help="Build an inventory from a live cloud account (read-only)")
    s.add_argument("platform", choices=("azure", "aws"))
    s.add_argument("--subscription", help="Azure subscription ID")
    s.add_argument("--profile", help="AWS profile name")
    s.add_argument("-o", "--output", required=True)
    s.set_defaults(func=_cmd_collect)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "collect" and args.platform == "azure" and not args.subscription:
        print("--subscription is required for Azure", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except (KeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
