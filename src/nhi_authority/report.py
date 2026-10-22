"""Markdown rendering for authority reports and revocation plans."""
from __future__ import annotations

import json

from .graph import Entitlement, summarise
from .loader import to_jsonable
from .model import Inventory
from .revocation import RevocationPlan


def _fmt_actions(actions: tuple[str, ...] | list[str], limit: int = 4) -> str:
    items = list(actions)
    shown = ", ".join(f"`{a}`" for a in items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def authority_markdown(inv: Inventory, principal: str, entitlements: list[Entitlement]) -> str:
    s = summarise(inv, principal)
    ident = inv.identities[principal]
    lines = [
        f"# Effective authority: {principal}",
        "",
        f"Type: {ident.type} | Platform: {ident.platform} | Owner: {ident.owner or 'unassigned'}",
        "",
        "| Measure | Value |",
        "|---|---|",
        f"| Grants assigned directly | {s.direct_grants} |",
        f"| Grants reachable through delegation | {s.inherited_grants} |",
        f"| Other identities it can act as | {s.reachable_identities} |",
        f"| Privileged grants (direct / inherited) | {s.privileged_direct} / {s.privileged_inherited} |",
        f"| Authority amplification | {s.amplification}x |",
        "",
        "## Entitlements",
        "",
        "| Grant | Held by | Actions | Scope | Privileged | Path |",
        "|---|---|---|---|---|---|",
    ]
    for e in entitlements:
        lines.append(
            f"| {e.grant.source or e.grant.id} | {e.holder} | {_fmt_actions(e.grant.actions)} | "
             f"`{e.grant.scope}` | {'yes' if e.privileged else 'no'} | {e.describe_path()} |"
        )
    return "\n".join(lines) + "\n"


def plan_markdown(plan: RevocationPlan) -> str:
    c = plan.counts
    lines = [
        f"# Revocation plan: {plan.identity}",
        "",
        f"As of {plan.as_of.isoformat()} using a {plan.window_days}-day usage window.",
        f"Decisions: {c.get('revoke', 0)} revoke, {c.get('replace', 0)} replace, {c.get('keep', 0)} keep.",
        "",
    ]
    if plan.observation_gap_days:
        lines += [
            (f"**Not enough history.** Usage data is missing for {plan.observation_gap_days} day(s) "
             "of the window, so no grant is recommended for removal yet."),
            "",
        ]
    lines += ["## Grant decisions", ""]
    for n, d in enumerate(plan.decisions, start=1):
        lines += [
            f"### {n}. {d.decision.upper()}: {d.grant.source or d.grant.id}",
            "",
            f"Scope `{d.grant.scope}` | Blast radius {d.blast_radius}",
            "",
            f"{d.reason}",
            "",
        ]
        if d.used_actions:
            lines += [f"Actions observed: {_fmt_actions(d.used_actions, 8)}", ""]
        if d.proposed:
            lines += [
                f"Replacement grant: {_fmt_actions(d.proposed.actions, 8)} at `{d.proposed.scope}`",
                "",
            ]
        if d.dependencies_touched:
            names = ", ".join(sorted({x.consumer for x in d.dependencies_touched}))
            lines += [f"Dependent workloads: {names}", ""]
        for step in d.steps:
            lines.append(f"{step.order}. **{step.action}**: {step.detail}")
        if d.steps:
            lines.append("")
        if d.rollback:
            lines += ["<details><summary>Rollback record</summary>", "", "```json",
                      json.dumps(to_jsonable(d.rollback), indent=2), "```", "", "</details>", ""]
    if plan.edge_findings:
        lines += ["## Delegation paths", ""]
        for f in plan.edge_findings:
            lines += [
                (f"* `{f.edge.source}` **{f.edge.kind}** `{f.edge.target}`"
                 f"{' via ' + f.edge.via if f.edge.via else ''}: "
                 f"{f.total_entitlements} inherited grant(s), {f.privileged_entitlements} privileged. "
                 f"{f.recommendation}"),
            ]
        lines.append("")
    return "\n".join(lines)
