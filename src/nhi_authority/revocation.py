"""Safe revocation planning.

For each grant held by an identity the planner decides one of:

* ``revoke``   nothing observed or declared needs it, or everything it is
               used for is already covered by the grants that remain
* ``replace``  part of the grant is used: swap it for a narrower grant
* ``keep``     already least-privilege, or not enough evidence to act

Decisions are made **sequentially against a working set of grants**: once
a grant is planned for removal it no longer counts as cover for the next
one. This stops two overlapping grants (for example Reader and
Contributor) from each being judged redundant because of the other.

Every change is checked by ``simulate`` before it is emitted: after the
change, every declared dependency and every action observed in the window
must still be allowed. If the check fails the decision falls back to
``keep``. Each change carries a rollback record so it can be undone exactly.

Delegation edges (ownership, assume-role, run-as) are reported separately
as review findings, because whether a path is needed is a human decision.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date

from .graph import effective_authority
from .model import Dependency, Edge, Grant, Inventory, UsageRecord, common_scope
from .usage import observation_gap_days, usage_for_grant, usage_in_window


@dataclass
class Step:
    order: int
    action: str
    detail: str


@dataclass
class GrantDecision:
    grant: Grant
    decision: str
    reason: str
    used_actions: list[str] = field(default_factory=list)
    proposed: Grant | None = None
    dependencies_touched: list[Dependency] = field(default_factory=list)
    blast_radius: int = 0
    steps: list[Step] = field(default_factory=list)
    rollback: dict | None = None


@dataclass
class EdgeFinding:
    edge: Edge
    privileged_entitlements: int
    total_entitlements: int
    recommendation: str


@dataclass
class RevocationPlan:
    identity: str
    as_of: date
    window_days: int
    observation_gap_days: int
    decisions: list[GrantDecision]
    edge_findings: list[EdgeFinding]

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for d in self.decisions:
            out[d.decision] = out.get(d.decision, 0) + 1
        return out


def _dependency_satisfied(dep: Dependency, grants: list[Grant]) -> bool:
    return all(any(g.allows(a, dep.scope, dep.plane) for g in grants) for a in dep.actions)


def _usage_satisfied(record: UsageRecord, grants: list[Grant]) -> bool:
    return any(g.allows(record.action, record.scope, record.plane) for g in grants)


def simulate(
    inv: Inventory,
    identity: str,
    grants_after: list[Grant],
    as_of: date,
    window_days: int,
) -> list[str]:
    """Problems the identity would hit if it held exactly ``grants_after``.

    An empty list means the change is safe with respect to every declared
    dependency and every action observed in the window.
    """
    problems: list[str] = []
    for dep in inv.dependencies_for(identity):
        if not _dependency_satisfied(dep, grants_after):
            problems.append(f"dependency '{dep.consumer}' would lose {list(dep.actions)} on {dep.scope}")
    for rec in usage_in_window(inv, as_of, window_days):
        if rec.identity == identity and not _usage_satisfied(rec, grants_after):
            problems.append(f"observed action {rec.action} on {rec.scope} would be denied")
    return problems


def _rollback(grant: Grant) -> dict:
    return {"operation": "recreate_grant", "grant": asdict(grant)}


def _breadth(grant: Grant) -> tuple:
    """Sort key: broadest, most privileged grants are considered first, so the
    planner removes the wide grant and keeps the narrow one, not the reverse."""
    wildcards = sum("*" in a for a in grant.actions)
    depth = grant.scope.strip("/").count("/")
    return (not grant.privileged, -wildcards, depth, grant.id)


def _decide(
    inv: Inventory,
    grant: Grant,
    working: list[Grant],
    as_of: date,
    window_days: int,
) -> GrantDecision:
    others = [g for g in working if g.id != grant.id]
    used = usage_for_grant(inv, grant, as_of, window_days)
    used_actions = sorted({u.action for u in used})
    exclusive = [u for u in used if not _usage_satisfied(u, others)]
    touched = [d for d in inv.dependencies_for(grant.identity) if _dependency_satisfied(d, [grant])]
    sole_provider = [d for d in touched if not _dependency_satisfied(d, others)]
    blast = len(sole_provider)

    if not exclusive and not sole_provider:
        problems = simulate(inv, grant.identity, others, as_of, window_days)
        if problems:
            return GrantDecision(grant, "keep", "; ".join(problems), used_actions, None, touched, blast)
        reason = (
            f"No activity in {window_days} days and no declared dependency relies on it."
            if not used else
            "Everything this grant was used for is also allowed by grants that remain."
        )
        steps = [
            Step(1, "snapshot", "Export the grant definition (rollback record below)."),
            Step(2, "notify", f"Tell the owner of '{grant.identity}' the grant will be removed and when."),
            Step(3, "remove", f"Delete grant {grant.id} ({grant.source}) at {grant.scope}."),
            Step(4, "watch", "Watch for authorization failures for the agreed period; recreate it on any break."),
        ]
        return GrantDecision(grant, "revoke", reason, used_actions, None, touched, blast, steps, _rollback(grant))

    needed_actions = {u.action for u in exclusive}
    needed_scopes = [u.scope for u in exclusive]
    for d in sole_provider:
        needed_actions.update(d.actions)
        needed_scopes.append(d.scope)
    proposed = Grant(
        id=f"{grant.id}-least-privilege",
        identity=grant.identity,
        actions=tuple(sorted(needed_actions)),
        scope=common_scope(needed_scopes),
        source=f"custom: least-privilege replacement for {grant.source or grant.id}",
        plane=grant.plane,
    )

    same_actions = {a.lower() for a in grant.actions} == {a.lower() for a in proposed.actions}
    same_scope = proposed.scope.lower() == grant.scope.lower().rstrip("/")
    if same_actions and same_scope and not grant.not_actions:
        return GrantDecision(grant, "keep", "Already least-privilege for what it is used for.",
                             used_actions, None, touched, blast)

    problems = simulate(inv, grant.identity, others + [proposed], as_of, window_days)
    if problems:
        return GrantDecision(grant, "keep", "; ".join(problems), used_actions, None, touched, blast)

    steps = [
        Step(1, "snapshot", "Export the current grant (rollback record below)."),
        Step(2, "create", f"Create the replacement: {len(proposed.actions)} action(s) at {proposed.scope}."),
        Step(3, "verify", "Run dependent workloads against the replacement before removing anything."),
        Step(4, "remove", f"Delete the original grant {grant.id} ({grant.source})."),
        Step(5, "watch", "Watch for authorization failures; roll back by recreating the original grant."),
    ]
    if same_actions:
        reason = f"Actions are right but the scope is wider than needed; narrow it to {proposed.scope}."
    else:
        reason = (f"Only {len(needed_actions)} specific action(s) are needed; the grant allows "
                  f"{', '.join(grant.actions)} at {grant.scope}.")
    return GrantDecision(
        grant, "replace", reason,
        used_actions, proposed, touched, blast, steps, _rollback(grant),
    )


def _edge_findings(inv: Inventory, identity: str) -> list[EdgeFinding]:
    ents = effective_authority(inv, identity)
    findings: list[EdgeFinding] = []
    for edge in inv.outbound_edges(identity):
        through = [e for e in ents if e.path and e.path[0] == edge]
        priv = sum(e.privileged for e in through)
        rec = (
            "Remove this path unless its owner confirms it is required: it gives privileged "
            "authority the identity was never assigned directly."
            if priv else
            "Confirm the path is still needed."
        )
        findings.append(EdgeFinding(edge, priv, len(through), rec))
    findings.sort(key=lambda f: -f.privileged_entitlements)
    return findings


def plan_for_identity(inv: Inventory, identity: str, as_of: date, window_days: int = 90) -> RevocationPlan:
    if identity not in inv.identities:
        raise KeyError(f"Unknown identity: {identity}")
    gap = observation_gap_days(inv, as_of, window_days)
    grants = sorted(inv.grants_for(identity), key=_breadth)
    decisions: list[GrantDecision] = []

    if gap > 0:
        for g in grants:
            decisions.append(GrantDecision(
                g, "keep",
                f"Usage history covers only {window_days - gap} of {window_days} days; collect more before acting.",
            ))
    else:
        working = list(grants)
        for g in grants:
            d = _decide(inv, g, working, as_of, window_days)
            if d.decision == "revoke":
                working = [w for w in working if w.id != g.id]
            elif d.decision == "replace" and d.proposed is not None:
                working = [w for w in working if w.id != g.id] + [d.proposed]
            decisions.append(d)
        final = simulate(inv, identity, working, as_of, window_days)
        if final:  # defensive: should never happen given per-step simulation
            raise AssertionError(f"Combined plan is unsafe: {final}")

    return RevocationPlan(identity, as_of, window_days, gap, decisions, _edge_findings(inv, identity))
