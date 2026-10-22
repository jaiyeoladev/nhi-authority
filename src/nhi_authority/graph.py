"""Effective authority computation.

An identity's *effective* authority is the union of:

1. grants assigned to it directly, and
2. grants held by every identity it can reach through delegation edges
   (assume, impersonate, own, add credentials, run-as, pass-role).

Reach is computed with a breadth-first search so every inherited
entitlement carries the shortest delegation path that produces it.
That path is what an operator needs to see to understand, and to cut,
the authority.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .model import Edge, Grant, Inventory


@dataclass(frozen=True)
class Entitlement:
    principal: str            # the identity being analysed
    holder: str               # the identity that actually holds the grant
    grant: Grant
    path: tuple[Edge, ...]    # delegation chain from principal to holder

    @property
    def direct(self) -> bool:
        return not self.path

    @property
    def privileged(self) -> bool:
        return self.grant.privileged

    def describe_path(self) -> str:
        if not self.path:
            return "direct"
        hops = [self.principal] + [f"--{e.kind}--> {e.target}" for e in self.path]
        return " ".join(hops)


def reachable_identities(inv: Inventory, principal: str) -> dict[str, tuple[Edge, ...]]:
    """Every identity the principal can act as, with the shortest path to it."""
    paths: dict[str, tuple[Edge, ...]] = {principal: ()}
    queue: deque[str] = deque([principal])
    while queue:
        current = queue.popleft()
        for edge in inv.outbound_edges(current):
            if edge.target in paths:
                continue
            paths[edge.target] = paths[current] + (edge,)
            queue.append(edge.target)
    return paths


def effective_authority(inv: Inventory, principal: str) -> list[Entitlement]:
    if principal not in inv.identities:
        raise KeyError(f"Unknown identity: {principal}")
    result: list[Entitlement] = []
    for holder, path in reachable_identities(inv, principal).items():
        for grant in inv.grants_for(holder):
            result.append(Entitlement(principal, holder, grant, path))
    result.sort(key=lambda e: (len(e.path), not e.privileged, e.grant.id))
    return result


def can_perform(
    inv: Inventory, principal: str, action: str, scope: str, plane: str = "any"
) -> list[Entitlement]:
    """All entitlements that let ``principal`` perform ``action`` on ``scope``."""
    return [e for e in effective_authority(inv, principal) if e.grant.allows(action, scope, plane)]


@dataclass(frozen=True)
class AuthoritySummary:
    principal: str
    direct_grants: int
    inherited_grants: int
    reachable_identities: int
    privileged_direct: int
    privileged_inherited: int

    @property
    def amplification(self) -> float:
        """How much larger effective authority is than assigned authority."""
        total = self.direct_grants + self.inherited_grants
        return round(total / self.direct_grants, 2) if self.direct_grants else float(total)


def summarise(inv: Inventory, principal: str) -> AuthoritySummary:
    ents = effective_authority(inv, principal)
    direct = [e for e in ents if e.direct]
    inherited = [e for e in ents if not e.direct]
    return AuthoritySummary(
        principal=principal,
        direct_grants=len(direct),
        inherited_grants=len(inherited),
        reachable_identities=len(reachable_identities(inv, principal)) - 1,
        privileged_direct=sum(e.privileged for e in direct),
        privileged_inherited=sum(e.privileged for e in inherited),
    )
