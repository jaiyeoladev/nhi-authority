"""Core data model.

Everything the engine reasons about is expressed as five record types:
identities, grants, edges (ways one identity can act as another),
usage records (observed activity) and dependencies (what other
systems rely on an identity being able to do).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatchcase

# Identity types the engine understands. Anything else is accepted but
# treated as a generic non-human identity.
IDENTITY_TYPES = (
    "ai_agent",
    "service_principal",
    "managed_identity",
    "iam_role",
    "iam_user",
    "workload",
)

# Edge kinds that let the source identity obtain the authority of the target.
DELEGATION_KINDS = frozenset(
    {
        "can_assume",          # AWS sts:AssumeRole via trust policy
        "can_impersonate",     # GCP / generic impersonation
        "can_add_credential",  # owner of an app registration / access key creation
        "owns",                # Entra ID application or service principal ownership
        "can_run_as",          # e.g. run command on a VM that carries a managed identity
        "can_pass_role",       # iam:PassRole into a compute service
    }
)

# Concrete actions that indicate a grant can be used to escalate privilege
# or take over other identities. A grant is "privileged" if it allows any of these.
PRIVILEGE_PROBES = (
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    "Microsoft.Compute/virtualMachines/runCommand/action",
    "Microsoft.ManagedIdentity/userAssignedIdentities/assign/action",
    "Microsoft.KeyVault/vaults/secrets/getSecret/action",
    "iam:PassRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
)


def action_matches(pattern: str, action: str) -> bool:
    """Case-insensitive wildcard match used by both Azure and AWS action strings."""
    return fnmatchcase(action.lower(), pattern.lower())


def planes_compatible(a: str, b: str) -> bool:
    """Azure keeps control-plane Actions and data-plane DataActions separate:
    a wildcard in one never grants the other."""
    return a == "any" or b == "any" or a == b


def _norm_scope(scope: str) -> str:
    s = scope.strip().lower().rstrip("/")
    return s or "/"


def scope_covers(grant_scope: str, target_scope: str) -> bool:
    """True if a grant at ``grant_scope`` applies to ``target_scope``.

    Hierarchical scopes (Azure resource IDs) inherit downwards: a grant on
    ``/subscriptions/s1`` covers ``/subscriptions/s1/resourceGroups/rg1``.
    Scopes containing ``*`` (AWS resource ARNs) are wildcard matched.
    """
    g, t = _norm_scope(grant_scope), _norm_scope(target_scope)
    if "*" in g:
        return fnmatchcase(t, g)
    if g == "/":
        return True
    return t == g or t.startswith(g + "/")


def common_scope(scopes: list[str]) -> str:
    """Narrowest hierarchical scope that contains every scope in the list.

    Comparison is case-insensitive; the casing of the first scope is kept.
    """
    if not scopes:
        return "/"
    originals = [s.strip().rstrip("/").split("/") for s in scopes]
    shared: list[str] = []
    for segment in zip(*originals, strict=False):
        if len({x.lower() for x in segment}) != 1:
            break
        shared.append(segment[0])
    joined = "/".join(shared)
    return joined if joined else "/"


@dataclass(frozen=True)
class Identity:
    id: str
    type: str
    platform: str
    owner: str | None = None
    description: str = ""


@dataclass(frozen=True)
class Grant:
    id: str
    identity: str
    actions: tuple[str, ...]
    scope: str
    not_actions: tuple[str, ...] = ()
    source: str = ""
    plane: str = "any"  # "control", "data" or "any"

    def allows_action(self, action: str) -> bool:
        return any(action_matches(p, action) for p in self.actions) and not any(
            action_matches(p, action) for p in self.not_actions
        )

    def allows(self, action: str, scope: str, plane: str = "any") -> bool:
        if not planes_compatible(self.plane, plane):
            return False
        return scope_covers(self.scope, scope) and self.allows_action(action)

    @property
    def privileged(self) -> bool:
        return any(self.allows_action(probe) for probe in PRIVILEGE_PROBES)


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    kind: str
    via: str = ""


@dataclass(frozen=True)
class UsageRecord:
    identity: str
    action: str
    scope: str
    last_seen: date
    plane: str = "any"


@dataclass(frozen=True)
class Dependency:
    consumer: str
    identity: str
    actions: tuple[str, ...]
    scope: str
    critical: bool = True
    plane: str = "any"


@dataclass
class Inventory:
    identities: dict[str, Identity] = field(default_factory=dict)
    grants: list[Grant] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    usage: list[UsageRecord] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    usage_window_start: date | None = None

    def grants_for(self, identity: str) -> list[Grant]:
        return [g for g in self.grants if g.identity == identity]

    def outbound_edges(self, identity: str) -> list[Edge]:
        return [e for e in self.edges if e.source == identity and e.kind in DELEGATION_KINDS]

    def dependencies_for(self, identity: str) -> list[Dependency]:
        return [d for d in self.dependencies if d.identity == identity]
