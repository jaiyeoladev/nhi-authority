"""Azure RBAC collector (read-only).

Requires: pip install "nhi-authority[azure]"
Permissions: Reader (or any role with Microsoft.Authorization/*/read) on the subscription.
Authentication uses DefaultAzureCredential (az login, managed identity, environment variables).

Collected today: role assignments to service principals and managed identities,
with their role definitions expanded into actions and data actions.

Not yet collected (see docs/roadmap.md): Entra ID application ownership and
credential-management edges (Microsoft Graph), Activity Log usage, deny assignments,
and management-group scopes.
"""
from __future__ import annotations

from typing import Any


def collect_azure(subscription_id: str) -> dict[str, Any]:
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.authorization import AuthorizationManagementClient
    except ImportError as exc:  # pragma: no cover
        raise SystemExit('Install the Azure extra first: pip install "nhi-authority[azure]"') from exc

    client = AuthorizationManagementClient(credential=DefaultAzureCredential(), subscription_id=subscription_id)
    definitions: dict[str, Any] = {}
    identities: dict[str, dict[str, Any]] = {}
    grants: list[dict[str, Any]] = []

    for ra in client.role_assignments.list_for_subscription():
        principal_type = getattr(ra, "principal_type", None)
        if principal_type != "ServicePrincipal":
            # Managed identities are also reported as ServicePrincipal.
            continue
        role_id = ra.role_definition_id
        if role_id not in definitions:
            definitions[role_id] = client.role_definitions.get_by_id(role_id)
        rd = definitions[role_id]

        control: list[str] = []
        not_control: list[str] = []
        data: list[str] = []
        not_data: list[str] = []
        for perm in rd.permissions or []:
            control += list(perm.actions or [])
            not_control += list(perm.not_actions or [])
            data += list(perm.data_actions or [])
            not_data += list(perm.not_data_actions or [])

        identities.setdefault(ra.principal_id, {
            "id": ra.principal_id,
            "type": "service_principal",
            "platform": "azure",
        })
        # Actions and DataActions are kept as separate grants because Azure
        # never lets a control-plane wildcard grant data-plane access.
        for plane, allowed, excluded in (("control", control, not_control), ("data", data, not_data)):
            if not allowed:
                continue
            grants.append({
                "id": f"{ra.name}:{plane}",
                "identity": ra.principal_id,
                "actions": allowed,
                "not_actions": excluded,
                "scope": ra.scope,
                "source": f"role:{rd.role_name}",
                "plane": plane,
            })

    return {
        "identities": list(identities.values()),
        "grants": grants,
        "edges": [],
        "usage": [],
        "dependencies": [],
    }
