"""AWS IAM collector (read-only).

Requires: pip install "nhi-authority[aws]"
Permissions: iam:GetAccountAuthorizationDetails, sts:GetCallerIdentity
(the AWS managed policy SecurityAudit covers both).

Collected today: IAM roles, their inline and attached policies (Allow statements
become grants, Deny statements with Resource "*" become exclusions), and trust
policies (AWS principals become can_assume edges).

Not yet collected (see docs/roadmap.md): CloudTrail usage, permission boundaries,
SCPs, resource-based policies, and condition keys.
"""
from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote


def _doc(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return json.loads(unquote(value))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _identity_type(trust: dict[str, Any]) -> str:
    services: list[str] = []
    for st in _as_list(trust.get("Statement")):
        services += _as_list((st.get("Principal") or {}).get("Service"))
    if any("bedrock" in s for s in services):
        return "ai_agent"
    if services:
        return "iam_role"
    return "iam_role"


def _statements_to_grants(
    role_arn: str, policy_name: str, document: dict[str, Any], start: int
) -> list[dict[str, Any]]:
    grants: list[dict[str, Any]] = []
    denies: list[str] = []
    for st in _as_list(document.get("Statement")):
        if st.get("Effect") == "Deny" and "*" in _as_list(st.get("Resource")):
            denies += _as_list(st.get("Action"))
    for st in _as_list(document.get("Statement")):
        if st.get("Effect") != "Allow" or "Action" not in st:
            continue  # NotAction statements are reported in roadmap as unsupported
        for resource in _as_list(st.get("Resource")) or ["*"]:
            grants.append({
                "id": f"{role_arn}#{policy_name}#{start + len(grants)}",
                "identity": role_arn,
                "actions": _as_list(st["Action"]),
                "not_actions": denies,
                "scope": resource,
                "source": f"policy:{policy_name}",
            })
    return grants


def collect_aws(profile: str | None = None) -> dict[str, Any]:
    try:
        import boto3
    except ImportError as exc:  # pragma: no cover
        raise SystemExit('Install the AWS extra first: pip install "nhi-authority[aws]"') from exc

    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    iam = session.client("iam")
    roles: list[dict[str, Any]] = []
    managed: dict[str, dict[str, Any]] = {}

    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["Role", "LocalManagedPolicy", "AWSManagedPolicy"]):
        roles += page.get("RoleDetailList", [])
        for pol in page.get("Policies", []):
            default = next((v for v in pol.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
            if default:
                managed[pol["Arn"]] = {"name": pol["PolicyName"], "doc": _doc(default["Document"])}

    identities: list[dict[str, Any]] = []
    grants: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for role in roles:
        arn = role["Arn"]
        trust = _doc(role.get("AssumeRolePolicyDocument") or {})
        identities.append({"id": arn, "type": _identity_type(trust), "platform": "aws",
                           "description": role.get("Description", "")})
        for inline in role.get("RolePolicyList", []):
            grants += _statements_to_grants(arn, inline["PolicyName"], _doc(inline["PolicyDocument"]), len(grants))
        for attached in role.get("AttachedManagedPolicies", []):
            pol = managed.get(attached["PolicyArn"])
            if pol:
                grants += _statements_to_grants(arn, pol["name"], pol["doc"], len(grants))
        for st in _as_list(trust.get("Statement")):
            if st.get("Effect") != "Allow":
                continue
            for principal in _as_list((st.get("Principal") or {}).get("AWS")):
                edges.append({"source": principal, "target": arn, "kind": "can_assume", "via": "trust policy"})

    known = {i["id"] for i in identities}
    for e in edges:
        if e["source"] not in known:
            identities.append({"id": e["source"], "type": "external_principal", "platform": "aws"})
            known.add(e["source"])

    return {"identities": identities, "grants": grants, "edges": edges, "usage": [], "dependencies": []}
