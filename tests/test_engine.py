from datetime import date
from pathlib import Path

import pytest

from nhi_authority import can_perform, effective_authority, load_inventory, plan_for_identity, summarise
from nhi_authority.loader import inventory_from_dict
from nhi_authority.model import common_scope, scope_covers
from nhi_authority.revocation import simulate

SAMPLE = Path(__file__).parent.parent / "examples" / "sample_inventory.json"
AS_OF = date(2026, 10, 20)
AGENT = "support-copilot"
AWS_AGENT = "arn:aws:iam::111122223333:role/invoice-agent"


@pytest.fixture()
def inv():
    return load_inventory(SAMPLE)


# Scope semantics -----------------------------------------------------------

def test_hierarchical_scope_inherits_downwards():
    assert scope_covers("/subscriptions/s1", "/subscriptions/s1/resourceGroups/rg")
    assert not scope_covers("/subscriptions/s1/resourceGroups/rg", "/subscriptions/s1")
    assert not scope_covers("/subscriptions/s1", "/subscriptions/s10")


def test_scope_matching_is_case_insensitive():
    assert scope_covers("/Subscriptions/S1/resourceGroups/RG", "/subscriptions/s1/resourcegroups/rg/x")


def test_wildcard_scope_for_arns():
    assert scope_covers("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/a/b.txt")
    assert not scope_covers("arn:aws:s3:::bucket/*", "arn:aws:s3:::other/a")


def test_common_scope_keeps_original_case():
    assert common_scope(["/a/B/c", "/a/b/D"]) == "/a/B"


# Effective authority -------------------------------------------------------

def test_ownership_edge_exposes_latent_owner_rights(inv):
    hits = can_perform(inv, AGENT, "Microsoft.Authorization/roleAssignments/write", "/subscriptions/sub-prod")
    assert hits, "agent should reach Owner through the app it owns"
    assert all(not h.direct for h in hits)
    assert hits[0].holder == "ci-deployer"


def test_contributor_not_actions_are_respected(inv):
    direct = [e for e in can_perform(
        inv, AGENT, "Microsoft.Authorization/roleAssignments/write",
        "/subscriptions/sub-prod/resourceGroups/rg-support") if e.direct]
    assert direct == []


def test_control_plane_wildcard_does_not_grant_data_plane(inv):
    hits = can_perform(
        inv, AGENT, "Microsoft.KeyVault/vaults/secrets/getSecret/action",
        "/subscriptions/sub-prod/resourceGroups/rg-support/providers/Microsoft.KeyVault/vaults/kv-support",
        plane="data",
    )
    sources = {h.grant.source for h in hits if h.direct}
    assert sources == {"role:Key Vault Secrets User"}


def test_summary_reports_amplification(inv):
    s = summarise(inv, AGENT)
    assert s.inherited_grants == 1 and s.privileged_inherited == 1
    assert s.amplification > 1


def test_unknown_identity_raises(inv):
    with pytest.raises(KeyError):
        effective_authority(inv, "nobody")


# Revocation planning -------------------------------------------------------

def _decisions(plan):
    return {d.grant.id: d for d in plan.decisions}


def test_unused_privileged_grant_is_revoked(inv):
    d = _decisions(plan_for_identity(inv, AGENT, AS_OF))
    assert d["az-ra-kv-secrets"].decision == "revoke"
    assert d["az-ra-kv-secrets"].rollback["grant"]["id"] == "az-ra-kv-secrets"


def test_overlapping_grants_are_not_both_removed(inv):
    d = _decisions(plan_for_identity(inv, AGENT, AS_OF))
    assert d["az-ra-contributor"].decision == "revoke"
    assert d["az-ra-reader"].decision in {"keep", "replace"}


def test_dependency_is_preserved_by_replacement(inv):
    d = _decisions(plan_for_identity(inv, AWS_AGENT, AS_OF))
    s3 = d["aws-s3-all"]
    assert s3.decision == "replace"
    assert "s3:DeleteObject" in s3.proposed.actions  # declared by nightly-attachment-cleanup
    assert s3.blast_radius == 1


def test_whole_plan_is_safe_when_applied_together(inv):
    for identity in (AGENT, AWS_AGENT):
        plan = plan_for_identity(inv, identity, AS_OF)
        after = [g for g in inv.grants_for(identity)]
        for d in plan.decisions:
            if d.decision in {"revoke", "replace"}:
                after = [g for g in after if g.id != d.grant.id]
            if d.proposed:
                after.append(d.proposed)
        assert simulate(inv, identity, after, AS_OF, plan.window_days) == []


def test_activity_outside_window_is_ignored(inv):
    # restart/action was last seen in April, so it must not be kept alive.
    d = _decisions(plan_for_identity(inv, AGENT, AS_OF))
    for dec in d.values():
        if dec.proposed:
            assert "Microsoft.Web/sites/restart/action" not in dec.proposed.actions


def test_insufficient_history_blocks_all_changes():
    data = {
        "usage_window_start": "2026-10-01",
        "identities": [{"id": "a", "type": "ai_agent", "platform": "azure"}],
        "grants": [{"id": "g", "identity": "a", "actions": ["*"], "scope": "/subscriptions/s"}],
    }
    plan = plan_for_identity(inventory_from_dict(data), "a", AS_OF, 90)
    assert plan.observation_gap_days > 0
    assert {d.decision for d in plan.decisions} == {"keep"}


def test_grant_referencing_unknown_identity_is_rejected():
    with pytest.raises(ValueError):
        inventory_from_dict({"grants": [{"identity": "ghost", "actions": ["*"], "scope": "/"}]})
