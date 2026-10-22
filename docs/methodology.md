# Methodology

## 1. Problem statement

A non-human identity (NHI) is any principal that is not a person: a service principal, managed identity, IAM role, workload identity, or an AI agent acting through one of these. Three properties make NHI authority hard to manage:

1. **Authority is transitive.** An identity that can obtain another identity's credentials, assume its role, or run code as it, inherits that identity's rights. Assigned permissions understate real authority.
2. **Authority is rarely used in full.** Broad built-in roles are granted for convenience. AI agents in particular are given wide access because their future actions are hard to predict.
3. **Removal is risky.** No one knows what will break, so excess access stays.

This project defines a repeatable method to measure effective authority and to reduce it with a provable safety check.

## 2. Model

The method works over five record types (see [data-model.md](data-model.md)):

| Record | Meaning |
|---|---|
| Identity | A non-human principal |
| Grant | A set of allowed actions, optional exclusions, at a scope, on a plane (control or data) |
| Edge | A way for one identity to act as another |
| Usage | An action an identity was observed performing at a scope on a date |
| Dependency | A declaration that a consumer needs an identity to keep certain actions at a scope |

**Scope semantics.** Hierarchical scopes (Azure resource IDs) inherit downwards and match case-insensitively. Scopes containing `*` (AWS ARNs) are wildcard matched.

**Plane semantics.** Azure separates control-plane `Actions` from data-plane `DataActions`. A wildcard in one never grants the other, so grants and usage records carry a plane and only match within it.

**Delegation edges.** `owns`, `can_add_credential`, `can_assume`, `can_impersonate`, `can_run_as` and `can_pass_role` all mean the source can obtain the target's authority.

## 3. Effective authority

For a principal P:

1. Run breadth-first search from P over delegation edges. Each reachable identity R is recorded with the shortest path P → R.
2. Effective authority = every grant held by P or any R, each tagged with its holder and path.
3. A grant is **privileged** if it allows any action from a fixed probe list of escalation and takeover actions (role assignment write, VM run command, secret read, `iam:PassRole`, `sts:AssumeRole`, policy writes, access key creation).

Shortest paths matter because the first hop of the path is what an operator removes to cut the inherited authority.

## 4. Usage attribution

For a usage window W ending on date T:

1. Keep usage records with `T − W ≤ last_seen ≤ T`.
2. A record counts as use of a grant if the grant allows the action at the scope on the plane.
3. Attribution is **conservative**: a record allowed by several grants counts as use of all of them. This can leave some excess in place but never marks a grant unused while it is in use.

**Coverage check.** If collected usage history starts after `T − W`, the method refuses to recommend any removal. Absence of evidence is only treated as evidence of absence when the evidence was actually collected.

## 5. Sequential planning

Grants are ordered broadest and most privileged first, then decided one by one against a **working set** that reflects decisions already made:

1. Let `others` = working set minus the current grant.
2. `exclusive` = usage records allowed by this grant and by nothing in `others`.
3. `sole_provider` = dependencies satisfied by this grant and by nothing in `others`.
4. If both are empty → **revoke** candidate.
5. Otherwise build a replacement grant with exactly the actions in `exclusive` and `sole_provider`, at the narrowest common scope. If that equals the current grant → **keep**; otherwise → **replace** candidate.
6. Simulate the candidate (section 6). If it fails, → **keep**.
7. Apply the decision to the working set.

Ordering by breadth means that when a wide and a narrow grant overlap, the wide one is removed and the narrow one kept. Using a working set means two overlapping grants are never each judged redundant because of the other.

## 6. Safety simulation

For a proposed grant set G′ for identity P, the simulation fails if:

1. any declared dependency on P is not fully allowed by G′, or
2. any usage record for P in the window is not allowed by G′.

Each decision is simulated individually, and the final working set is simulated again as a whole. A plan that fails the combined check is a bug and raises an error.

## 7. Staged execution

Every change is emitted as ordered steps:

1. **Snapshot**: record the original grant as a rollback record.
2. **Create** (replace only): add the narrower grant first.
3. **Verify**: run dependent workloads against the narrower grant.
4. **Remove**: delete the original grant.
5. **Watch**: monitor for authorization failures; on any failure, recreate from the rollback record.

Creating before removing means there is never a moment where the identity has less than it needs.

## 8. Delegation findings

Edges are reported separately with the count of inherited and privileged grants each one confers. Whether a delegation path is needed is an organisational question (who should own this app?) rather than one usage data can answer, so the method recommends review rather than automatic removal.

## 9. Known limitations

1. Conditions (Azure ABAC conditions, AWS condition keys), deny assignments, permission boundaries and SCPs are not yet evaluated. The engine therefore over-approximates authority, which is the safe direction for discovery but means some replacements may be wider than strictly necessary.
2. Scope narrowing uses the longest common path of observed scopes. Reviewers may want to widen a proposed scope (for example to a whole bucket rather than one prefix) for operational reasons.
3. Usage quality depends on logging. Data-plane activity in particular needs diagnostic logs enabled.
4. Replacement grants are expressed in the tool's model. Exporting them as Azure custom role definitions or IAM policy documents is on the roadmap.
