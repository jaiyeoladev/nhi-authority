# nhi-authority

**Compute the real scope of authority held by non-human and AI agent identities in cloud environments, and revoke the excess without breaking the systems that depend on them.**

Service principals, managed identities, IAM roles and, increasingly, autonomous AI agents now outnumber human users in most cloud estates. Their permissions are usually granted once, broadly, and never revisited. Worse, the permissions *assigned* to an identity are rarely the permissions it can actually *exercise*: an agent that owns an app registration can add a secret to it and act as that app; a role that can be assumed by another role passes all of its rights along.

`nhi-authority` answers three questions for every non-human identity:

1. **What can it really do?** Its effective authority: direct grants plus everything reachable through delegation paths (ownership, assume-role, impersonation, run-as, pass-role), each with the exact path that produces it.
2. **What does it actually use?** Observed activity over a time window, matched to the grants that permit it.
3. **What can be safely removed?** A staged revocation plan where every change has been simulated against observed usage and declared dependencies, and carries an exact rollback record.

## Why this matters

| Problem | What the tool does |
|---|---|
| Assigned permissions understate real authority | Follows delegation edges and reports inherited, often privileged, grants with the path that grants them |
| AI agents are given broad roles "to be safe" | Compares granted actions with observed actions and proposes least-privilege replacements |
| Teams are afraid to remove access in case something breaks | Simulates every change; refuses to recommend anything that would deny an observed action or a declared dependency |
| Overlapping grants hide each other | Plans changes sequentially, so two redundant grants are never both removed |
| Thin logs make "unused" look true when it isn't | Refuses to recommend removal until the usage window is fully covered by collected data |

## Quick start

```bash
git clone https://github.com/<your-account>/nhi-authority.git
cd nhi-authority
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Run it against the bundled example:

```bash
nhi-authority list examples/sample_inventory.json
nhi-authority authority examples/sample_inventory.json --identity support-copilot
nhi-authority plan examples/sample_inventory.json --identity support-copilot --as-of 2026-10-20
nhi-authority check examples/sample_inventory.json --identity support-copilot \
  --action Microsoft.Authorization/roleAssignments/write --scope /subscriptions/sub-prod
```

The last command shows the core idea in one line. The support agent was never assigned Owner, yet:

```
ALLOWED: support-copilot can perform Microsoft.Authorization/roleAssignments/write on /subscriptions/sub-prod
  via role:Owner held by ci-deployer [support-copilot --owns--> ci-deployer]
```

It owns the `ci-deployer` app registration, so it can add a credential to it and act with that app's Owner rights.

## Example plan output

For the same agent, `plan` produces (abridged):

| # | Decision | Grant | Why |
|---|---|---|---|
| 1 | Revoke | Contributor on rg-support | Everything it was used for is also allowed by grants that remain |
| 2 | Revoke | Key Vault Secrets User | No activity in 90 days, no declared dependency |
| 3 | Replace | Reader on the subscription | Only `Microsoft.Web/sites/read` on one app is needed |
| 4 | Replace | Storage Blob Data Reader | Narrow from the storage account to the one container used |
| 5 | Replace | Storage Queue Data Message Sender | Narrow to the `tickets` queue, which `ticket-ingest-function` depends on |

Plus a delegation finding: the ownership of `ci-deployer` gives the agent privileged authority it was never assigned, and should be removed unless an owner confirms it is needed.

Each decision includes ordered steps (snapshot, create replacement, verify, remove, watch) and a JSON rollback record.

## Collect from a live account (read-only)

```bash
pip install -e ".[azure]"
az login
nhi-authority collect azure --subscription <subscription-id> -o azure.json

pip install -e ".[aws]"
nhi-authority collect aws --profile <profile> -o aws.json
```

Collectors only read configuration. They never change cloud state. See [docs/data-model.md](docs/data-model.md) for how to add usage records and dependency declarations, and [docs/roadmap.md](docs/roadmap.md) for what is collected today versus planned.

## How it works

```
 collectors (read-only)          engine                          outputs
 ┌──────────────────┐   ┌──────────────────────────────┐   ┌─────────────────────┐
 │ Azure RBAC       │   │ 1. authority graph (BFS over │   │ authority report    │
 │ AWS IAM          │──▶│    delegation edges)         │──▶│ revocation plan     │
 │ usage exports    │   │ 2. usage attribution         │   │ rollback records    │
 │ dependency decls │   │ 3. sequential planner        │   │ JSON for pipelines  │
 └──────────────────┘   │ 4. safety simulation         │   └─────────────────────┘
                        └──────────────────────────────┘
```

Read [docs/methodology.md](docs/methodology.md) for the method and its safety properties, and [docs/architecture.md](docs/architecture.md) for the code layout.

## Safety properties

The planner guarantees, and the test suite checks, that:

1. No recommended change denies any action observed in the usage window.
2. No recommended change breaks a declared dependency.
3. The full set of changes, applied together, still satisfies 1 and 2.
4. No removal is recommended while usage history is incomplete for the window.
5. Every change has a rollback record that recreates the original grant exactly.

## Project status

Early release (0.1). The engine, CLI, Azure RBAC and AWS IAM collectors, and test suite work today. Usage ingestion from Azure Activity Log and AWS CloudTrail, Entra ID ownership edges, and policy export are on the [roadmap](docs/roadmap.md). Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
