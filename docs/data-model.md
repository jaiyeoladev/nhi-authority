# Inventory data model

The engine reads one JSON file. Collectors produce the `identities`, `grants` and `edges` sections. `usage` and `dependencies` come from log exports and from teams that own dependent systems. See `examples/sample_inventory.json` for a complete example.

## Top level

| Field | Type | Required | Notes |
|---|---|---|---|
| `usage_window_start` | date (YYYY-MM-DD) | Recommended | Earliest date usage data was collected from. If missing, no removal is recommended |
| `identities` | list | Yes | |
| `grants` | list | Yes | |
| `edges` | list | No | |
| `usage` | list | No | |
| `dependencies` | list | No | |

## identities

| Field | Required | Notes |
|---|---|---|
| `id` | Yes | Object ID, ARN or any stable unique ID |
| `type` | No | `ai_agent`, `service_principal`, `managed_identity`, `iam_role`, `iam_user`, `workload` |
| `platform` | No | `azure`, `aws`, `gcp`, ... |
| `owner` | No | Team or person accountable |
| `description` | No | |

## grants

| Field | Required | Notes |
|---|---|---|
| `id` | No | Defaults to `grant-<n>` |
| `identity` | Yes | Must match an identity `id` |
| `actions` | Yes | Wildcards allowed: `*`, `*/read`, `s3:Get*` |
| `not_actions` | No | Exclusions, same syntax |
| `scope` | Yes | Azure resource ID path or ARN (wildcards allowed) |
| `source` | No | Human label, for example `role:Contributor` |
| `plane` | No | `control`, `data` or `any` (default) |

## edges

| Field | Required | Notes |
|---|---|---|
| `source` | Yes | Identity that gains authority |
| `target` | Yes | Identity whose authority is gained |
| `kind` | Yes | `owns`, `can_add_credential`, `can_assume`, `can_impersonate`, `can_run_as`, `can_pass_role` |
| `via` | No | How, in plain words |

## usage

| Field | Required | Notes |
|---|---|---|
| `identity` | Yes | |
| `action` | Yes | Concrete action, no wildcards |
| `scope` | Yes | Concrete resource |
| `last_seen` | Yes | Date the action was last observed |
| `plane` | No | `control`, `data` or `any` |

Typical sources: Azure Activity Log (control plane), Azure resource diagnostic logs (data plane), AWS CloudTrail management and data events. Aggregate to one record per identity, action and scope with the latest date.

## dependencies

| Field | Required | Notes |
|---|---|---|
| `consumer` | Yes | System that relies on the identity |
| `identity` | Yes | |
| `actions` | Yes | Actions the consumer needs the identity to keep |
| `scope` | Yes | |
| `critical` | No | Default `true` |
| `plane` | No | |

Dependencies capture needs that usage logs may not show yet, such as a quarterly job or a disaster recovery runbook.
