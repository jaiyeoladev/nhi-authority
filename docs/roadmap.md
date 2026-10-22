# Roadmap

## 0.1 (this release)

1. Effective authority over delegation edges with shortest paths
2. Control and data plane separation
3. Conservative usage attribution with coverage check
4. Sequential revocation planner with per-step and whole-plan simulation
5. Rollback records
6. Azure RBAC and AWS IAM read-only collectors
7. CLI with markdown and JSON output

## 0.2 Usage ingestion

1. Azure Activity Log and Log Analytics query export to `usage` records
2. AWS CloudTrail (management and data events) via Athena or CloudTrail Lake export
3. AWS IAM last-accessed data as a coarse fallback

## 0.3 Richer delegation edges

1. Entra ID application and service principal owners (Microsoft Graph) as `owns` edges
2. Managed identities attached to VMs, functions and app services, with `can_run_as` edges from identities that can run code there
3. AWS `iam:PassRole` into Lambda, EC2, ECS and Bedrock agents as `can_pass_role` edges
4. GCP service account impersonation

## 0.4 Policy accuracy

1. Azure deny assignments and ABAC conditions
2. AWS permission boundaries, SCPs, resource-based policies and condition keys
3. AWS `NotAction` statements

## 0.5 Output for change pipelines

1. Export replacement grants as Azure custom role definitions and IAM policy documents
2. Terraform and Bicep snippets for each step
3. Pull-request mode that opens a change per decision

## Research directions

1. AI agent tool manifests as a source of declared dependencies
2. Risk scoring that weights authority by data sensitivity of the scope
3. Continuous mode that re-plans as usage changes and flags drift
