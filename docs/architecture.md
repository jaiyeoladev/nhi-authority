# Architecture

```
src/nhi_authority/
  model.py          records, scope and plane matching, privilege probes
  graph.py          delegation BFS, effective authority, summaries
  usage.py          usage window filtering, attribution, coverage gap
  revocation.py     sequential planner, simulation, rollback records
  report.py         markdown rendering
  loader.py         JSON inventory read, merge, serialise
  cli.py            command line entry point
  collectors/
    azure.py        Azure RBAC role assignments (read-only)
    aws.py          AWS IAM roles, policies, trust edges (read-only)
tests/              pytest suite, runs against examples/sample_inventory.json
examples/           sample inventory covering Azure and AWS agents
docs/               method, data model, roadmap
```

## Design rules

1. **Core has no dependencies.** The engine runs on the Python standard library. Cloud SDKs are optional extras used only by collectors.
2. **Collectors only read.** Nothing in this repository changes cloud state. Plans are output for humans or pipelines to apply.
3. **Every decision is explainable.** Entitlements carry their delegation path; decisions carry a reason, the observed actions and the dependencies touched.
4. **Fail safe.** Where evidence is missing or a simulation fails, the answer is `keep`.

## Extending

1. **New platform**: add a collector that returns the inventory dictionary described in [data-model.md](data-model.md).
2. **New delegation kind**: add it to `DELEGATION_KINDS` in `model.py` and emit edges from a collector.
3. **New privilege probe**: add the concrete action to `PRIVILEGE_PROBES`.
