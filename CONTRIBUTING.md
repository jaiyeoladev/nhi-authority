# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Set up

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check src tests
```

## Ground rules

1. **Safety first.** Any change to the planner must keep the safety properties listed in the README. Add a test that proves it.
2. **Read-only collectors.** Collectors must never change cloud state.
3. **No real data.** Never commit inventories, IDs, account numbers or names from a real tenant. Use the style of `examples/sample_inventory.json`.
4. **Core stays dependency-free.** Put SDK imports inside collector functions and add them to an optional extra in `pyproject.toml`.
5. **Explain decisions.** New decision logic should produce a reason a human can read.

## Good first contributions

1. Azure Activity Log export to `usage` records
2. Entra ID application owner edges via Microsoft Graph
3. Export of replacement grants as Azure custom role JSON

See [docs/roadmap.md](docs/roadmap.md) for more.
