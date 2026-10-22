"""Read and write the JSON inventory format (see docs/data-model.md)."""
from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .model import Dependency, Edge, Grant, Identity, Inventory, UsageRecord


def _date(value: str | None) -> date | None:
    return date.fromisoformat(value) if value else None


def inventory_from_dict(data: dict[str, Any]) -> Inventory:
    inv = Inventory(usage_window_start=_date(data.get("usage_window_start")))
    for i in data.get("identities", []):
        inv.identities[i["id"]] = Identity(
            id=i["id"], type=i.get("type", "workload"), platform=i.get("platform", "unknown"),
            owner=i.get("owner"), description=i.get("description", ""),
        )
    for n, g in enumerate(data.get("grants", [])):
        inv.grants.append(Grant(
            id=g.get("id", f"grant-{n}"), identity=g["identity"], actions=tuple(g["actions"]),
            scope=g["scope"], not_actions=tuple(g.get("not_actions", [])), source=g.get("source", ""),
            plane=g.get("plane", "any"),
        ))
    for e in data.get("edges", []):
        inv.edges.append(Edge(source=e["source"], target=e["target"], kind=e["kind"], via=e.get("via", "")))
    for u in data.get("usage", []):
        inv.usage.append(UsageRecord(
            identity=u["identity"], action=u["action"], scope=u["scope"], last_seen=date.fromisoformat(u["last_seen"]),
            plane=u.get("plane", "any"),
        ))
    for d in data.get("dependencies", []):
        inv.dependencies.append(Dependency(
            consumer=d["consumer"], identity=d["identity"], actions=tuple(d["actions"]),
            scope=d["scope"], critical=d.get("critical", True), plane=d.get("plane", "any"),
        ))
    unknown = {g.identity for g in inv.grants} - set(inv.identities)
    if unknown:
        raise ValueError(f"Grants reference unknown identities: {sorted(unknown)}")
    return inv


def load_inventory(path: str | Path) -> Inventory:
    with open(path, encoding="utf-8") as fh:
        return inventory_from_dict(json.load(fh))


def merge(*parts: dict[str, Any]) -> dict[str, Any]:
    """Combine raw inventories from several collectors into one."""
    out: dict[str, Any] = {k: [] for k in ("identities", "grants", "edges", "usage", "dependencies")}
    seen: set[str] = set()
    for part in parts:
        for i in part.get("identities", []):
            if i["id"] not in seen:
                seen.add(i["id"])
                out["identities"].append(i)
        for key in ("grants", "edges", "usage", "dependencies"):
            out[key].extend(part.get(key, []))
    starts = [p["usage_window_start"] for p in parts if p.get("usage_window_start")]
    if starts:
        out["usage_window_start"] = max(starts)
    return out


def to_jsonable(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, date):
        return obj.isoformat()
    return obj
