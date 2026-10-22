"""Matching observed activity against grants.

Attribution is deliberately conservative: if one observed action is
allowed by two grants, it counts as usage of *both*. That can leave
some excess in place, but it never marks a grant as unused while a
live workload still depends on it.
"""
from __future__ import annotations

from datetime import date, timedelta

from .model import Grant, Inventory, UsageRecord


def usage_in_window(inv: Inventory, as_of: date, window_days: int) -> list[UsageRecord]:
    cutoff = as_of - timedelta(days=window_days)
    return [u for u in inv.usage if cutoff <= u.last_seen <= as_of]


def usage_for_grant(inv: Inventory, grant: Grant, as_of: date, window_days: int) -> list[UsageRecord]:
    return [
        u
        for u in usage_in_window(inv, as_of, window_days)
        if u.identity == grant.identity and grant.allows(u.action, u.scope, u.plane)
    ]


def observation_gap_days(inv: Inventory, as_of: date, window_days: int) -> int:
    """Days of the analysis window not covered by collected usage data.

    A non-zero gap means "unused" cannot be trusted yet: the engine will
    refuse to recommend revocation until enough history has been collected.
    """
    if inv.usage_window_start is None:
        return window_days
    covered = (as_of - inv.usage_window_start).days
    return max(0, window_days - covered)
