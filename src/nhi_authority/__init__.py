"""nhi-authority: compute the real scope of authority held by non-human and
AI agent identities, and plan safe removal of the excess."""

from .graph import can_perform, effective_authority, reachable_identities, summarise
from .loader import inventory_from_dict, load_inventory
from .revocation import plan_for_identity, simulate

__all__ = [
    "can_perform",
    "effective_authority",
    "inventory_from_dict",
    "load_inventory",
    "plan_for_identity",
    "reachable_identities",
    "simulate",
    "summarise",
]

__version__ = "0.1.0"
