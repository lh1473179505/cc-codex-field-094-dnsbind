from __future__ import annotations

from typing import Any


def inspect_message(message: dict[str, Any]) -> dict[str, Any]:
    hops = []
    for section, key in (("an", "answers"), ("ns", "authority"), ("ar", "additional")):
        for rr in message.get(key) or []:
            hops.append(
                {
                    "section": section,
                    "name": rr.get("name"),
                    "type": rr.get("type"),
                    "ttl": rr.get("ttl"),
                    "rdata": rr.get("rdata"),
                }
            )
    return {
        "qname": message.get("qname"),
        "qtype": message.get("qtype"),
        "msgid": message.get("msgid"),
        "zone": message.get("zone"),
        "kid": message.get("kid"),
        "hops": hops,
    }


def admit_chain(
    message: dict[str, Any],
    keys: dict[str, Any],
    policy: dict[str, Any],
    msgid_store: dict[str, Any],
) -> dict[str, Any]:
    """Admit one signed answer chain. Stub — always denies."""
    return {
        "decision": "deny",
        "reason_codes": ["stub"],
        "qname": message.get("qname"),
        "qtype": message.get("qtype"),
        "zone": message.get("zone"),
        "kid": message.get("kid"),
        "msgid": message.get("msgid"),
        "final_name": message.get("qname"),
        "hops": [],
        "notes": ["stub"],
    }
