from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any


class LoadFailureError(ValueError):
    """Raised when an input cannot be shaped into an admittable message."""


NAME_TYPES = {"CNAME", "NS", "PTR"}


def _plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def canonical_name(value: Any) -> str:
    if not isinstance(value, str):
        raise LoadFailureError("name must be a string")
    name = value.strip().lower()
    if not name:
        raise LoadFailureError("empty name")
    try:
        name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise LoadFailureError("name must be ASCII") from exc
    while name.endswith(".."):
        name = name[:-1]
    if not name.endswith("."):
        name += "."
    labels = name.split(".")
    if any(label == "" for label in labels[:-1]):
        raise LoadFailureError("empty label in name")
    return name


def canonical_rdata(rr_type: str, rdata: Any) -> str:
    if not isinstance(rdata, str):
        raise LoadFailureError("rdata must be a string")
    if rr_type in NAME_TYPES:
        return canonical_name(rdata)
    if rr_type == "A":
        octets = rdata.strip().split(".")
        if len(octets) != 4 or any(
            not octet.isascii()
            or not octet.isdigit()
            or (len(octet) > 1 and octet[0] == "0")
            or not 0 <= int(octet) <= 255
            for octet in octets
        ):
            raise LoadFailureError("invalid A rdata")
        return ".".join(octets)
    if rr_type == "AAAA":
        return rdata.strip().lower()
    return rdata.strip()


def in_bailiwick(name: str, apex: str) -> bool:
    return name == apex or name.endswith("." + apex)


def _prepare_rr(rr: Any) -> dict[str, Any]:
    if not isinstance(rr, dict):
        raise LoadFailureError("RR must be an object")
    for field in ("name", "type", "ttl", "rdata"):
        if field not in rr:
            raise LoadFailureError(f"RR missing field {field}")
    if not _plain_int(rr["ttl"]):
        raise LoadFailureError("RR ttl must be a JSON integer")
    if not isinstance(rr["type"], str):
        raise LoadFailureError("RR type must be a string")
    rr_type = rr["type"].strip().upper()
    return {
        "name": canonical_name(rr["name"]),
        "type": rr_type,
        "ttl": rr["ttl"],
        "rdata": canonical_rdata(rr_type, rr["rdata"]),
    }


def _section(message: dict[str, Any], key: str) -> list:
    value = message.get(key)
    if not isinstance(value, list):
        raise LoadFailureError(f"{key} must be an array")
    return value


def _validate(
    message: dict[str, Any],
    keys_doc: dict[str, Any],
    policy: dict[str, Any],
    msgid_store: dict[str, Any],
) -> None:
    required = ("version", "msgid", "qname", "qtype", "zone", "kid", "sig")
    for field in required:
        if field not in message:
            raise LoadFailureError(f"message missing field {field}")
    for section in ("answers", "authority", "additional"):
        if section not in message or not isinstance(message[section], list):
            raise LoadFailureError(f"message field {section} must be an array")
    if not _plain_int(message["msgid"]):
        raise LoadFailureError("msgid must be a JSON integer")
    if not isinstance(message["qtype"], str):
        raise LoadFailureError("qtype must be a string")
    if not isinstance(message["kid"], str):
        raise LoadFailureError("kid must be a string")
    if not isinstance(message["sig"], str):
        raise LoadFailureError("sig must be a string")
    if not isinstance(keys_doc, dict) or not isinstance(keys_doc.get("keys"), dict):
        raise LoadFailureError("keys document must have a keys object")
    key = keys_doc["keys"].get(message["kid"])
    if key is None:
        raise LoadFailureError("unknown kid")
    if not isinstance(key, dict) or not isinstance(key.get("secret"), str):
        raise LoadFailureError("key must be an object with a string secret")
    if key.get("status") not in ("active", "revoked"):
        raise LoadFailureError("key status must be active or revoked")
    canonical_name(key["zone"])
    if not isinstance(policy, dict):
        raise LoadFailureError("policy must be an object")
    if not _plain_int(policy.get("min_ttl")):
        raise LoadFailureError("policy.min_ttl must be an integer")
    if not _plain_int(policy.get("max_cname_depth")):
        raise LoadFailureError("policy.max_cname_depth must be an integer")
    if not isinstance(policy.get("allow_glue"), bool):
        raise LoadFailureError("policy.allow_glue must be a boolean")
    if not isinstance(msgid_store, dict) or not isinstance(
        msgid_store.get("msgids"), dict
    ):
        raise LoadFailureError("msgid store must be an object with a msgids object")


def _canonical_line(
    message: dict[str, Any],
    sections: dict[str, list[dict[str, Any]]],
    qname: str,
    qtype: str,
    zone: str,
) -> str:
    tokens = []
    for code, key in (("an", "answers"), ("ns", "authority"), ("ar", "additional")):
        for rr in sections[key]:
            tokens.append(
                f"{code}/{rr['name']}/{rr['type']}/{rr['ttl']}/{rr['rdata']}"
            )
    return (
        f"v1|{message['msgid']}|{qname}|{qtype}|{zone}|{message['kid']}|"
        + ",".join(tokens)
    )


def _signature(secret: str, line: str) -> str:
    stripped = secret.strip()
    if stripped and len(stripped) % 2 == 0 and all(
        ch in "0123456789abcdefABCDEF" for ch in stripped
    ):
        material = bytes.fromhex(stripped)
    else:
        material = secret.encode("utf-8")
    digest = hmac.new(material, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


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
    """Admit one signed answer chain. Returns the report object."""
    _validate(message, keys, policy, msgid_store)

    qname = canonical_name(message["qname"])
    qtype = message["qtype"].strip().upper()
    zone = canonical_name(message["zone"])
    sections = {
        key: [_prepare_rr(rr) for rr in _section(message, key)]
        for key in ("answers", "authority", "additional")
    }
    key = keys["keys"][message["kid"]]

    def deny(code: str, *, final_name: str = qname, hops: list[str] | None = None):
        return {
            "decision": "deny",
            "reason_codes": [code],
            "qname": qname,
            "qtype": qtype,
            "zone": zone,
            "kid": message["kid"],
            "msgid": message["msgid"],
            "final_name": final_name,
            "hops": [qname] if hops is None else hops,
            "notes": [],
        }

    if message["version"] != "v1":
        return deny("version_rejected")
    if key["status"] == "revoked":
        return deny("kid_revoked")
    if canonical_name(key["zone"]) != zone:
        return deny("zone_mismatch")

    line = _canonical_line(message, sections, qname, qtype, zone)
    if not hmac.compare_digest(_signature(key["secret"], line), message["sig"]):
        return deny("bad_signature")

    if str(message["msgid"]) in msgid_store["msgids"]:
        return deny("replay")

    min_ttl = policy["min_ttl"]
    for rr in sections["answers"] + sections["authority"] + sections["additional"]:
        if rr["ttl"] < min_ttl:
            return deny("ttl_floor")

    for rr in sections["answers"]:
        if not in_bailiwick(rr["name"], zone):
            return deny("out_of_bailiwick")
        if rr["type"] in NAME_TYPES and not in_bailiwick(rr["rdata"], zone):
            return deny("out_of_bailiwick")

    answers = sections["answers"]
    is_referral = not answers and any(
        rr["type"] == "NS" for rr in sections["authority"]
    )
    if is_referral:
        outside: list[str] = []
        for rr in sections["authority"]:
            if rr["type"] == "NS" and not in_bailiwick(rr["rdata"], zone):
                if rr["rdata"] not in outside:
                    outside.append(rr["rdata"])
        if outside and not policy["allow_glue"]:
            return deny("glue_forbidden")
        if outside:
            glue_owners = {
                rr["name"]
                for rr in sections["additional"]
                if rr["type"] in ("A", "AAAA")
            }
            for ns_name in outside:
                if ns_name not in glue_owners:
                    return deny("missing_glue")
    else:
        current = qname
        followed = 0
        hops = [current]
        while True:
            links = [
                rr
                for rr in answers
                if rr["name"] == current and rr["type"] == "CNAME"
            ]
            if not links:
                break
            if followed >= policy["max_cname_depth"]:
                return deny("cname_depth", final_name=current, hops=hops)
            target = links[0]["rdata"]
            if target in hops:
                return deny("cname_loop", final_name=current, hops=hops)
            hops.append(target)
            current = target
            followed += 1
        if not any(rr["name"] == current and rr["type"] == qtype for rr in answers):
            return deny("nodata", final_name=current, hops=hops)

    msgid_store["msgids"][str(message["msgid"])] = True
    final_name = qname if is_referral else current
    hops = [qname] if is_referral else hops
    return {
        "decision": "allow",
        "reason_codes": [],
        "qname": qname,
        "qtype": qtype,
        "zone": zone,
        "kid": message["kid"],
        "msgid": message["msgid"],
        "final_name": final_name,
        "hops": hops,
        "notes": [],
    }
