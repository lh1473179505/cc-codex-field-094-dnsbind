from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_json(path: str | Path) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def load_msgid_store(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return {"msgids": {}}
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "msgids" not in data:
        raise ValueError("msgid store must be an object with msgids")
    if not isinstance(data["msgids"], dict):
        raise ValueError("msgids must be an object")
    return data


def save_msgid_store(path: str | Path, store: dict) -> None:
    """Atomically replace a msgid store. Caller decides when to save."""
    if not isinstance(store, dict) or not isinstance(store.get("msgids"), dict):
        raise ValueError("msgid store must be an object with msgids")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(
        json.dumps(store, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    tmp.replace(p)
