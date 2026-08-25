from __future__ import annotations

import re
from dataclasses import dataclass

from sark.models import Record
from sark.resp import RespError, SupportsResp

NAMESPACE_SCAN_CAP = 5000
SCAN_PAGE = 200

KEYSPACE_PATTERN = re.compile(r"^db(\d+):keys=(\d+)")


@dataclass(frozen=True)
class ReadBudget:
    scalar_cap: int = 4096
    hash_fields: int = 64
    list_items: int = 128
    set_items: int = 128
    zset_items: int = 128
    stream_entries: int = 64


PREVIEW_BUDGET = ReadBudget(
    scalar_cap=200,
    hash_fields=3,
    list_items=3,
    set_items=3,
    zset_items=3,
    stream_entries=3,
)

DUMP_BUDGET = ReadBudget()


def namespace_of(key: str) -> str:
    return key.split(":", 1)[0] if ":" in key else "(root)"


def parse_databases(info_text: str) -> dict[str, int]:
    databases: dict[str, int] = {}
    for line in info_text.splitlines():
        match = KEYSPACE_PATTERN.match(line)
        if match:
            databases[f"db{match.group(1)}"] = int(match.group(2))
    return databases


def _cap(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[{len(text)} chars]"


async def key_type(conn: SupportsResp, key: str) -> str:
    reply = await conn.execute("TYPE", key)
    return str(reply.value)


async def pttl_ms(conn: SupportsResp, key: str) -> int | None:
    try:
        reply = await conn.execute("PTTL", key)
    except RespError:
        return None
    value = reply.value
    if isinstance(value, int):
        return value if value != -2 else None
    return None


async def collect_keys(
    conn: SupportsResp,
    pattern: str,
    *,
    max_keys: int = NAMESPACE_SCAN_CAP,
    count: int = SCAN_PAGE,
) -> tuple[list[str], bool]:
    cursor = "0"
    keys: list[str] = []
    while True:
        reply = await conn.execute("SCAN", cursor, "MATCH", pattern, "COUNT", str(count))
        payload = reply.value
        if not (isinstance(payload, list) and len(payload) == 2):
            raise RespError("malformed SCAN reply", b"")
        cursor = str(payload[0])
        batch = payload[1]
        for key in batch:
            text = str(key)
            if text not in keys:
                keys.append(text)
                if len(keys) >= max_keys:
                    return keys, True
        if cursor == "0":
            return keys, False


async def read_value(
    conn: SupportsResp,
    key: str,
    key_type_: str,
    budget: ReadBudget,
) -> object:
    if key_type_ == "string":
        reply = await conn.execute("GET", key)
        return _cap(reply.text(), budget.scalar_cap)
    if key_type_ == "hash":
        reply = await conn.execute("HSCAN", key, "0", "COUNT", str(budget.hash_fields))
        payload = reply.value if isinstance(reply.value, list) else []
        flat = payload[1] if len(payload) == 2 else []
        fields = {
            str(flat[index]): _cap(str(flat[index + 1]), budget.scalar_cap)
            for index in range(0, min(len(flat), budget.hash_fields * 2) - 1, 2)
        }
        return fields
    if key_type_ == "list":
        reply = await conn.execute("LRANGE", key, "0", str(budget.list_items - 1))
        items = reply.value if isinstance(reply.value, list) else []
        return [_cap(str(item), budget.scalar_cap) for item in items[: budget.list_items]]
    if key_type_ == "set":
        reply = await conn.execute("SSCAN", key, "0", "COUNT", str(budget.set_items))
        payload = reply.value if isinstance(reply.value, list) else []
        flat = payload[1] if len(payload) == 2 else []
        return [_cap(str(item), budget.scalar_cap) for item in flat[: budget.set_items]]
    if key_type_ == "zset":
        reply = await conn.execute("ZRANGE", key, "0", str(budget.zset_items - 1), "WITHSCORES")
        items = reply.value if isinstance(reply.value, list) else []
        pairs: list[dict[str, object]] = []
        for index in range(0, min(len(items), budget.zset_items * 2) - 1, 2):
            pairs.append(
                {"member": _cap(str(items[index]), budget.scalar_cap), "score": items[index + 1]}
            )
        return pairs
    if key_type_ == "stream":
        length_reply = await conn.execute("XLEN", key)
        count = budget.stream_entries
        reply = await conn.execute("XRANGE", key, "-", "+", "COUNT", str(count))
        raw_entries = reply.value if isinstance(reply.value, list) else []
        entries: list[dict[str, object]] = []
        for entry in raw_entries[:count]:
            if isinstance(entry, list) and len(entry) == 2:
                entry_id, flat = str(entry[0]), entry[1]
                fields = {
                    str(flat[index]): str(flat[index + 1]) for index in range(0, len(flat) - 1, 2)
                }
                entries.append({"id": entry_id, "fields": fields})
        return {"length": length_reply.value, "entries": entries}
    if key_type_ == "none":
        return None
    return f"<unsupported type {key_type_}>"


async def build_record(
    conn: SupportsResp,
    key: str,
    budget: ReadBudget,
    db: str = "db0",
) -> Record | None:
    try:
        type_name = await key_type(conn, key)
    except RespError as exc:
        if "NOPERM" not in exc.message.upper():
            raise
        try:
            reply = await conn.execute("GET", key)
        except RespError:
            return None
        return Record(
            db=db,
            namespace=namespace_of(key),
            key=key,
            type="string",
            ttl_ms=None,
            value=_cap(reply.text(), budget.scalar_cap),
        )
    if type_name == "none":
        return None
    ttl = await pttl_ms(conn, key)
    value = await read_value(conn, key, type_name, budget)
    return Record(
        db=db,
        namespace=namespace_of(key),
        key=key,
        type=type_name,
        ttl_ms=ttl,
        value=value,
    )
