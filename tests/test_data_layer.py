from __future__ import annotations

import asyncio

from sark.data_layer import (
    PREVIEW_BUDGET,
    build_record,
    collect_keys,
    namespace_of,
    parse_databases,
    read_value,
)
from sark.models import Record
from sark.resp import Reply


class FakeConn:
    def __init__(self, script: dict[str, object]) -> None:
        self.script = script
        self.calls: list[tuple[object, ...]] = []

    async def execute(self, *args: str | bytes) -> Reply:
        self.calls.append(args)
        if str(args[0]).upper() == "SCAN":
            pages = self.script["scan"]
            index = len([c for c in self.calls if str(c[0]).upper() == "SCAN"]) - 1
            page = pages[min(index, len(pages) - 1)]
            cursor, keys = page
            return Reply("*", [cursor, list(keys)], b"", b"")
        result = self.script.get(str(args[1]) if len(args) > 1 else str(args[0]))
        if isinstance(result, BaseException):
            raise result
        return Reply("$", result, b"", b"")


def run(coro: object) -> object:
    return asyncio.run(coro)  # type: ignore[arg-type]


def test_namespace_extraction() -> None:
    assert namespace_of("session:abc") == "session"
    assert namespace_of("app:config:deep") == "app"
    assert namespace_of("barekey") == "(root)"


def test_parse_databases_from_info() -> None:
    text = "# Keyspace\r\ndb0:keys=42,expires=1\r\ndb3:keys=7\r\n"
    assert parse_databases(text) == {"db0": 42, "db3": 7}


def test_collect_keys_walks_cursor_pages() -> None:
    conn = FakeConn(
        {
            "scan": [
                ("17", ["a:1", "a:2"]),
                ("0", ["b:1"]),
            ]
        }
    )
    keys, truncated = run(collect_keys(conn, "*"))
    assert keys == ["a:1", "a:2", "b:1"]
    assert truncated is False


def test_collect_keys_caps_and_flags_truncation() -> None:
    conn = FakeConn({"scan": [("17", [f"k{i}" for i in range(50)])]})
    keys, truncated = run(collect_keys(conn, "*", max_keys=10))
    assert len(keys) == 10
    assert truncated is True


def test_collect_keys_deduplicates() -> None:
    conn = FakeConn(
        {
            "scan": [
                ("5", ["a", "b"]),
                ("0", ["b", "c"]),
            ]
        }
    )
    keys, _ = run(collect_keys(conn, "*"))
    assert keys == ["a", "b", "c"]


def test_read_value_dispatch_by_type() -> None:
    conn = FakeConn(
        {
            "strkey": "hello world this is a fairly long value for capping",
            "listkey": ["a", "b", "c", "d"],
        }
    )
    conn.script["strkey"] = "short"
    value = run(read_value(conn, "strkey", "string", PREVIEW_BUDGET))
    assert value == "short"

    list_reply = Reply("*", ["a", "b", "c", "d"], b"", b"")

    class ListConn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            if str(args[0]).upper() == "LRANGE":
                return list_reply
            return await super().execute(*args)

    conn2 = ListConn({})
    value2 = run(read_value(conn2, "listkey", "list", PREVIEW_BUDGET))
    assert value2 == ["a", "b", "c"]


def test_read_value_caps_long_strings() -> None:
    long_text = "x" * 500

    class StringConn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply("$", long_text, b"", b"")

    value = run(read_value(StringConn({}), "k", "string", PREVIEW_BUDGET))
    assert isinstance(value, str)
    assert value.startswith("x" * 200)
    assert "500 chars" in value


def test_read_value_unsupported_type_marker() -> None:
    value = run(read_value(FakeConn({}), "k", "module-type-custom", PREVIEW_BUDGET))
    assert str(value).startswith("<unsupported type")


def test_build_record_assembles_fields() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            head = str(args[0]).upper()
            if head == "TYPE":
                return Reply("+", "string", b"", b"+string\r\n")
            if head == "PTTL":
                return Reply(":", -1, b"", b":-1\r\n")
            if head == "GET":
                return Reply("$", "v", b"", b"$1\r\nv\r\n")

    record = run(build_record(Conn({}), "sark:test:key", PREVIEW_BUDGET, db="db0"))
    assert isinstance(record, Record)
    assert record.namespace == "sark"
    assert record.type == "string"
    assert record.ttl_ms == -1
    assert record.value == "v"
    assert record.source_vector == "RED-VALUE-READ"


def test_build_record_skips_vanished_keys() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply("+", "none", b"", b"+none\r\n")

    assert run(build_record(Conn({}), "gone", PREVIEW_BUDGET)) is None
