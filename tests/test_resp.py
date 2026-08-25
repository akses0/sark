from __future__ import annotations

import asyncio

import pytest

from sark.resp import (
    ProtocolError,
    RespConnection,
    RespError,
    Unreachable,
    encode_command,
    wire_preview,
)


class NullWriter:
    def __init__(self) -> None:
        self.closed = False
        self.buffer = b""

    def write(self, data: bytes) -> None:
        self.buffer += data

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


async def make_conn(payload: bytes) -> RespConnection:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return RespConnection(reader, NullWriter(), timeout=1.0)


def run_session(payload: bytes, action: object) -> object:
    async def go() -> object:
        conn = await make_conn(payload)
        try:
            result = await action(conn)
        finally:
            await conn.close()
        return result

    return asyncio.run(go())


async def execute_ping(conn: RespConnection) -> object:
    return await conn.execute("PING")


async def execute_gets(conn: RespConnection) -> tuple[object, object]:
    first = await conn.execute("GET", "a")
    second = await conn.execute("GET", "b")
    return first, second


async def execute_mget(conn: RespConnection) -> object:
    return await conn.execute("MGET", "a", "b")


async def execute_hello(conn: RespConnection) -> object:
    return await conn.execute("HELLO", "3")


async def execute_x(conn: RespConnection) -> object:
    return await conn.execute("X")


def test_encode_simple_command() -> None:
    assert encode_command("PING") == b"*1\r\n$4\r\nPING\r\n"


def test_encode_mixed_args() -> None:
    encoded = encode_command("SET", "k", b"\x00\xff")
    assert encoded == b"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\n\x00\xff\r\n"


def test_decode_simple_string() -> None:
    reply = run_session(b"+PONG\r\n", execute_ping)
    assert reply.prefix == "+"
    assert reply.value == "PONG"
    assert reply.raw_request == b"*1\r\n$4\r\nPING\r\n"
    assert reply.raw_response == b"+PONG\r\n"
    assert reply.size == 7


def test_decode_bulk_and_nil() -> None:
    first, second = run_session(b"$5\r\nhello\r\n$-1\r\n", execute_gets)
    assert first.value == "hello"
    assert second.value is None


def test_decode_array_of_bulks() -> None:
    reply = run_session(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n", execute_mget)
    assert reply.value == ["foo", "bar"]
    assert reply.prefix == "*"


def test_decode_map_resp3() -> None:
    payload = b"%2\r\n$6\r\nserver\r\n$5\r\nredis\r\n$5\r\nproto\r\n:3\r\n"
    reply = run_session(payload, execute_hello)
    assert reply.prefix == "%"
    assert reply.value == {"server": "redis", "proto": 3}


def test_error_reply_raises_with_raw_capture() -> None:
    payload = b"-NOAUTH Authentication required.\r\n"

    async def action(conn: RespConnection) -> object:
        await conn.execute("PING")

    with pytest.raises(RespError) as excinfo:
        run_session(payload, action)
    assert "NOAUTH" in str(excinfo.value)
    assert excinfo.value.raw == payload


def test_unsupported_type_prefix_is_protocol_error() -> None:
    async def action(conn: RespConnection) -> object:
        await conn.execute("X")

    with pytest.raises(ProtocolError):
        run_session(b"(12345\r\n", action)


def test_eof_maps_to_unreachable() -> None:
    with pytest.raises(Unreachable):
        run_session(b"", execute_ping)


def test_wire_preview_truncates_with_marker() -> None:
    raw = b"x" * 5000
    preview = wire_preview(raw)
    assert preview.startswith("x" * 240)
    assert "5000 bytes total" in preview
