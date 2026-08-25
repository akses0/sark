from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Protocol

CRLF = b"\r\n"

Token = str | bytes


class RespError(Exception):
    def __init__(self, message: str, raw: bytes) -> None:
        super().__init__(message)
        self.message = message
        self.raw = raw


class Unreachable(Exception):
    pass


class ProtocolError(Exception):
    pass


@dataclass(frozen=True)
class Reply:
    prefix: str
    value: object
    raw_request: bytes
    raw_response: bytes

    @property
    def size(self) -> int:
        return len(self.raw_response)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.raw_response).hexdigest()

    def text(self) -> str:
        if isinstance(self.value, str):
            return self.value
        raise TypeError(f"reply is {type(self.value).__name__}, not str")


def encode_command(*args: Token) -> bytes:
    parts = [b"*" + str(len(args)).encode() + CRLF]
    for arg in args:
        blob = arg.encode() if isinstance(arg, str) else arg
        parts.append(b"$" + str(len(blob)).encode() + CRLF + blob + CRLF)
    return b"".join(parts)


class SupportsResp(Protocol):
    def execute(self, *args: str | bytes) -> Awaitable[Reply]: ...


@dataclass(frozen=True)
class AuthOutcome:
    username: str | None
    password: str
    restricted: bool


class RespConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        timeout: float,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._timeout = timeout

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        *,
        tls: bool = False,
        insecure: bool = False,
        ca_file: str | None = None,
        timeout: float = 5.0,
    ) -> RespConnection:
        ssl_context: ssl.SSLContext | None = None
        if tls:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if insecure:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
            elif ca_file:
                ssl_context.load_verify_locations(ca_file)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_context),
                timeout,
            )
        except (TimeoutError, OSError, ssl.SSLError) as exc:
            raise Unreachable(str(exc)) from exc
        return cls(reader, writer, timeout)

    async def execute(self, *args: Token) -> Reply:
        wire = encode_command(*args)
        try:
            self._writer.write(wire)
            await asyncio.wait_for(self._writer.drain(), self._timeout)
            value, chunks = await self._read_reply()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError) as exc:
            raise Unreachable(str(exc)) from exc
        except TimeoutError as exc:
            raise Unreachable(f"timed out after {self._timeout}s") from exc
        return Reply(
            prefix=chr(chunks[0][0]) if chunks else "-",
            value=value,
            raw_request=wire,
            raw_response=b"".join(chunks),
        )

    async def _read_line(self) -> bytes:
        return await asyncio.wait_for(self._reader.readuntil(CRLF), self._timeout)

    async def _read_exact(self, size: int) -> bytes:
        return await asyncio.wait_for(self._reader.readexactly(size), self._timeout)

    async def _read_reply(self) -> tuple[object, list[bytes]]:
        head = await self._read_line()
        prefix = head[0:1]
        body = head[1:-2]
        chunks = [head]
        if prefix == b"+":
            return body.decode("utf-8", errors="replace"), chunks
        if prefix == b"-":
            raise RespError(body.decode("utf-8", errors="replace"), b"".join(chunks))
        if prefix == b":":
            return int(body), chunks
        if prefix in (b"$", b"="):
            size = int(body)
            if size == -1:
                return None, chunks
            payload = await self._read_exact(size + 2)
            chunks.append(payload)
            return payload[:-2].decode("utf-8", errors="replace"), chunks
        if prefix == b"_":
            return None, chunks
        if prefix in (b"*", b"~", b">"):
            count = int(body)
            items: list[object] = []
            for _ in range(count):
                item, sub_chunks = await self._read_reply()
                chunks.extend(sub_chunks)
                items.append(item)
            return items, chunks
        if prefix == b"%":
            count = int(body)
            items_map: dict[str, object] = {}
            for _ in range(count):
                key, sub_chunks = await self._read_reply()
                val, more_chunks = await self._read_reply()
                chunks.extend(sub_chunks)
                chunks.extend(more_chunks)
                items_map[str(key)] = val
            return items_map, chunks
        raise ProtocolError(f"unsupported RESP type prefix {prefix!r}")

    async def close(self) -> None:
        self._writer.close()
        with contextlib.suppress(TimeoutError, OSError):
            await asyncio.wait_for(self._writer.wait_closed(), self._timeout)


def wire_preview(raw: bytes, limit: int = 240) -> str:
    text = raw.decode("utf-8", errors="replace")
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[{len(raw)} bytes total]"


__all__ = [
    "CRLF",
    "AuthOutcome",
    "ProtocolError",
    "Reply",
    "RespConnection",
    "RespError",
    "SupportsResp",
    "Unreachable",
    "encode_command",
    "wire_preview",
]
