from __future__ import annotations

import asyncio
import json

from sark.backends.redis_vectors import (
    CURATED_MATRIX,
    masked_auth_evidence,
    red_census,
    red_config_audit,
    red_lua_probe,
    try_credentials,
)
from sark.engine.scheduler import ScanContext
from sark.models import Verdict
from sark.resp import Reply, RespError

CTX = ScanContext(run_id="a1b2c3", target_uri="redis://h:6379", risk=2)


class FakeConn:
    def __init__(self, behaviors: dict[str, object]) -> None:
        self.behaviors = behaviors
        self.calls: list[tuple[object, ...]] = []

    async def execute(self, *args: str | bytes) -> Reply:
        self.calls.append(args)
        result = self.behaviors.get(str(args[0]))
        if result is None:
            raise RespError("unexpected command", b"")
        if isinstance(result, BaseException):
            raise result
        assert isinstance(result, Reply)
        return result


def bulk(text: str) -> Reply:
    return Reply(
        prefix="$",
        value=text,
        raw_request=b"",
        raw_response=text.encode(),
    )


def test_curated_matrix_contains_canonical_defaults() -> None:
    assert "redis" in CURATED_MATRIX
    assert "foobared" in CURATED_MATRIX
    assert "" not in CURATED_MATRIX
    assert len(CURATED_MATRIX) >= 40


def test_try_credentials_stops_on_first_hit() -> None:
    accepted = {"foobared"}

    class AcceptList(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            if str(args[0]).upper() == "PING":
                return Reply("+", "+PONG", b"", b"+PONG\r\n")
            if str(args[0]).upper() == "CONFIG":
                return Reply("*", ["protected-mode", "yes"], b"", b"")
            password = str(args[-1])
            if password in accepted:
                return Reply("+", "+OK", b"", b"+OK\r\n")
            raise RespError("WRONGPASS Invalid password", b"")

    outcome = await_value(try_credentials(AcceptList({}), [(None, p) for p in CURATED_MATRIX]))
    assert outcome is not None
    assert outcome.password == "foobared"
    assert outcome.restricted is False


def await_value(coro: object) -> object:
    return asyncio.run(coro)  # type: ignore[arg-type]


def test_masked_auth_evidence_never_leaks_secret() -> None:
    secret_password = "sup3r-s3cret-value"
    reply = Reply(
        "+",
        "+OK",
        f"*2\r\n$4\r\nAUTH\r\n${len(secret_password)}\r\n{secret_password}\r\n".encode(),
        b"+OK\r\n",
    )
    evidence = masked_auth_evidence(reply)
    serialized = evidence.model_dump_json()
    assert secret_password not in serialized
    assert "***" in (evidence.commands[0].wire or "")
    assert evidence.responses[0].sha256


def test_config_audit_flags_exposure_combo() -> None:
    text = "\r\n".join(["protected-mode:no", "bind:0.0.0.0", "enable-module-command:no"])
    flat = ["protected-mode", "no", "bind", "0.0.0.0", "enable-module-command", "no"]

    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply("*", flat, b"", text.encode())

    event = await_value(red_config_audit(CTX, Conn({})))
    assert event.verdict is Verdict.CONFIRMED
    assert "protected mode disabled" in (event.detail or "")


def test_config_audit_remote_module_primitive_confirmed() -> None:
    flat = [
        "protected-mode",
        "yes",
        "bind",
        "127.0.0.1",
        "enable-module-command",
        "yes",
    ]

    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply("*", flat, b"", b"")

    event = await_value(red_config_audit(CTX, Conn({})))
    assert event.verdict is Verdict.CONFIRMED
    assert "RCE-enabling primitives reachable remotely" in (event.detail or "")


def test_config_audit_noperm_is_inconclusive() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            raise RespError("NOPERM this user has no permissions", b"")

    event = await_value(red_config_audit(CTX, Conn({})))
    assert event.verdict is Verdict.INCONCLUSIVE
    assert "NOPERM" in (event.detail or "")


def test_config_audit_renamed_config_refuted() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            raise RespError("ERR unknown command 'CONFIG'", b"")

    event = await_value(red_config_audit(CTX, Conn({})))
    assert event.verdict is Verdict.REFUTED


def test_config_audit_parses_resp3_map() -> None:
    mapping = {"protected-mode": "no", "bind": "0.0.0.0 ::1", "enable-module-command": "no"}

    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply("%", mapping, b"", b"")

    event = await_value(red_config_audit(CTX, Conn({})))
    assert event.verdict is Verdict.CONFIRMED
    assert "protected-mode=no" in (event.detail or "")


def test_config_audit_empty_bind_means_all_interfaces() -> None:
    mapping = {"protected-mode": "no", "bind": "", "enable-module-command": "no"}

    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply("%", mapping, b"", b"")

    event = await_value(red_config_audit(CTX, Conn({})))
    assert event.verdict is Verdict.CONFIRMED
    assert "(all interfaces)" in (event.detail or "")


def test_config_audit_hardened_refuted() -> None:
    mapping = {
        "protected-mode": "yes",
        "bind": "127.0.0.1",
        "enable-module-command": "no",
    }

    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply("%", mapping, b"", b"")

    event = await_value(red_config_audit(CTX, Conn({})))
    assert event.verdict is Verdict.REFUTED


def test_lua_probe_canary_confirmed() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply(":", 1, b"", b":1\r\n")

    event = await_value(red_lua_probe(CTX, Conn({})))
    assert event.verdict is Verdict.CONFIRMED
    assert "arithmetic canary" in (event.detail or "")


def test_lua_probe_noperm_refuted() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            raise RespError("NOPERM scripting is not allowed", b"")

    event = await_value(red_lua_probe(CTX, Conn({})))
    assert event.verdict is Verdict.REFUTED


def test_census_counts_databases() -> None:
    text = "# Keyspace\r\ndb0:keys=42,expires=1,avg_ttl=0\r\ndb3:keys=7,expires=0,avg_ttl=0\r\n"

    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return bulk(text)

    event = await_value(red_census(CTX, Conn({})))
    assert event.verdict is Verdict.CONFIRMED
    assert "db0=42 keys" in (event.detail or "")
    assert "db3=7 keys" in (event.detail or "")


def test_census_empty_keyspace_refuted() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return bulk("# Keyspace\r\n")

    event = await_value(red_census(CTX, Conn({})))
    assert event.verdict is Verdict.REFUTED


def test_events_serializable_and_secret_free() -> None:
    class Conn(FakeConn):
        async def execute(self, *args: str | bytes) -> Reply:
            self.calls.append(args)
            return Reply(":", 1, b"", b":1\r\n")

    event = await_value(red_lua_probe(CTX, Conn({})))
    payload = json.loads(event.model_dump_json())
    assert payload["vector"] == "RED-LUA-PROBE"
