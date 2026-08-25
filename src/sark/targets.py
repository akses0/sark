from __future__ import annotations

from urllib.parse import urlparse

from pydantic import BaseModel, Field


class Target(BaseModel):
    host: str = Field(min_length=1)
    port: int = Field(default=6379, ge=1, le=65535)
    tls: bool = False

    @classmethod
    def from_uri(cls, uri: str) -> Target:
        normalized = uri if "://" in uri else f"redis://{uri}"
        parsed = urlparse(normalized)
        if parsed.scheme == "rediss":
            tls = True
        elif parsed.scheme == "redis":
            tls = False
        else:
            raise ValueError(
                f"unsupported scheme {parsed.scheme!r}: expected redis:// or rediss://"
            )
        if parsed.username or parsed.password:
            raise ValueError("credentials in target URIs are not supported; use --user/--pass")
        host = parsed.hostname
        if not host:
            raise ValueError("target URI requires a host")
        return cls(host=host, port=parsed.port or 6379, tls=tls)

    def uri(self) -> str:
        scheme = "rediss" if self.tls else "redis"
        return f"{scheme}://{self.host}:{self.port}"
