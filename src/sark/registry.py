from __future__ import annotations

from importlib import resources

import yaml
from pydantic import BaseModel, Field

from sark.models import Channel, SafetyTier


class VectorSpec(BaseModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9]+(-[A-Z0-9]+)*$")
    name: str = Field(min_length=1)
    tier: SafetyTier
    channels: list[Channel] = Field(min_length=1)
    backend: str = Field(min_length=1)


def load_vectors(backend: str) -> list[VectorSpec]:
    resource = resources.files("sark.corpus").joinpath(backend, "vectors.yaml")
    raw = yaml.safe_load(resource.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("vectors"), list):
        raise ValueError(f"corpus {backend!r} must define a top-level 'vectors' list")
    specs = [VectorSpec.model_validate({**item, "backend": backend}) for item in raw["vectors"]]
    ids = [spec.id for spec in specs]
    duplicates = sorted({vid for vid in ids if ids.count(vid) > 1})
    if duplicates:
        raise ValueError(f"duplicate vector ids in {backend!r} corpus: {duplicates}")
    return specs
