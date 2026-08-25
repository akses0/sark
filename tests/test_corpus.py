from __future__ import annotations

from sark.backends.redis import RedisBackend
from sark.models import SafetyTier

EXPECTED_IDS = {
    "RED-UNAUTH",
    "RED-AUTH-CREDS",
    "RED-TLS-RESP3",
    "RED-CENSUS",
    "RED-VALUE-READ",
    "RED-LUA-PROBE",
    "RED-ACL-ENUM",
    "RED-CVE-FP",
    "RED-CONFIG-AUDIT",
    "RED-CRLF-APP",
}


def test_redis_corpus_matches_spec_registry() -> None:
    vectors = RedisBackend().vectors()
    assert {spec.id for spec in vectors} == EXPECTED_IDS
    assert len({spec.id for spec in vectors}) == len(vectors)


def test_every_vector_has_valid_tier_and_channels() -> None:
    for spec in RedisBackend().vectors():
        assert spec.tier in SafetyTier
        assert len(spec.channels) >= 1
        assert spec.name


def test_only_crlf_canary_is_destructive() -> None:
    destructive = {
        spec.id for spec in RedisBackend().vectors() if spec.tier is SafetyTier.DESTRUCTIVE
    }
    assert destructive == {"RED-CRLF-APP"}
