# SPEC: Project Sark — NoSQL Injection Testing CLI

Status: DRAFT v2 (Redis-first scope)
Date: 2026-08-25
License: AGPL-3.0-or-later
Purpose: This document is the authoritative specification for generating a CLI tool. Every section is written to be directly implementable. Where a decision is open, it is marked **[OPEN]**.

---

## 1. Purpose & Positioning

A single-binary-feeling CLI (`sark`) that detects, confirms, and safely demonstrates NoSQL misconfiguration and injection exposure. **v1 targets Redis only** — the one dominant NoSQL system for which no credible tooling has ever shipped (NoSQLMap promised it at inception and never delivered; current alternatives are single-digit-star toys). MongoDB and CouchDB are fully designed in this spec (§5 registries) and will be delivered as backend plugins post-v1 via the public ABI.

It fills the negative space left by NoSQLMap:

| Capability | NoSQLMap | Sark v1 |
|---|---|---|
| Injection surfaces | Form-encoded GET/POST params | Direct RESP service auditing now; nested-JSON/GraphQL surfaces return with the Mongo/Couch plugins |
| Inference methodology | Ad-hoc per-module checks | Unified oracle engine interface with confidence scoring (direct + error channels active in v1) |
| Redis | "Planned" since inception, never delivered | Unauth census, AUTH/ACL credential testing (Redis ≥6), TLS/RESP3, config audit, CVE fingerprinting, SCAN-based enumeration, capped dumps |
| MongoDB / CouchDB depth | Mongo+Couch focus | Designed vector registries below; delivered as plugins post-v1 |
| Output | Interactive stdout only | JSONL event stream + MD/HTML/SARIF reports, evidence capture |
| Automation | Menu wizard, weak flags | Four scriptable verbs, exit-code contract, CI-friendly, importable as a library |
| Safety | None explicit | Read-only default, risk-tiered escalation, destructive-op guardlist, scope enforcement, rate limiting |

## 2. Goals

1. Audit Redis direct-service exposure end to end: fingerprint → configuration/security assessment → credential testing → data-layer enumeration → capped extraction.
2. Enumerate and extract data via the least-noisy available channel.
3. Be safe by default: zero mutations to target state unless explicitly unlocked.
4. Produce evidence-grade output suitable for pentest reports (full command transcripts, timings, confidence).
5. Canonical UX: sqlmap-style flag conventions (`--risk`, `--dump-format`, `--start/--stop`) over a minimal four-verb structure; full HTTP-injection ergonomics return with the backend plugins.

## 3. Non-Goals (v1)

- **MongoDB and CouchDB backends** — designed in this spec as plugin backlog; not implemented in v1.
- **HTTP-mediated injection** — returns with those plugins (bracket/dot encoders, boolean oracle, request-file import all deferred with them).
- **Boolean/timing/OOB oracle channels** — interfaces defined (§6) but inactive: Redis has no native time sink and no credible OOB primitive. Do not fake either.
- **No wordlist brute-forcer — by design.** Sark detects misconfigurations related to default/common passwords and resolves the auth-state; it does not perform large-scale credential rotation. For proper brute forcing, go use these other great tools: `hydra`, `legba`, `nmap --script redis-brute`, or msf `auxiliary/scanner/redis/redis_login` — then resume the run with discovered credentials (the handoff hint names them).
- No exploitation/persistence modules (no module-load RCE, no CONFIG SET abuse — these are *detected* and reported as "primitive available", never executed).
- No GUI/TUI; plain CLI + files.

## 4. Target Model

```toml
# targets.toml
[[target]]
name = "cache-1"
service = { kind = "redis", host = "10.0.0.5", port = 6379, tls = false }
auth = "cache-creds"                            # key into auth profiles (optional)
scope = "prod-scope"                            # CIDR allowlist reference
```

- v1 targets are **direct services**, addressed as URIs: `-t redis://10.0.0.5:6379` or `--targets-file targets.toml` for batches.
- HTTP request templates (raw Burp/ZAP export, sqlmap-style `*` injection markers) return with the HTTP-mediated backend plugins; the parser is specified here so the format is stable:

```http
POST /api/login HTTP/1.1
Host: target.example.com
Content-Type: application/json

{"user": "*admin*", "pass": "*"}
```

## 5. Vector Registry

Every technique is a registered vector with stable ID, safety tier, required channel(s), and backend. The engine executes vectors; vectors are data, not code paths.

### 5.1 v1 core — Redis

| ID | Name | Tier | Channels |
|---|---|---|---|
| RED-UNAUTH | Unauthenticated access census (HELLO, COMMAND COUNT, DBSIZE sampling) | SAFE | direct |
| RED-AUTH-CREDS | Auth-state resolution: curated default/weak matrix, opt-in wordlist spray, `-WRONGPASS` vs `-NOPERM` discrimination (valid-but-restricted principal) | RISKY | direct |
| RED-TLS-RESP3 | TLS-required and RESP3 capability detection | SAFE | direct |
| RED-CENSUS | Multi-DB key-space census: `INFO keyspace` discovery + `SELECT n` iteration + incremental `SCAN` (never `KEYS *`) | RISKY | direct |
| RED-VALUE-READ | Type-aware GET/HGETALL/LRANGE/etc. sampling of sampled keys | RISKY | direct |
| RED-LUA-PROBE | EVAL availability + sandbox presence check (pure arithmetic canary), reported against Redis ≥7 hardening defaults | RISKY | direct |
| RED-ACL-ENUM | Principal capability surface: ACL WHOAMI / USERS / GETUSER (incl. Redis 7 selectors), ACL CAT @dangerous, renamed-command inference via COMMAND INFO, MODULE LIST / FUNCTION LIST (+ WITHCODE leak check) | SAFE | direct |
| RED-CONFIG-AUDIT | Post-auth configuration audit: protected-mode/bind exposure, RCE-primitive flags (`enable-module-command`, `enable-protected-configs`) reported as available/local-only/disabled | RISKY | direct |
| RED-CVE-FP | Version fingerprint mapped to advisory table — Lua engine family (CVE-2022-0543 Debian packaging; CVE-2025-49844/-46817/-46818; CVE-2026-23631 DarkReplica); advisories linked, never exploited | SAFE | direct |
| RED-CRLF-APP | CRLF injection into app-visible values to poison downstream consumers (detection payload w/ canary marker, single key write) | DESTRUCTIVE* | direct |

\* `RED-CRLF-APP` is the only seeded vector above SAFE that performs a write; requires `--risk=3`.

Vector notes:

- **Auth-state machine**: every run resolves exactly one of `{anonymous, authenticated-as-principal, valid-but-restricted}` before vector dispatch; downstream vectors adapt to the resolved principal. Credentials are never assumed — the resolved state is itself a finding.
- **Credential tiers**: curated default/weak matrix (~50 entries: empty password, `redis`, `foobared`, vendor defaults) runs at risk=2 by default — this is misconfiguration detection, not brute force. Wordlist spray is strictly opt-in (`--wordlist`, stop-on-first-hit). Large-scale rotation is deliberately not provided (§3): on exhaustion of the in-core matrix without success, sark emits a handoff event naming suitable bruteforcers (hydra, legba, nmap redis-brute) and accepts resumed runs with discovered credentials via the normal auth profile.
- **Primitive reporting vs Redis ≥7 hardening**: file-write knobs (`dir`/`dbfilename`), `MODULE LOAD`, and similar report state as `{available, local-only, disabled}` per protected-config defaults. "Primitive existed on old Redis" ≠ "exploitable here" — findings must state the version context.
- **Backlog (Redis-specific, HTTP-surface-dependent)**: `RED-SSRF-PROBE` — CRLF-smuggled RESP command injection via SSRF-able app endpoints (GitLab 11.4.7-style queue abuse). Lands with the HTTP injection surface alongside the backend plugins.

### 5.2 Plugin backlog — MongoDB (designed, not scheduled)

> Delivered post-v1 as a backend plugin consuming the public ABI. Registry frozen here so IDs and channel assignments stay stable.

| ID | Name | Tier | Channels |
|---|---|---|---|
| MON-AUTH-BYPASS-OPS | Login bypass via comparison operators (`$ne`,`$gt`,`$regex`) on JSON/bracket/dot encodings | SAFE | boolean |
| MON-FILTER-INJ | Data filter params accepting operators → result-set expansion | SAFE | boolean, error |
| MON-WHERE-JSI | `$where` JS evaluation probe (non-destructive arithmetic canary, no sleep loops) | RISKY | boolean, error, timing |
| MON-EXPR-INJ | `$expr`/aggregation operator injection in filter contexts | SAFE | boolean |
| MON-AGG-STAGE | Aggregation stage injection; `$lookup` cross-collection read proof (single record) | RISKY | boolean |
| MON-PROJECTION | Projection param injection (`?fields={"secret":1}`) | SAFE | boolean |
| MON-CAST-ORACLE | Mongoose/driver CastError taxonomy as error oracle | SAFE | error |
| MON-OID-PROBE | ObjectId format probing for IDOR adjacency | SAFE | boolean |
| MON-DIRECT-UNAUTH | Direct mongod/port exposure handshake + `isMaster`/`hello` fingerprint | SAFE | direct |
| MON-DIRECT-CREDS | Default/common cred auth test (SCRAM) | RISKY | direct |

### 5.3 Plugin backlog — CouchDB (designed, not scheduled)

| ID | Name | Tier | Channels |
|---|---|---|---|
| COUCH-ADMIN-PARTY | Admin party detection (`_config` readable, `ok:true` writes refused) | SAFE | direct |
| COUCH-DEF-CREDS | Default/vendor cred matrix against `_session` | RISKY | direct |
| COUCH-ALLDOCS-DUMP | `_all_docs` pagination dump of reachable DBs | SAFE | direct |
| COUCH-USERS-READ | `_users` DB readability (hash exposure) | SAFE | direct |
| COUCH-DESIGN-ENUM | Design doc + view enumeration (read-only) | SAFE | direct |
| COUCH-VIEW-JSI | Stored view/query-server JS injection *detection* via temporary throwaway doc (requires `--risk=3`) | DESTRUCTIVE* | boolean |
| COUCH-REPL-PRIMITIVE | Replication primitive availability check (config read only, no replication started) | SAFE | direct |
| COUCH-CORS | Permissive CORS audit on `_all_dbs` | SAFE | direct |
| COUCH-NODE-ENDPOINTS | `_node/_local/_cluster` info reachability | SAFE | direct |
| COUCH-CVE-FP | Version fingerprint mapped to advisory table (links only) | SAFE | direct |

Safety tiers surface to users as sqlmap-style risk levels: `--risk=1` → SAFE (read-only), `--risk=2` → RISKY (auth attempts, resource-heavy reads), `--risk=3` → DESTRUCTIVE-capable (state mutation via canaries — see §9).

## 6. Oracle Engine

All confirmation logic goes through one interface so channels compose and report uniformly.

**v1 status:** `direct` channel is native to every RED vector; ErrorOracle is active. Boolean/Timing/OOB are defined interfaces that emit explicit `UNSUPPORTED` events for Redis rather than pretending (see §3).

```
trait Oracle:
    probe(request_context) -> Observation
    calibrate(baseline_samples) -> ChannelHealth   # stability score; disables channel if unstable
    verdict(observations) -> Confirmed | Refuted | Inconclusive(confidence)
```

### 6.1 BooleanOracle *(interface defined; activates with HTTP-mediated plugins)*
- Sends true-condition and false-condition variants (e.g., `"user":{"$ne":"___none___"}` vs `"user":{"$regex":"^___nomatch___$"}`).
- Baseline clustering: n≥3 baseline responses; classify by status/body-hash/token-count/size deltas; ignore volatile fields (csrf nonces, timestamps) via configurable scrubbers.
- Requires consistent differential over 3 repetitions before CONFIRMED.

### 6.2 ErrorOracle *(active in v1)*
- Driver/framework error taxonomy table mapping observed signatures to meaning:
  - Mongoose `CastError`, `ValidationError`; pymongo-style server messages leaking through API; CouchDB `{"error":"bad_request",...}` shapes; **Redis `-ERR` / `-WRONGPASS` / `-NOAUTH` strings, both direct and app-proxied**.
- Errors are *signals*, not verdicts alone; escalate to boolean confirmation when possible.

### 6.3 TimingOracle *(interface defined; no Redis sink — reports UNSUPPORTED by design)*
- Adaptive baselining (rolling median/MAD), minimum Δ threshold defaulting to 4× MAD.
- MongoDB sink (deferred with plugin): bounded busy-loop inside `$where` (CPU-bounded, capped at 300ms, tier RISKY).
- Auto-disables under detected rate-limiting/jitter (health < 0.6).

### 6.4 OOBCallback *(deferred — returns when an OOB-capable backend ships)*
- Listener providing HTTP + DNS callbacks; primitives were specced per backend (Mongo `$where` fetch, CouchDB replicator availability). Where a backend has no credible OOB primitive, say so explicitly in output rather than pretending.

Verdict model: every finding carries `confidence ∈ [0,1]`, channel used, repetition count, and raw evidence. `Inconclusive` findings are always surfaced (never silently dropped).

## 7. Payload Grammar & Encoder Pipeline *(deferred with HTTP-mediated plugins)*

The full design (JSON/bracket-php/bracket-rails/dot-notation/urlencoded encoder pipeline, YAML corpus templating, GraphQL adapter plugin, round-trip property tests against qs/Rack/PHP reference parsers) is retained from DRAFT v1 for the MongoDB/CouchDB plugins. Redis v1 speaks RESP through the in-repo client (`resp.py`, decision #13) and needs none of it.

## 8. Enumeration & Exploitation (`enum` / `dump`)

Redis v1 strategy, ordered by noise:

1. `enum` — per logical DB (`INFO keyspace` discovery, then `SELECT n` iteration): incremental `SCAN` sampling (never `KEYS *`), top-level namespace prefixes with counts/types/approximate sizes; value sampling type-aware (`GET`/`HGETALL`/`LRANGE`/`SMEMBERS`/`ZRANGE`/`XLEN`, bounded preview per record).
2. `dump` — targeted extraction over a key pattern with sqlmap-style `--start/--stop` windows; full dump gated behind `--risk=2`; hard internal cap (default 1000 records) prevents accidental mass extraction, exceeding cap emits warning event.
3. Records stream to NDJSON: `{backend, namespace, key, type, ttl, value, source_vector}`.

MongoDB/CouchDB strategies (driver reads → oracle-driven binary search → anchored-prefix extraction) are retained from DRAFT v1 for the backend plugins.

## 9. Safety Model

- Default posture: `--risk=1` (SAFE-tier vectors only).
- Escalation: `--risk=2` enables RISKY vectors; `--risk=3` additionally unlocks DESTRUCTIVE canary vectors after printing the guardlist diff. One-time `--attest-authorized "text"` per profile (stored in config with timestamp) required before any run above risk 1; `--batch` auto-answers confirmations with safe defaults except DESTRUCTIVE prompts, which always need explicit affirmation or pre-set attest.
- Guardlist (hard-blocked even with flags, override needs `--override-guard` + reason): `FLUSHALL`, `FLUSHDB`, `CONFIG SET`, `MODULE LOAD`, `SLAVEOF`/`REPLICAOF`, `SHUTDOWN`, mongo `dropDatabase`/`drop`/`insert` outside canary, Couch `_compact`, `_view_cleanup`, real replication triggers, design-doc PUT/DELETE.
- Rate limiter: token bucket, global `--rps` default 10; per-target jitter; automatic cool-down on 429/backoff signals.
- Scope enforcement: targets must match allowlisted CIDRs/domains; violations abort run (exit 78).
- Canary discipline: any permitted write uses unique canary tokens (`sark_<run_id>_<n>`) and best-effort cleanup attempt + explicit "cleanup attempted/failed" reporting.

## 10. CLI Contract

Four verbs, one per operator question; `--help` presents them as a workflow. Flag conventions follow **sqlmap** where a concept survives the direct-service scope (`--risk`, `--start/--stop`, `--dump-format`); HTTP-injection flags return with the backend plugins.

```
# Is it reachable, and is it exposed?
sark scan -t redis://10.0.0.5:6379                    # risk=1 default: fingerprint, unauth census, TLS/RESP3, ACL surface, CVE fp
sark scan -t redis://10.0.0.5:6379 --risk=2           # + credential testing, config audit, EVAL probe
sark scan -t redis://10.0.0.5:6379 --risk=3           # + RED-CRLF-APP canary write (attestation required)

# What data lives here?
sark enum -t redis://10.0.0.5:6379 --sample 50        # namespace summary: prefixes, types, counts
sark enum -t redis://10.0.0.5:6379 --pattern 'session:*'

# Give me the records.
sark dump -t redis://10.0.0.5:6379 --pattern 'session:*' --stop 1000
sark dump -t redis://10.0.0.5:6379 --all --dump-format=csv --out loot/

# Render evidence.
sark report --events run.jsonl --format md|html|sarif --out report/
```

Verbs:
- `scan` — fingerprint + vector execution up to the selected risk; absorbs probing, configuration audit, and credential testing (`--wordlist users.txt:passes.txt`)
- `enum` — keyspace mapping: namespaces, types, counts, sampled previews
- `dump` — targeted extraction with caps and scoping (§8)
- `report` — render events; a pure function of JSONL input

Common flags: `-t/--target URI` (repeatable) or `--targets-file targets.toml` (§4) · `--user/--pass` or named cred profile · `--wordlist` · `--risk=1..3` · `--pattern GLOB` · `--timeout` · `--retries` · `--delay` · `--threads` · `--proxy` · `--tls-ca` · `--output jsonl` · `--session-file`/`--flush-session` · `--batch`.

Behavioral notes:
- Unsupported flag/backend combinations emit explicit `UNSUPPORTED` events — never silently ignored.
- Exit codes: `0` clean · `1` usage · `2` findings · `3` inconclusive-only · `70` internal · `78` scope violation.
- `--dbms=` reserved for multi-backend future; v1 accepts only `redis`.
- Batch runs honor scope allowlists and rate limits globally across targets.

## 11. Event & Evidence Schema

One JSONL line per observation:

```json
{
  "ts": "2026-08-25T14:03:11Z",
  "run_id": "a1b2c3",
  "target": "cache-1",
  "vector": "RED-UNAUTH",
  "channel": "direct",
  "verdict": "confirmed",
  "confidence": 1.0,
  "repetitions": 1,
  "evidence": {
    "commands": [{"wire_ref": "./evidence/0007.cmd"}],
    "responses": [{"prefix": "+", "size": 48213, "sha256": "...", "body_ref": "./evidence/0007.resp"}],
    "timing_ms": [212.1]
  }
}
```

Responses over 64KB stored as file refs. HTTP request/response evidence shapes return with the backend plugins. Advisory events that are not findings (e.g., brute-force handoff hints per §3) use `"verdict": "advisory"` with confidence omitted. Reports (MD/HTML/SARIF) render from this stream only — reports are pure functions of events.

## 12. Architecture

```
sark/
├── cli.py               # verb dispatch: scan, enum, dump, report (typer)
├── models.py            # pydantic: Event, Verdict, Channel, SafetyTier, AuthState
├── targets.py           # redis:// · rediss:// URI parsing
├── resp.py              # in-repo async RESP client w/ wire-transcript capture
├── registry.py          # YAML vector corpus loader (pydantic-validated)
├── engine/
│   ├── scheduler.py     # ScanContext, token-bucket rate limiter, job runner
│   ├── oracles/         # direct.py error.py (active) · boolean.py timing.py oob.py (interfaces, inactive)
│   └── plugins.py       # entry-point loader for sark.backends
├── backends/
│   ├── base.py          # Backend plugin ABC: vectors()
│   ├── redis.py         # built-in backend: registry + job assembly
│   ├── redis_vectors.py # SAFE-tier executors + auth-state resolution
│   └── redis_cves.py    # Lua CVE family advisory table + branch-aware evaluation
├── corpus/redis/vectors.yaml
├── report/{md.py html.py sarif.py}
└── safety/guardlist.py scope.py ratelimit.py
```

- Plugin ABI (core, from M0): plugins register via Python entry points (`sark.backends`, `sark.points`) and implement `Backend` (fingerprint, vector registry contribution, client factory, extraction strategy). The built-in Redis backend consumes the same ABI — no private core shortcuts. MongoDB ships as the first backend plugin; GraphQL adapter and Elasticsearch/Cassandra follow.
- Stack: Python ≥3.12, asyncio, pydantic v2, typer, rich, PyYAML. The RESP protocol client is **in-repo** (`resp.py`), not redis-py: transcript-perfect wire capture is an evidence pillar (§11) and app-oriented driver clients abstract the wire away. httpx/pymongo join only when their backends do. Minimal dependency philosophy — no framework beyond these.
- **Typing discipline (invariant)**: `mypy --strict` must stay green from M0 onward — it is an acceptance criterion of every milestone, not a cleanup task. Boundary rule: no bare `dict`/`Any` crosses a module or process boundary; targets, events, vector payloads, configs, and corpus entries all flow through pydantic v2 models (runtime-validated at load). Type safety is enforced at CI instead of compile time — same guarantee, one step later.
- Packaging: pip-installable, `pyproject.toml`, console script `sark`. Users install via `pipx install sark` or `uv tool install sark` from PyPI — both documented as first-class paths in the README. Packed binaries (PyInstaller et al.) are excluded by policy: EDR false-positive reputation makes them counterproductive for offensive tooling, and our audience definitionally has Python.

## 13. Test Strategy

- `tests/harness/docker-compose.yml`: redis:7-alpine in three variants — hardened (requirepass+ACL+renamed commands), weak-defaults, and fully exposed — plus a small vulnerable demo app for RED-CRLF-APP canary detection.
- Golden-file tests: each RED vector MUST be CONFIRMED on the matching variant and REFUTED/inconclusive-with-low-confidence on hardened.
- Unit tests: SCAN census math against seeded keyspaces, guardlist interception (attempt FLUSHALL → blocked + audited), RESP wire transcript capture.
- Lint/type gates: ruff + mypy strict in CI.

## 14. Milestones & Acceptance

| Milestone | Deliverable | Done when |
|---|---|---|
| M0 Skeleton | repo, models, 4 verbs stubbed, event schema, plugin loader, Makefile (`check`/`test`/`harness`/`e2e`), lean README | `sark --help` shows the workflow with examples; JSONL emitted; plugin ABI loadable; `make check` green (ruff + `mypy --strict`) |
| M1 Scan-SAFE | fingerprint, RED-UNAUTH/TLS-RESP3/ACL-ENUM/CVE-FP | golden tests green on harness variants |
| M2 Audit-RISKY | RED-AUTH-CREDS, config audit, RED-LUA-PROBE, CENSUS | risk=2 run completes ≤5min on harness |
| M3 Data | `enum` + `dump` with caps, scoping, evidence refs | capped NDJSON dumps verified against seeded keyspace |
| M4 Reports | md/html/sarif renderers | report renders from arbitrary event streams |
| M5 Canary | RED-CRLF-APP at risk=3 incl. cleanup reporting | write + best-effort cleanup audited end-to-end |

## 15. Decisions & Open Questions

Resolved:

1. **[RESOLVED]** Tool name: `sark` (user-selected; Tron-themed project naming convention).
2. **[RESOLVED]** License: AGPL-3.0-or-later.
3. **[RESOLVED]** Platform: Linux-only at this stage. No Windows/WSL support work; do not spend effort on proactor/event-loop portability.
4. **[RESOLVED]** Plugin architecture is core from day one (M0); the built-in backend consumes the public ABI with no private shortcuts.
5. **[RESOLVED]** Scope hammer: v1 is Redis-only. MongoDB/CouchDB registries retained as designed plugin backlog. Rationale: Redis is the un-delivered negative space of every prior tool; current Redis tools have negligible traction.
6. **[RESOLVED]** Minimal verb set: `scan` / `enum` / `dump` / `report`. Credential testing folds into `scan`; OOB listener deferred until an OOB-capable backend exists.
7. **[RESOLVED]** UX conventions: sqlmap-style flags where concepts survive (`--risk`, `--start/--stop`, `--dump-format`); nosqli's raw-request import returns with the HTTP-mediated plugins.
8. **[RESOLVED]** Credential philosophy: sark never assumes credentials — auth state is resolved per run and is itself a finding. Curated default/weak matrix in-core (misconfiguration detection); opt-in light spray; heavy rotation delegated to hydra/legba with handoff hints.
9. **[RESOLVED]** Language: **Python ≥3.12**, strict semantics (`mypy --strict` per-milestone, pydantic-enforced boundaries — see §12). Rationale: the only mainstream language clearing all four pillars (dynamic plugin ABI via entry points, wire-transcript-capable RESP client, typed discipline, zero-friction Kali/pipx distribution) while maximizing ecosystem leverage per token. Rejected alternatives: TypeScript/Deno (plugin installs inherit npm supply-chain posture — bad optics for offensive tooling), Kotlin/JVM (ServiceLoader viable, distribution weight kills it), C# (no reflection under NativeAOT breaks plugins; audience friction), Rust/Go (no mature dynamic plugin mechanism; borrow-checker/verbosity tax on iteration).
10. **[RESOLVED]** Documentation & delivery policy: lean README only — install (`pipx` / `uv tool`) plus a copy-paste quickstart; usage reference lives in a wiki. No packed binaries. All dev gates exposed as Makefile targets (`make check`, `test`, `harness`, `e2e`) — the Makefile is the canonical task surface for humans, agents, and CI alike.
11. **[RESOLVED]** CLI help quality bar: terse one-line verb descriptions; plain language, no jargon walls; every verb ships at least two examples drawn from the most common use cases (`scan` unauth check, `scan --risk=2` audit, `dump --pattern ... --stop 1000`, `report` render); flags documented by analogy where conventions are shared (sqlmap-style).
12. **[RESOLVED]** CI: GitHub Actions as a *dumb runner* — checkout + Python setup + `make` invocation, nothing else (no reusable workflows, no marketplace sprawl). Free for public repos, native Docker services for the e2e harness, OIDC trusted publishing when PyPI release day comes. Provider lock-in avoided because all gates live behind Makefile targets; migrating providers later is a ~20-line rewrite.
13. **[RESOLVED]** RESP transport is hand-rolled in-repo (`src/sark/resp.py`) instead of redis-py. Rationale: evidence-grade wire transcripts (§11) require capturing exact request/reply bytes, which driver clients erase by design; the protocol is small enough that a typed async client (~200 lines) carries less risk than the dependency. redis-py remains listed as a future option only if dump-scale features demand it.
14. **[RESOLVED]** Registry amendment (M2): added `RED-CONFIG-AUDIT` (RISKY, direct) — the M2 milestone's "config audit" had no vector ID; added rather than overloading RED-AUTH-CREDS. Config-audit is read-only in action but tiered RISKY because it is post-auth heavy-read recon. AUTH-CREDS wire evidence is always masked (`***`) — a security tool must never write discovered credentials into its own evidence store. Restricted-principal detection discriminates via a benign `CONFIG GET protected-mode` NOPERM probe after successful AUTH + PING (PING alone is insufficient: restricted users commonly hold `+ping`).
15. **[RESOLVED]** Data-verb output contract (M3): `enum`/`dump` stream Records (pydantic `Record`: backend/db/namespace/key/type/ttl_ms/value/source_vector) as NDJSON to stdout or `--out`; events go to **stderr**, keeping stdout a pure, pipeable record stream (`scan` remains events-on-stdout). Exit: 2 = records emitted, 3 = auth-barred, 0 = empty keyspace. Nuances: (a) per-key degradation — restricted principals lacking `+type` fall back to a GET-based string probe; keys unreadable to the principal are skipped, never fatal; (b) data verbs default `--rps 100` vs scan's 10 — per-key command fan-out (SCAN+TYPE+PTTL+read ≈ 4 commands/key) makes 10 rps impractical for extraction; (c) no RESP pipelining yet — a future optimization milestone for large dumps; (d) click/typer convention exits **2** on usage errors, numerically colliding with findings=2 — scripts distinguish via stream content (usage errors print nothing to stdout).

Open:

- None currently.

## Appendix A — Legal/Safety Notice

Offensive tooling under AGPL-3.0-or-later. Distribution must include authorization-attestation requirement, responsible-use documentation, and a clear statement that destructive capabilities are intentionally absent or guarded. Maintainer should define a coordinated-disclosure policy for vulnerabilities found in the tool itself.
