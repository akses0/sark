# sark

Redis exposure auditing CLI — finds misconfigurations, resolves auth state, enumerates and extracts data safely. Detects default/common passwords; deliberately not a brute-forcer.

## Install

```sh
pipx install sark
```

or

```sh
uv tool install sark
```

## Quickstart

```sh
sark scan -t redis://10.0.0.5:6379              # unauth census, TLS/RESP3, ACL surface, CVE fp
sark scan -t rediss://cache.internal --risk=2   # + credential matrix, config audit, EVAL probe
sark enum -t redis://10.0.0.5:6379 --sample 50  # namespace map: prefixes, types, counts
sark dump -t redis://10.0.0.5:6379 --pattern 'session:*' --stop 1000
sark report --events run.jsonl                  # render findings from the JSONL event stream
```

Usage reference, safety model and vector registry live in the [wiki](https://github.com/akses/sark/wiki).

- Design specification: [`SPEC.md`](SPEC.md)
- License: AGPL-3.0-or-later
- Status: pre-alpha (M0 skeleton)
