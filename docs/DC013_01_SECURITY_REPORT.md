# DC-013 Security Scan Report

Date: 2026-11-27. Baseline device-control `c0c3923`.

## Dependency finding

`Pillow==12.3.0` was used by the control plane (server-side PNG re-decode) and
gateway (screenshot redaction). `pip-audit` reported **42 known vulnerabilities**
in that single package, with fix version `13.0.0` (PYSEC-2026-4326/4327/4328/
4334/4339/4340/4343 and others).

### Resolution

- Upgraded `Pillow` to `13.0.0` in:
  - `pyproject.toml`, `gateway/pyproject.toml` (`>=13,<14`);
  - `requirements/constraints.txt` (`==13.0.0`);
  - `requirements/audit.txt`.
- Did not skip, ignore or whitelist the advisory.
- Compatibility exercised:
  - image open/verify/re-encode/redact: `gateway/tests/test_redaction.py`;
  - server-side PNG decode/hash/proof: `tests/test_evidence.py`;
  - screenshot worker/evidence upload: `gateway/tests/test_worker_e2e.py`;
  - invalid/corrupt image fail-closed branches.

`pip-audit -r requirements/audit.txt` now: **No known vulnerabilities found**.

## Bandit suppression review

`bandit -c .bandit -r src gateway/src`: **0 issues**. The global config only
skips `B101`; all line-level suppressions are targeted:

| Location | Rule | Reason |
| --- | --- | --- |
| `store.py` dynamic SELECT/UPDATE builders (7 lines) | B608 | clauses are fixed strings and every value is bound; `IN` placeholders are generated only as `?` |
| `iot/telemetry` query | B608 | fixed clause strings + bound values |
| `android_adb.py` subprocess import/calls | B404/B603 | fixed `adb` path and argument arrays, `shell=False`, timeout, bounded output |
| `control_client.py` urlopen / HA adapter urlopen | B310 | URL scheme is validated to http(s) before the call |
| `iot/lifecycle.py` disable path | no suppression | exception is recorded in `last_error`, not silently swallowed |

No new `nosec` was added to bypass a finding. The remaining warnings are Bandit
reporting suppression comments that do not correspond to a currently emitted
finding (line-number drift); they do not suppress unrelated issues and are
reviewed in this report.

## Verification commands

```text
python -m pytest -q                                  126 passed
python -m ruff check src tests gateway/src gateway/tests scripts examples
python -m mypy src/device_control gateway/src/device_gateway --ignore-missing-imports --no-site-packages
python -m bandit -c .bandit -r src gateway/src
python -m pip_audit -r requirements/audit.txt
python scripts/export_openapi.py
```

Python 3.11/3.12 container builds are defined in CI. Docker was unavailable in
this environment, so the container job itself is **BLOCKED** here; local syntax,
tests, lint, types, Bandit and dependency audit pass.
