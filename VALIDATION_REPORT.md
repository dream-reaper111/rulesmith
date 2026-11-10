# RuleSmith validation report

Date: 2026-11-09. Scope: new RuleSmith repository only. Test rules are isolated, nonfunctional fixtures and are never used as operational detections.

| Check | Actual result |
| --- | --- |
| `python3 -m compileall -q rulesmith tests` | Passed |
| `python3 -m unittest discover -s tests -v` | 7 passed, 0 failed, 0 skipped |
| Authenticated ASGI API unit test | Passed using local FastAPI/httpx |
| Local Uvicorn process | Startup log reported running; loopback HTTP smoke test could not connect from another command. A same-command socket attempt failed with `PermissionError: [Errno 1] Operation not permitted`. Network API smoke remains unverified. |
| `python3 -m venv .venv` and project install | Venv created; install failed because package-index DNS resolution could not obtain build dependency `setuptools>=68` |
| `python3 -m pytest -q` | Not run: module unavailable |
| `python3 -m ruff check .` | Not run: module unavailable |
| `docker compose config` | Failed before project validation: Snap Docker cannot create `/run/user/1000/snap.docker` in this read-only runtime |
| pySigma, YARA, Suricata compiler validation | Not run; tools unavailable/unconfigured |
| Database migration, dashboard build | Not applicable to stateless first milestone; neither is implemented |

One test failure was found and fixed during development: unsafe or duplicate-key YAML returned errors but retained `precheck_only` status. It now returns `invalid`. The first HTTP test hung with the installed sync TestClient and was stopped; making the stateless API routes async allowed an ASGI test to complete. No production detection engine or SIEM connection has been verified.

Next: restore package-index access, run Ruff and pytest in the project venv, smoke-test a locally started API, validate Compose on a functional Docker engine, then add reviewed versioned rule persistence and engine-backed validation.
