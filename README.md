# RuleSmith

RuleSmith is an offline-first, non-deploying detection-rule review tool. Its first milestone scans an explicitly selected local rule directory, checks a safe structural subset of Sigma YAML, performs limited YARA and Suricata text prechecks, identifies duplicate content and Sigma IDs, and exposes an authenticated stateless lint API. It does not load rules into a SIEM, execute YARA against files, run Suricata, or publish detections.

## Current feature status

| Capability | Status |
| --- | --- |
| Bounded offline directory scan and duplicate reporting | Unit tested |
| Sigma YAML structure, alias and duplicate-key rejection | Unit tested; full Sigma semantic validation unverified |
| Declared ATT&CK tag extraction | Unit tested; tags are author assertions, not coverage proof |
| YARA and Suricata text precheck | Unit tested; engine validation not run |
| Authenticated `/v1/lint` API | ASGI unit tested; process startup unverified |
| Rule persistence/versioning, Git workflows, conversion, false-positive review, dashboard | Not implemented |

RuleSmith follows the [Sigma rule format](https://sigmahq.io/docs/basics/rules.html), [YARA rule documentation](https://yara.readthedocs.io/en/stable/writingrules.html), and [Suricata rule format](https://docs.suricata.io/en/latest/rules/intro.html) for its limited prechecks. The `precheck_only` result explicitly means a supported upstream engine has **not** validated a rule. Complex Sigma conditions are preserved as text and flagged for pySigma validation; RuleSmith does not interpret them. Supported Sigma backend conversion will require an installed [pySigma backend](https://sigmahq.io/docs/digging-deeper/backends) and explicit target configuration.

## Setup and use

Python 3.12+ is required. Install project dependencies in a local virtual environment when package access is available:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

Run an offline scan of an **authorized** local directory:

```bash
PYTHONPATH=. python3.12 -m rulesmith.cli /path/to/authorized/rules
```

The scanner reads `.yml`, `.yaml`, `.yar`, `.yara`, and `.rules` files only. It skips symlinks, limits depth to eight parts, files to 2,000, total entries to 10,000, each rule to 256 KiB, and scanned rule content to 50 MiB. Results contain metadata and SHA-256 digests, not rule content.

To run the API, set `RULESMITH_API_TOKEN` to a private random string of at least 32 characters and start:

```bash
.venv/bin/uvicorn rulesmith.api:app --host 127.0.0.1 --port 8000
```

Call `POST /v1/lint` with a bearer token and JSON `{ "kind": "sigma", "content": "..." }`. The API does not persist input or scan server paths. OpenAPI docs are available at `/docs` when running. See [API.md](API.md).

For local container use, set the token in a private `.env` and run `docker compose up --build`. Compose binds the API to `127.0.0.1:8091`. Container startup is unverified in the current environment.

## Testing and next steps

```bash
python3.12 -m compileall -q rulesmith tests
python3.12 -m unittest discover -s tests -v
.venv/bin/ruff check .
.venv/bin/pytest -q
```

See [VALIDATION_REPORT.md](VALIDATION_REPORT.md) for actual results. The next milestone is an immutable rule revision store with review decisions and audit records, then full validation through installed pySigma/YARA/Suricata tools and an analyst dashboard. No repository rule is deployed automatically.
