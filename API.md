# API v1

`GET /health` is public and reports runtime state, lack of persistence, and disabled deployment. `POST /v1/lint` requires `Authorization: Bearer <RULESMITH_API_TOKEN>` and JSON with `kind` (`sigma`, `yara`, or `suricata`) and `content` (at most 262,144 characters; the UTF-8 byte limit is enforced separately). It returns `status`, `errors`, `warnings`, `sha256`, `declared_attack_tags`, `rule_id`, and `engine_validation`. `precheck_only` is a successful structural review, **not** full grammar or runtime validation. No API endpoint scans a server directory or deploys a rule.

FastAPI serves `/openapi.json` and `/docs` when the API is running. API process startup is not verified in this environment; the ASGI unit test covers authentication and the lint response.
