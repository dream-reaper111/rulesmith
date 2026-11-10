# Security model

Use RuleSmith only on rule collections you are authorized to inspect. The CLI does not execute rules or automatically deploy them. The API accepts rule text, not paths, and requires a configured bearer token. Keep the token in a private environment file; `.env` is ignored by Git. Bind the API to loopback or put it behind HTTPS and an approved identity-aware gateway before wider access.

YAML aliases and duplicate keys are rejected. The parser uses PyYAML's safe loader and limits input size, nesting, and node count. Directory scans skip symlinks and bound traversal and content. YARA and Suricata text passes are incomplete by design; do not treat a `precheck_only` status as a valid production rule. Rule text may contain sensitive detection details, so protect API requests and CLI output. The current service does not retain submitted content.

Known gaps: no persistent audit history, no per-user identity, no rate limiting, no full Sigma/YARA/Suricata compiler validation, no dependency audit, and no tenant isolation. Those controls are required before a multi-user deployment.
