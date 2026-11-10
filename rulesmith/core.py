"""Bounded, non-executing rule prechecks with explicit validation limits."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from uuid import UUID

import yaml

MAX_RULE_BYTES = 256 * 1024
MAX_FILES = 2000
MAX_DEPTH = 8
MAX_ENTRIES = 10000
MAX_TOTAL_BYTES = 50 * 1024 * 1024
ATTACK_TAG = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$", re.IGNORECASE)
RULE_FILE_KIND = {".yml": "sigma", ".yaml": "sigma", ".yar": "yara", ".yara": "yara", ".rules": "suricata"}


class RuleError(ValueError):
    pass


class StrictLoader(yaml.SafeLoader):
    """Safe YAML loader forbidding aliases, duplicate keys, and deep nesting."""

    def __init__(self, stream):
        super().__init__(stream)
        self.depth = 0
        self.nodes_seen = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise RuleError("YAML aliases are not accepted")
        self.depth += 1
        self.nodes_seen += 1
        if self.depth > 32 or self.nodes_seen > 10000:
            raise RuleError("YAML complexity limit exceeded")
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise RuleError("YAML mapping keys must be strings")
            if key in mapping:
                raise RuleError(f"duplicate YAML key: {key}")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _text(raw: bytes) -> str:
    if not 0 < len(raw) <= MAX_RULE_BYTES:
        raise RuleError("rule must be 1 to 262144 bytes")
    if b"\x00" in raw:
        raise RuleError("binary content is not a rule")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuleError("rule must use UTF-8") from exc


def _result(kind: str, raw: bytes) -> dict:
    return {"kind": kind, "sha256": hashlib.sha256(raw).hexdigest(), "status": "precheck_only",
            "errors": [], "warnings": [], "declared_attack_tags": [], "rule_id": None,
            "title": None, "engine_validation": "not run"}


def lint_sigma(raw: bytes) -> dict:
    text = _text(raw)
    result = _result("sigma", raw)
    try:
        rule = yaml.load(text, Loader=StrictLoader)
    except (yaml.YAMLError, RuleError) as exc:
        result["errors"].append(f"invalid or unsafe YAML: {exc}")
        result["status"] = "invalid"
        return result
    if not isinstance(rule, dict):
        result["errors"].append("Sigma document must be a mapping")
        result["status"] = "invalid"
        return result
    title = rule.get("title")
    if not isinstance(title, str) or not title.strip():
        result["errors"].append("missing non-empty title")
    else:
        result["title"] = title.strip()[:256]
    rule_id = rule.get("id")
    if rule_id is not None:
        try:
            result["rule_id"] = str(UUID(str(rule_id)))
        except ValueError:
            result["errors"].append("id must be a UUID")
    logsource = rule.get("logsource")
    if not isinstance(logsource, dict) or not logsource:
        result["errors"].append("missing logsource mapping")
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        result["errors"].append("missing detection mapping")
    else:
        condition = detection.get("condition")
        if not isinstance(condition, str) or not condition.strip():
            result["errors"].append("missing detection condition")
        selectors = {name for name in detection if name not in {"condition", "timeframe"}}
        if not selectors:
            result["errors"].append("detection needs at least one selection")
        for name in selectors:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                result["errors"].append(f"invalid selection name: {name[:80]}")
            if not isinstance(detection[name], (dict, list, str)):
                result["errors"].append(f"invalid selection value: {name[:80]}")
        if isinstance(condition, str):
            simple = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", condition.strip())
            if simple and simple.group() not in selectors:
                result["errors"].append("condition references an undefined selection")
            elif not simple:
                result["warnings"].append("condition semantics require pySigma validation")
    level = rule.get("level")
    if level is not None and level not in {"informational", "low", "medium", "high", "critical"}:
        result["errors"].append("invalid level")
    tags = rule.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        result["errors"].append("tags must be a string list")
    else:
        result["declared_attack_tags"] = sorted({tag.lower() for tag in tags if ATTACK_TAG.fullmatch(tag)})
    if not rule.get("falsepositives"):
        result["warnings"].append("false positives not documented")
    if not rule.get("status"):
        result["warnings"].append("rule status not documented")
    result["warnings"].append("structural precheck only; no Sigma engine or backend conversion run")
    result["status"] = "invalid" if result["errors"] else "precheck_only"
    return result


def lint_yara(raw: bytes) -> dict:
    text = _text(raw)
    result = _result("yara", raw)
    if not re.search(r"\brule\s+[A-Za-z_][A-Za-z0-9_]*\s*\{", text):
        result["errors"].append("no rule declaration found")
    if not re.search(r"\bcondition\s*:", text):
        result["errors"].append("no condition section found")
    result["warnings"].append("text precheck only; use a supported YARA compiler for syntax validation")
    result["status"] = "invalid" if result["errors"] else "precheck_only"
    return result


def lint_suricata(raw: bytes) -> dict:
    text = _text(raw)
    result = _result("suricata", raw)
    lines = [(i, line.strip()) for i, line in enumerate(text.splitlines(), 1)
             if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        result["errors"].append("no active signature lines")
    for number, line in lines:
        if not re.match(r"^(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth)\s+\S+\s+\S+\s+\S+\s+(?:->|<>)\s+\S+\s+\S+\s*\(", line):
            result["errors"].append(f"line {number}: malformed signature header")
        if not re.search(r"\bsid\s*:\s*[1-9]\d*\s*;", line):
            result["errors"].append(f"line {number}: missing positive sid")
        if not line.endswith(")"):
            result["errors"].append(f"line {number}: missing closing options parenthesis")
    result["warnings"].append("text precheck only; use Suricata test mode for full syntax validation")
    result["status"] = "invalid" if result["errors"] else "precheck_only"
    return result


LINTERS = {"sigma": lint_sigma, "yara": lint_yara, "suricata": lint_suricata}


def scan_directory(root: Path) -> dict:
    """Inspect only the explicitly selected directory; never follow symlinks."""
    if root.is_symlink() or not root.is_dir():
        raise RuleError("scope must be a real directory")
    root = root.resolve(strict=True)
    files = []
    seen_hashes = {}
    seen_ids = {}
    entries = 0
    total_bytes = 0
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directory_names[:] = sorted(name for name in directory_names
                                    if not (current_path / name).is_symlink()
                                    and len((current_path / name).relative_to(root).parts) < MAX_DEPTH)
        entries += len(directory_names) + len(file_names)
        if entries > MAX_ENTRIES:
            raise RuleError("scan exceeds 10000 directory entries")
        for name in sorted(file_names):
            path = current_path / name
            if path.suffix.lower() not in RULE_FILE_KIND or path.is_symlink():
                continue
            relative = path.relative_to(root)
            if len(relative.parts) > MAX_DEPTH:
                continue
            if len(files) >= MAX_FILES:
                raise RuleError("scan exceeds 2000 rule files")
            try:
                fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(fd, "rb") as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        continue
                    raw = stream.read(MAX_RULE_BYTES + 1)
            except OSError as exc:
                files.append({"path": str(relative), "status": "invalid",
                              "errors": [f"cannot read rule: {exc.strerror or 'I/O error'}"]})
                continue
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_BYTES:
                raise RuleError("scan exceeds 50 MiB of rule content")
            if len(raw) > MAX_RULE_BYTES:
                files.append({"path": str(relative), "status": "invalid",
                              "errors": ["file exceeds 262144 bytes"]})
                continue
            result = LINTERS[RULE_FILE_KIND[path.suffix.lower()]](raw)
            result["path"] = str(relative)
            digest = result["sha256"]
            if digest in seen_hashes:
                result["warnings"].append(f"duplicate content: {seen_hashes[digest]}")
            else:
                seen_hashes[digest] = str(relative)
            if result["rule_id"]:
                if result["rule_id"] in seen_ids:
                    result["warnings"].append(f"duplicate rule ID: {seen_ids[result['rule_id']]}")
                else:
                    seen_ids[result["rule_id"]] = str(relative)
            files.append(result)
    return {"scope": str(root), "files": files, "file_count": len(files),
            "engine_validation": "not run", "deployment": "none"}
