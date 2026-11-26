"""Role-aware field masking.

Rules describe a field path, a role and a strategy.  A record is transformed
field by field; authorized views keep the original value and are recorded in
the audit trail.
"""
from __future__ import annotations

import copy
from typing import Any

AUDIT_LOG: list[dict[str, Any]] = []

_STRATEGY_ALIASES = {
    "view": "allow",
    "read": "allow",
    "permit": "allow",
    "reveal": "allow",
    "redact": "mask",
    "hide": "mask",
    "deny": "deny",
    "block": "deny",
}

_KIND_ALIASES = {
    "mobile": "phone",
    "tel": "phone",
    "telephone": "phone",
    "mail": "email",
    "e-mail": "email",
    "id": "idcard",
    "identity": "idcard",
    "id_card": "idcard",
    "username": "name",
}

_STRICTNESS = {"allow": 0, "mask": 1, "deny": 2}


def _norm_path(path: Any) -> str:
    text = str(path if path is not None else "").strip().lower()
    text = text.replace("/", ".").replace("[", ".").replace("]", "")
    while ".." in text:
        text = text.replace("..", ".")
    return text.strip(".")


def _norm_role(role: Any) -> str:
    return str(role if role is not None else "").strip().lower()


def _norm_strategy(strategy: Any) -> str:
    text = str(strategy if strategy is not None else "").strip().lower()
    return _STRATEGY_ALIASES.get(text, text or "mask")


def _norm_kind(kind: Any) -> str:
    text = str(kind if kind is not None else "").strip().lower()
    return _KIND_ALIASES.get(text, text or "text")


def _path_matches(rule_path: str, path: str) -> bool:
    rule_path = _norm_path(rule_path)
    path = _norm_path(path)
    if rule_path in ("", "*"):
        return True
    if rule_path == path:
        return True
    if rule_path.endswith(".*"):
        return path.startswith(rule_path[:-1])
    return False


def _role_matches(rule_role: str, role: Any) -> bool:
    return rule_role in ("", "*") or rule_role == _norm_role(role)


def _fallback(path: str, role: Any) -> dict:
    return {
        "path": _norm_path(path),
        "role": _norm_role(role),
        "strategy": "mask",
        "kind": "text",
        "audit": False,
        "priority": 0,
        "matched": False,
    }


def parse_rules(rules: Any) -> list[dict]:
    """Return normalized rule dictionaries without mutating the input."""
    if rules is None:
        return []
    if isinstance(rules, dict):
        raw_rules = rules.get("rules", [])
    else:
        raw_rules = rules
    if not isinstance(raw_rules, (list, tuple)):
        raise TypeError("rules must be a list of mappings")

    parsed: list[dict] = []
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise TypeError("each rule must be a mapping")
        path = _norm_path(raw.get("path"))
        role = str(raw.get("role", "*") if raw.get("role") is not None else "*").strip()
        strategy = _norm_strategy(raw.get("strategy", raw.get("action", "mask")))
        kind = _norm_kind(raw.get("kind", "text"))
        audit = bool(raw.get("audit", strategy == "allow"))
        priority = int(raw.get("priority", 0) or 0)
        parsed.append(
            {
                "path": path,
                "role": role,
                "strategy": strategy,
                "kind": kind,
                "audit": audit,
                "priority": priority,
            }
        )
    return parsed


def match_rule(rules: Any, path: str, role: Any) -> dict:
    """Find the first rule matching both the field path and the role."""
    target_path = _norm_path(path)
    for rule in parse_rules(rules):
        if _path_matches(rule["path"], target_path) and _role_matches(rule["role"], role):
            result = copy.deepcopy(rule)
            result["matched"] = True
            return result
    return _fallback(target_path, role)


def mask_value(value: Any, kind: str = "text") -> str:
    """Hide the middle of a value while keeping a recognizable shape."""
    text = "" if value is None else str(value)
    if not text:
        return ""
    return "***"


def resolve_priority(matched: Any) -> dict:
    """Choose one rule from the candidates for a field."""
    candidates = [item for item in (matched or []) if isinstance(item, dict)]
    if not candidates:
        return {
            "path": "",
            "role": "",
            "strategy": "mask",
            "kind": "text",
            "audit": False,
            "priority": 0,
            "matched": False,
        }
    return dict(candidates[0])


def apply_mask(record: Any, rules: Any, role: Any) -> dict:
    """Mask one record for one role."""
    if not isinstance(record, dict):
        raise TypeError("record must be a mapping")
    parsed = parse_rules(rules or [])

    if any(
        rule["path"] == "*"
        and rule["strategy"] == "allow"
        and _role_matches(rule["role"], role)
        for rule in parsed
    ):
        return copy.deepcopy(record)

    masked: dict[str, Any] = {}
    for key, value in record.items():
        path = _norm_path(key)
        candidates = [
            rule for rule in parsed if _path_matches(rule["path"], path)
        ]
        if not candidates:
            masked[key] = copy.deepcopy(value)
            continue
        rule = resolve_priority(candidates)
        strategy = rule.get("strategy", "mask")
        if strategy == "allow":
            masked[key] = copy.deepcopy(value)
        elif strategy == "deny":
            masked[key] = None
        else:
            masked[key] = mask_value(value, rule.get("kind", "text"))
    return masked


def check_audit(role: Any, path: Any) -> dict:
    """Report whether an authorized view of a field was recorded."""
    normalized_role = _norm_role(role)
    normalized_path = _norm_path(path)
    entries = [
        dict(entry)
        for entry in AUDIT_LOG
        if entry.get("role") == normalized_role
        and entry.get("path") == normalized_path
    ]
    return {
        "role": normalized_role,
        "path": normalized_path,
        "audited": bool(entries),
        "entries": entries,
    }


def validate_rules(rules: Any) -> list[str]:
    """Return human-readable problems found in a rule set."""
    parsed = parse_rules(rules or [])
    issues: list[str] = []
    for rule in parsed:
        if rule["path"] == "*" and rule["role"] != "*":
            issues.append("wildcard_path_too_broad")
        if rule["role"] == "*" and rule["path"] != "*":
            issues.append("wildcard_role_too_broad")
        if rule["strategy"] == "allow" and not rule["audit"]:
            issues.append("authorized_view_missing_audit")
        if not rule["path"]:
            issues.append("missing_path")
        if not rule["role"]:
            issues.append("missing_role")
    return issues


def mask_batch(requests: Any, rules: Any) -> dict:
    """Mask a list of independent requests."""
    parsed = parse_rules(rules or [])
    results: list[dict] = []
    cache: dict[str, dict] = {}

    for request in requests or []:
        if not isinstance(request, dict):
            raise TypeError("each request must be a mapping")
        record = request.get("record") or {}
        if not isinstance(record, dict):
            raise TypeError("request record must be a mapping")
        role = request.get("role", "")
        masked: dict[str, Any] = {}
        for key, value in record.items():
            path = _norm_path(key)
            if path not in cache:
                candidates = [
                    rule
                    for rule in parsed
                    if _path_matches(rule["path"], path)
                    and _role_matches(rule["role"], role)
                ]
                cache[path] = (
                    resolve_priority(candidates)
                    if candidates
                    else {
                        "path": path,
                        "role": _norm_role(role),
                        "strategy": "allow",
                        "kind": "text",
                        "audit": False,
                        "priority": 0,
                        "matched": False,
                    }
                )
            rule = cache[path]
            strategy = rule.get("strategy", "mask")
            if strategy == "allow":
                masked[key] = copy.deepcopy(value)
            elif strategy == "deny":
                masked[key] = None
            else:
                masked[key] = mask_value(value, rule.get("kind", "text"))
        results.append(masked)
    return {"results": results}