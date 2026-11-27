"""Role-aware field masking.

Rules describe a field path, a role and a strategy.  A record is transformed
field by field; authorized views keep the original value and are recorded in
the audit trail.

Guarantees:
  * a rule fires only when *both* its field path and its role match;
  * no match (or an unmatched role) falls back to the strictest behaviour,
    never to the original value;
  * when several rules match, the most specific path wins (wildcards are only
    a fallback) and the strictest strategy wins among equally specific rules;
  * masking is deterministic, preserves the exact length/format and never
    reveals original content beyond the documented fixed prefix/suffix;
  * every authorized (``allow``) view appends an audit entry; masked or
    denied views never do;
  * batch requests are resolved independently, with no shared role/cache.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
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

# Higher number == stricter.  An allow can therefore never override a mask.
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
    """Segment-wise path match.

    ``*`` matches exactly one segment, except as the final segment where it
    also absorbs every remaining segment (``profile.*`` matches
    ``profile.phone`` and, conservatively, deeper descendants).  The bare
    ``*`` rule matches every path.  An empty rule path never matches, so a
    malformed rule can never open a field up.
    """
    rule = _norm_path(rule_path)
    target = _norm_path(path)
    if not rule or not target:
        return False
    if rule == "*":
        return True

    rule_segments = rule.split(".")
    target_segments = target.split(".")
    for index, segment in enumerate(rule_segments):
        if segment == "*":
            if index == len(rule_segments) - 1:
                # Trailing wildcard absorbs the rest of the target path.
                return len(target_segments) > index
            if index >= len(target_segments):
                return False
            continue
        if index >= len(target_segments) or target_segments[index] != segment:
            return False
    return len(target_segments) == len(rule_segments)


def _role_matches(rule_role: Any, role: Any) -> bool:
    """Role matching is exact, case-insensitive and whitespace-insensitive.

    ``*`` is the only wildcard; an empty rule role matches nobody (fail
    closed), as does an empty caller role against a concrete role.
    """
    normalized_rule_role = _norm_role(rule_role)
    if normalized_rule_role == "*":
        return True
    if not normalized_rule_role:
        return False
    return normalized_rule_role == _norm_role(role)


def _fallback(path: str, role: Any) -> dict:
    """Decision used when nothing matches: strictest possible (mask)."""
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
        raw_role = raw.get("role")
        role = _norm_role("*" if raw_role is None else raw_role)
        path = _norm_path(raw.get("path"))
        strategy = _norm_strategy(raw.get("strategy", raw.get("action", "mask")))
        kind = _norm_kind(raw.get("kind", "text"))
        audit = bool(raw.get("audit", strategy == "allow"))
        try:
            priority = int(raw.get("priority", 0) or 0)
        except (TypeError, ValueError):
            priority = 0
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


def _specificity(rule: dict, target_path: str) -> tuple[int, int]:
    """Higher tuple == more specific.

    Path specificity dominates so that a wildcard path can never overtake a
    concrete field rule for the same field.  Role specificity only breaks
    ties between equally specific paths.
    """
    normalized_target = _norm_path(target_path)
    if rule["path"] == normalized_target and normalized_target:
        path_score = 100 + len(normalized_target.split("."))
    else:
        path_score = 0
        for segment in rule["path"].split("."):
            if segment == "*":
                break
            path_score += 1
    role_score = 0 if rule["role"] in ("", "*") else 1
    return path_score, role_score


def _resolve_rule(parsed_rules: list[dict], path: str, role: Any) -> dict:
    """Dual-match resolution for one leaf field.

    Only rules matching *both* path and role are candidates.  The most
    specific candidate wins; among ties the strictest strategy wins; when no
    rule matches the field gets the strict fallback.
    """
    target_path = _norm_path(path)
    candidates = [
        rule
        for rule in parsed_rules
        if rule["path"]
        and _path_matches(rule["path"], target_path)
        and _role_matches(rule["role"], role)
    ]
    if not candidates:
        return _fallback(target_path, role)

    ranked = [(rule, _specificity(rule, target_path)) for rule in candidates]
    best_specificity = max(score for _, score in ranked)
    top_tier = [rule for rule, score in ranked if score == best_specificity]
    # ``max`` is stable: equal strictness keeps declaration order, so repeated
    # resolutions stay deterministic.  Unknown strategies are treated as the
    # strictest possible value (fail closed).
    winner = max(top_tier, key=lambda rule: _STRICTNESS.get(rule["strategy"], 2))
    result = copy.deepcopy(winner)
    result["matched"] = True
    return result


def match_rule(rules: Any, path: str, role: Any) -> dict:
    """Resolve the single effective rule matching both path and role."""
    return _resolve_rule(parse_rules(rules), path, role)


def mask_value(value: Any, kind: str = "text") -> str:
    """Mask a scalar while keeping its shape and exact length.

    Only the documented fixed prefix/suffix of each kind may survive; every
    other character becomes ``*``.  The output never reveals original content
    beyond that fixed fragment and otherwise reveals only the length.
    """
    text = "" if value is None else str(value)
    if not text:
        return ""
    normalized_kind = _norm_kind(kind)
    length = len(text)

    if normalized_kind == "phone":
        # First three and last four characters, equal-length stars between.
        if length > 7:
            return text[:3] + ("*" * (length - 7)) + text[-4:]
        return "*" * length

    if normalized_kind == "email":
        # Keep the first local-part character and the whole domain.
        if "@" in text:
            local, domain = text.split("@", 1)
            masked_local = (local[0] + ("*" * (len(local) - 1))) if local else ""
            return f"{masked_local}@{domain}"
        return "*" * length

    if normalized_kind == "idcard":
        # First four and last four characters.
        if length > 8:
            return text[:4] + ("*" * (length - 8)) + text[-4:]
        return "*" * length

    if normalized_kind == "name":
        # Keep the first character only.
        if length > 1:
            return text[0] + ("*" * (length - 1))
        return "*" * length

    # Generic text: full equal-length replacement.
    return "*" * length


def resolve_priority(matched: Any) -> dict:
    """Choose the strictest rule from the candidates for one field."""
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

    def strictness(item: dict) -> int:
        return _STRICTNESS.get(_norm_strategy(item.get("strategy", "mask")), 2)

    return copy.deepcopy(max(candidates, key=strictness))


def _audit_entry(role: Any, path: str) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "role": _norm_role(role),
        "path": _norm_path(path),
        "event": "view",
        "time": now.isoformat(),
        "timestamp": now.timestamp(),
    }


def _transform(value: Any, path: str, parsed_rules: list[dict], role: Any) -> Any:
    """Recursively mask one record for one role, building dotted leaf paths."""
    if isinstance(value, dict):
        return {
            key: _transform(
                child_value,
                f"{path}.{key}" if path else str(key),
                parsed_rules,
                role,
            )
            for key, child_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _transform(
                child_value,
                f"{path}.{index}" if path else str(index),
                parsed_rules,
                role,
            )
            for index, child_value in enumerate(value)
        ]

    decision = _resolve_rule(parsed_rules, path, role)
    strategy = decision.get("strategy", "mask")

    if strategy == "allow":
        # Authorized view: keep the original and leave a trace.
        AUDIT_LOG.append(_audit_entry(role, path))
        return copy.deepcopy(value)

    if strategy == "deny":
        return None

    if value is None:
        return None
    # Any other/unknown strategy fails closed as masking.
    return mask_value(value, decision.get("kind", "text"))


def apply_mask(record: Any, rules: Any, role: Any) -> dict:
    """Mask one record for one role without mutating the input."""
    if not isinstance(record, dict):
        raise TypeError("record must be a mapping")
    parsed_rules = parse_rules(rules or [])
    return _transform(copy.deepcopy(record), "", parsed_rules, role)


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
        # A catch-all that permits viewing defeats the strict default.
        # A catch-all ``mask`` is the strict default and is fine.
        if (
            rule["path"] == "*"
            and rule["role"] == "*"
            and rule["strategy"] == "allow"
        ):
            issues.append("default_policy_must_be_strict")

    # Without an explicit catch-all rule, unmatched fields still fall back to
    # masking at runtime, but the policy should state that default.
    if not any(rule["path"] == "*" and rule["role"] == "*" for rule in parsed):
        issues.append("missing_default_strict_policy")
    return issues


def mask_batch(requests: Any, rules: Any) -> dict:
    """Mask a list of independent requests.

    Each request carries its own role and record and is resolved from
    scratch: no role decision or match result is shared or inherited between
    requests.
    """
    parsed_rules = parse_rules(rules or [])
    results: list[dict] = []

    for request in requests or []:
        if not isinstance(request, dict):
            raise TypeError("each request must be a mapping")
        record = request.get("record") or {}
        if not isinstance(record, dict):
            raise TypeError("request record must be a mapping")
        role = request.get("role", "")
        results.append(_transform(copy.deepcopy(record), "", parsed_rules, role))

    return {"results": results}
