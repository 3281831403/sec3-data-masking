"""Public acceptance tests for the role-aware masking engine."""
from engine.mask.apply import (
    apply_mask,
    mask_batch,
    mask_value,
    parse_rules,
    resolve_priority,
)

PHONE = "13812348000"
MASKED_PHONE = "138****8000"


def _view_rules():
    return parse_rules(
        [
            {"path": "phone", "role": "manager", "strategy": "allow"},
            {"path": "phone", "role": "guest", "strategy": "mask", "kind": "phone"},
        ]
    )


def test_public_parse_rules_normalizes():
    raw = [
        {
            "path": " Profile.Phone ",
            "role": "Manager",
            "strategy": "MASK",
            "kind": "PHONE",
        }
    ]
    parsed = parse_rules(raw)

    assert parsed[0]["path"] == "profile.phone"
    assert parsed[0]["role"] == "manager"
    assert parsed[0]["strategy"] == "mask"
    assert parsed[0]["kind"] == "phone"
    assert raw[0]["role"] == "Manager"


def test_public_double_matching_checks_path_and_role():
    rules = _view_rules()
    record = {"phone": PHONE}

    assert apply_mask(record, rules, "manager")["phone"] == PHONE
    assert apply_mask(record, rules, "guest")["phone"] == MASKED_PHONE


def test_public_mask_value_preserves_format():
    assert mask_value(PHONE, "phone") == MASKED_PHONE
    assert mask_value("alice@example.com", "email") == "a****@example.com"
    assert len(mask_value(PHONE, "phone")) == len(PHONE)


def test_public_conflict_takes_strictest():
    matched = [
        {"path": "phone", "role": "support", "strategy": "allow"},
        {"path": "phone", "role": "support", "strategy": "mask", "kind": "phone"},
    ]

    assert resolve_priority(matched)["strategy"] == "mask"


def test_public_batch_requests_are_independent():
    requests = [
        {"role": "manager", "record": {"phone": PHONE}},
        {"role": "guest", "record": {"phone": PHONE}},
    ]

    output = mask_batch(requests, _view_rules())

    assert output["results"][0]["phone"] == PHONE
    assert output["results"][1]["phone"] == MASKED_PHONE