"""Tests for cccs_yara.main: validate_yara_rule and rebuild_rule."""

from cccs_yara.main import rebuild_rule, validate_yara_rule

VALID_RULE = """
rule valid_test
{
    meta:
        version = "1.0"
        score = "0"
        minimum_yara = "3.5"
        date = "2024-05-07"
        modified = "2024-05-07"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "CCCS"
        description = "Test rule"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
    strings:
        $ = "test"
    condition:
        all of them
}
"""

MINIMAL_RULE = """
rule minimal_test
{
    meta:
        sharing = "TLP:CLEAR"
        author = "CCCS"
        description = "Minimal rule"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
    strings:
        $ = "test"
    condition:
        all of them
}
"""

MULTI_RULE = """
rule first_rule
{
    meta:
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-01"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "CCCS"
        description = "First rule"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
    strings:
        $ = "first"
    condition:
        all of them
}

rule second_rule
{
    meta:
        version = "2.0"
        date = "2024-01-02"
        modified = "2024-01-02"
        status = "RELEASED"
        sharing = "TLP:GREEN"
        author = "CCCS"
        description = "Second rule"
        category = "MALWARE"
        malware = "TEST"
        source = "CCCS"
    strings:
        $ = "second"
    condition:
        all of them
}
"""


def test_valid_rule_no_errors():
    # Test that a valid rule produces no validation errors.
    results = validate_yara_rule(VALID_RULE)
    assert len(results) == 1
    _, errors = results[0]
    assert errors == []


def test_valid_rule_has_required_fields():
    # Test that a valid rule has all required metadata fields.
    results = validate_yara_rule(VALID_RULE)
    rule, _ = results[0]
    metadata = rule["metadata_kv"]
    assert "id" in metadata
    assert "fingerprint" in metadata
    assert metadata["version"] == "1.0"
    assert metadata["sharing"] == "TLP:CLEAR"


def test_minimal_rule_autogenerates_fields():
    # Test that a minimal rule has auto-generated fields added.
    results = validate_yara_rule(MINIMAL_RULE)
    rule, errors = results[0]
    assert errors == []
    metadata = rule["metadata_kv"]
    # Auto-generated fields
    assert "id" in metadata
    assert "fingerprint" in metadata
    # Version defaults to 1.0
    assert metadata["version"] == "1.0"


def test_multi_rule_validation():
    # Test that multiple rules are validated correctly.
    results = validate_yara_rule(MULTI_RULE)
    assert len(results) == 2
    for _, errors in results:
        assert errors == []


def test_invalid_rule_returns_errors():
    # Test that an invalid rule produces validation errors.
    rule = """
rule bad_rule
{
    meta:
        sharing = "INVALID_SHARING"
        author = "CCCS"
        description = "Bad rule"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
    strings:
        $ = "bad"
    condition:
        all of them
}
"""
    results = validate_yara_rule(rule)
    _, errors = results[0]
    assert len(errors) > 0


def test_dict_input():
    # Test that validate_yara_rule can accept a dict input (needed for scripted validation).
    parsed_rule = {
        "rule_name": "dict_test",
        "name": "dict_test",
        "metadata_kv": {
            "version": "1.0",
            "date": "2024-05-07",
            "modified": "2024-05-07",
            "status": "RELEASED",
            "sharing": "TLP:CLEAR",
            "author": "CCCS",
            "description": "Test from dict",
            "category": "TOOL",
            "tool": "exemplar",
            "source": "CCCS",
        },
        "strings": [{"value": "test", "name": "$", "type": "text"}],
        "condition_terms": ["all", "of", "them"],
        "raw_condition": "all of them",
        "raw_strings": '$ = "test"',
    }
    results = validate_yara_rule(parsed_rule)
    assert len(results) == 1
    _, errors = results[0]
    assert errors == []


def test_default_metadata_applied():
    # Test that default metadata is applied when not provided in the rule.
    rule = """
rule defaults_test
{
    meta:
        sharing = "TLP:CLEAR"
        description = "Defaults test"
        category = "TOOL"
        tool = "test"
    strings:
        $ = "test"
    condition:
        all of them
}
"""
    results = validate_yara_rule(rule, default_metadata={"author": "Default", "source": "Default"})
    rule_data, errors = results[0]
    assert errors == []
    assert rule_data["metadata_kv"]["author"] == "Default"
    assert rule_data["metadata_kv"]["source"] == "DEFAULT"


def test_field_aliases_applied():
    # Test that field aliases are correctly applied during validation.
    rule = """
rule alias_test
{
    meta:
        version = "1.0"
        creation_date = "2024-05-07"
        modified = "2024-05-07"
        status = "RELEASED"
        classification = "TLP:CLEAR"
        author = "CCCS"
        description = "Alias test"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
        hash_md5 = "d41d8cd98f00b204e9800998ecf8427e"
    strings:
        $ = "test"
    condition:
        all of them
}
"""
    # classification should map to sharing, creation_date should map to date, and hash_md5 should map to hash
    aliases = {"hash": "hash.*", "sharing": "classification", "date": "creation_date"}
    results = validate_yara_rule(rule, field_aliases=aliases)
    rule_data, errors = results[0]
    assert errors == []
    assert rule_data["metadata_kv"]["date"] == "2024-05-07"
    assert rule_data["metadata_kv"]["sharing"] == "TLP:CLEAR"
    assert "d41d8cd98f00b204e9800998ecf8427e" in rule_data["metadata_kv"]["hash"]


def test_filename_context_passed():
    # Test that the filename context is correctly passed to the validation function.
    rule = """
rule filename_test
{
    meta:
        version = "1.0"
        date = "2024-01-01"
        modified = "2024-01-01"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "CCCS"
        description = "Filename test"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
    strings:
        $ = "test"
    condition:
        all of them
}
"""
    results = validate_yara_rule(rule, filename="apt_test.yara")
    rule_data, _ = results[0]
    assert rule_data["filename"] == "apt_test.yara"


def test_rebuild_produces_valid_yara():
    # Test that rebuilding a validated rule produces valid YARA syntax.
    results = validate_yara_rule(VALID_RULE)
    rule, _ = results[0]
    rebuilt = rebuild_rule(rule)
    assert "rule valid_test" in rebuilt
    assert "condition:" in rebuilt
    assert "meta:" in rebuilt


def test_rebuild_set_fields_expanded():
    # Test that set fields are correctly expanded during rebuild.
    results = validate_yara_rule(MULTI_RULE)
    # Second rule has malware field which is a set
    rule, _ = results[1]
    rebuilt = rebuild_rule(rule)
    assert "malware" in rebuilt
