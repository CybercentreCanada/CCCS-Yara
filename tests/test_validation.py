import re
from datetime import datetime, timezone

import pytest
from plyara import Plyara
from pydantic import ValidationError

from cccs_yara.validator import RuleValidatorModel, transform_date, transform_version

RULES = """
rule x
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
        description = "Fake rule for testing"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
    strings:
        $ = "x"
    condition:
        all of them
}

rule y
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
        description = "Fake rule for testing"
        category = "TOOL"
        tool = "exemplar"
        source = "CCCS"
    strings:
        $ = "y"
    condition:
        all of them
}
"""


def test_required_fields():
    # Bug: Metadata generation only worked on the first rule within a ruleset
    for rule in Plyara(meta_as_kv=True).parse_string(RULES):
        # Assert there's no validation issues
        validated_metadata = RuleValidatorModel.model_validate(rule["metadata_kv"], context={"rule": rule})

        # Assert required fields are present after validation due to auto-generation
        assert validated_metadata.id is not None
        assert validated_metadata.fingerprint is not None


def test_field_aliases():
    # Bug: Field aliases were not being applied during validation
    field_aliases = {"hash": "hash.*", "sharing": "classification", "date": "creation_date"}

    rules = Plyara(meta_as_kv=True).parse_string(
        """
    rule z
    {
        meta:
            version = "1.0"
            score = "0"
            minimum_yara = "3.5"
            creation_date = "2024-05-07"
            modified = "2024-05-07"
            status = "RELEASED"
            classification = "TLP:CLEAR"
            author = "CCCS"
            description = "Fake rule for testing"
            category = "TOOL"
            tool = "exemplar"
            source = "CCCS"
            hash_value = "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
        strings:
            $ = "z"
        condition:
            all of them
    }
    """
    )

    for rule in rules:
        # Validate with field aliases
        validated_metadata = RuleValidatorModel.model_validate(
            rule["metadata_kv"],
            context={
                "rule": rule,
                "aliases": {key: re.compile(pattern) for key, pattern in field_aliases.items()},
            },
        )

        # Assert aliased fields are correctly mapped
        assert validated_metadata.date == "2024-05-07"
        assert validated_metadata.sharing == "TLP:CLEAR"
        assert validated_metadata.hash == {"936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"}


def test_default_metadata():
    # Bug: Default metadata values were not being applied during validation
    default_metadata = {
        "author": "Default Author",
        "source": "Default Source",
    }

    rules = Plyara(meta_as_kv=True).parse_string(
        """
    rule w
    {
        meta:
            version = "1.0"
            score = "0"
            minimum_yara = "3.5"
            date = "2024-05-07"
            modified = "2024-05-07"
            status = "RELEASED"
            sharing = "TLP:CLEAR"
            description = "Fake rule for testing"
            tool = "exemplar"
            category = "TOOL"
        strings:
            $ = "w"
        condition:
            all of them
    }
    """
    )

    for rule in rules:
        # Validate with default metadata
        validated_metadata = RuleValidatorModel.model_validate(
            rule["metadata_kv"],
            context={
                "rule": rule,
                "default_metadata": default_metadata,
            },
        )

        # Assert default metadata values are applied
        assert validated_metadata.author == "Default Author"
        assert validated_metadata.source == "DEFAULT SOURCE"


def test_transform_version():
    assert transform_version("2.3") == "2.3"
    assert transform_version("2") == "2.0"
    assert transform_version(".7") == "0.7"
    assert transform_version("3.") == "3.0"
    assert transform_version(4) == "4.0"
    assert transform_version("") == "1.0"
    assert transform_version("invalid") == "1.0"


# -- Helper utilities for model-level tests --


def _make_context(rule=None, **kwargs):
    if rule is None:
        rule = {
            "rule_name": "test",
            "name": "test",
            "strings": [{"value": "x", "name": "$", "type": "text"}],
            "condition_terms": ["all", "of", "them"],
            "raw_condition": "all of them",
            "raw_strings": '$ = "x"',
        }
    ctx = {"rule": rule}
    ctx.update(kwargs)
    return ctx


def _valid_metadata(**overrides):
    base = {
        "version": "1.0",
        "date": "2024-05-07",
        "modified": "2024-05-07",
        "status": "RELEASED",
        "sharing": "TLP:CLEAR",
        "author": "CCCS",
        "description": "Test",
        "category": "TOOL",
        "tool": "exemplar",
        "source": "CCCS",
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    "input,expected",
    [
        ("2024-05-07", "2024-05-07"),
        ("2024/05/07", "2024-05-07"),
        ("2024.05.07", "2024-05-07"),
        ("2024-05", "2024-05-01"),
        ("", datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")),
        ("invalid", ValueError),
    ],
)
def test_transform_date(input, expected):
    if expected is ValueError:
        # If we're expecting a ValueError, assert that it's raised
        with pytest.raises(ValueError):
            transform_date(input)
    else:
        # Otherwise, expect the transformed date to match the expected value
        assert transform_date(input) == expected


def test_model_valid():
    data = _valid_metadata()
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.version == "1.0"
    assert result.sharing == "TLP:CLEAR"
    assert result.author == "CCCS"


def test_model_autogenerate_id():
    data = _valid_metadata()
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.id is not None
    assert len(result.id) > 0


def test_model_autogenerate_fingerprint():
    data = _valid_metadata()
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.fingerprint is not None
    assert re.match(r"^[a-fA-F0-9]{64}$", result.fingerprint)


def test_model_sharing_tlp_white_to_clear():
    data = _valid_metadata(sharing="TLP:WHITE")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.sharing == "TLP:CLEAR"


def test_model_sharing_uppercase():
    data = _valid_metadata(sharing="tlp:green")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.sharing == "TLP:GREEN"


def test_model_sharing_amber_strict():
    data = _valid_metadata(sharing="TLP:AMBER+STRICT")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.sharing == "TLP:AMBER+STRICT"


def test_model_invalid_sharing():
    data = _valid_metadata(sharing="INVALID")
    with pytest.raises(ValidationError):
        RuleValidatorModel.model_validate(data, context=_make_context())


def test_model_status_values():
    for status in ["TESTING", "RELEASED", "DEPRECATED"]:
        data = _valid_metadata(status=status)
        result = RuleValidatorModel.model_validate(data, context=_make_context())
        assert result.status == status


def test_model_invalid_status():
    data = _valid_metadata(status="INVALID")
    with pytest.raises(ValidationError):
        RuleValidatorModel.model_validate(data, context=_make_context())


def test_model_category_validation():
    for category in ["MALWARE", "EXPLOIT", "TECHNIQUE", "TOOL", "INFO", "VULNERABILITY"]:
        extra = {}
        if category == "MALWARE":
            extra = {"malware": "TEST"}
        elif category == "EXPLOIT":
            extra = {"exploit": "CVE-2024-0001"}
        elif category == "TECHNIQUE":
            extra = {"technique": "T1059"}
        elif category == "TOOL":
            extra = {"tool": "exemplar"}
        elif category == "INFO":
            extra = {"info": "generic"}

        data = _valid_metadata(category=category, **extra)
        if category != "TOOL":
            data.pop("tool", None)
        result = RuleValidatorModel.model_validate(data, context=_make_context())
        assert result.category == category


def test_model_invalid_category():
    data = _valid_metadata(category="BADCAT")
    data.pop("tool", None)
    with pytest.raises(ValidationError):
        RuleValidatorModel.model_validate(data, context=_make_context())


def test_model_malware_field_requires_malware_category():
    data = _valid_metadata(category="TOOL", malware="TEST")
    with pytest.raises(ValidationError):
        RuleValidatorModel.model_validate(data, context=_make_context())


def test_model_tool_field_requires_tool_category():
    data = _valid_metadata(category="MALWARE", malware="TEST", tool="BADTOOL")
    with pytest.raises(ValidationError):
        RuleValidatorModel.model_validate(data, context=_make_context())


def test_model_hash_validation_valid():
    valid_hash = "a" * 64
    data = _valid_metadata(hash=valid_hash)
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert valid_hash in result.hash


def test_model_hash_validation_set():
    hashes = {"a" * 64, "b" * 64}
    data = _valid_metadata(hash=hashes)
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.hash == hashes


def test_model_mitre_att_valid():
    data = _valid_metadata(mitre_att="T1059")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "T1059" in result.mitre_att


def test_model_mitre_att_set():
    data = _valid_metadata(mitre_att={"T1059", "T1053.005"})
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "T1059" in result.mitre_att
    assert "T1053.005" in result.mitre_att


def test_model_source_uppercased():
    data = _valid_metadata(source="lower_source")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.source == "LOWER_SOURCE"


def test_model_version_transform():
    data = _valid_metadata(version="3")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.version == "3.0"


def test_model_date_transform():
    data = _valid_metadata(date="05/07/2024")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.date == "2024-05-07"


def test_model_default_metadata_applied():
    data = _valid_metadata()
    data.pop("author")
    data.pop("source")
    result = RuleValidatorModel.model_validate(
        data, context=_make_context(default_metadata={"author": "DefaultAuthor", "source": "DefaultSource"})
    )
    assert result.author == "DefaultAuthor"
    assert result.source == "DEFAULTSOURCE"


def test_model_alias_resolution():
    data = _valid_metadata()
    data.pop("sharing")
    data["classification"] = "TLP:GREEN"
    aliases = {"sharing": re.compile("classification")}
    result = RuleValidatorModel.model_validate(data, context=_make_context(aliases=aliases))
    assert result.sharing == "TLP:GREEN"


def test_model_description_autogenerated_for_malware():
    data = _valid_metadata(category="MALWARE", malware="EMOTET")
    data.pop("tool")
    data.pop("description")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "EMOTET" in result.description


def test_model_description_autogenerated_for_actor():
    data = _valid_metadata(category="MALWARE", malware="TEST", actor={"APT28"})
    data.pop("tool")
    data.pop("description")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "APT28" in result.description


def test_model_fingerprint_strip_v1_prefix():
    fake_hash = "a" * 64
    data = _valid_metadata(fingerprint=f"v1_sha256_{fake_hash}")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.fingerprint == fake_hash


def test_model_malware_type_validation():
    data = _valid_metadata(category="MALWARE", malware="TEST", malware_type="RANSOMWARE")
    data.pop("tool")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "RANSOMWARE" in result.malware_type


def test_model_actor_type_validation():
    data = _valid_metadata(actor_type="APT")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "APT" in result.actor_type


def test_model_report_field_as_string():
    data = _valid_metadata(report="https://example.com/report")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "https://example.com/report" in result.report


def test_model_report_field_as_set():
    data = _valid_metadata(report={"https://a.com", "https://b.com"})
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert len(result.report) == 2


def test_model_tags_field():
    data = _valid_metadata(tags={"tag1", "tag2"})
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert result.tags == {"tag1", "tag2"}


def test_model_tags_field_string():
    data = _valid_metadata(tags="single_tag")
    result = RuleValidatorModel.model_validate(data, context=_make_context())
    assert "single_tag" in result.tags
