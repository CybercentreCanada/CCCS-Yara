import re

from plyara import Plyara

from cccs_yara.validator import RuleValidatorModel

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
        assert validated_metadata.source == "Default Source".upper()
