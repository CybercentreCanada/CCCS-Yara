from tempfile import NamedTemporaryFile

from yara_validator.validator import run_yara_validator

RULES = b"""
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
    with NamedTemporaryFile() as tf:
        tf.write(RULES)
        tf.seek(0)

        for rule in run_yara_validator(tf.name, generate_values=True).yara_rules:
            fingerprint, id = None, None
            for m in rule.rule_plyara['metadata']:
                if 'id' in m:
                    id = m['id']
                elif 'fingerprint' in m:
                    fingerprint = m['fingerprint']

            # Ensure the fingerprint and the id metadata fields were generated for all rules
            assert fingerprint and id
