from tempfile import NamedTemporaryFile

import pytest

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
            for m in rule.rule_plyara["metadata"]:
                if "id" in m:
                    id = m["id"]
                elif "fingerprint" in m:
                    fingerprint = m["fingerprint"]

            # Ensure the fingerprint and the id metadata fields were generated for all rules
            assert fingerprint and id


NO_METADATA_RULE = b"""
rule no_metadata {
    strings:
        $ = "lol"
    condition:
        any of them
}
"""


VT_MODULE_RULE = b"""
import "vt"

rule Test_VT_Module {
    condition:
        vt.metadata.subfile
        and vt.metadata.file_type == vt.FileType.XML
        and  filesize < 5KB
}
"""


@pytest.mark.parametrize("generate_values", [True, False])
def test_no_metadata(generate_values):
    with NamedTemporaryFile() as tf:
        tf.write(NO_METADATA_RULE)
        tf.seek(0)

        for rule in run_yara_validator(
            tf.name, generate_values=generate_values
        ).yara_rules:
            if generate_values:
                # If generate_values is True, metadata should be generated even if it doesn't exist in the original rule
                assert "metadata" in rule.rule_plyara
                fingerprint, id_val = None, None
                for m in rule.rule_plyara["metadata"]:
                    if "id" in m:
                        id_val = m["id"]
                    elif "fingerprint" in m:
                        fingerprint = m["fingerprint"]

                assert fingerprint and id_val
            else:
                # Otherwise don't expect any metadata to be generated
                assert "metadata" not in rule.rule_plyara


def test_vt_module_rule_parses_and_metadata_is_validated():
    with NamedTemporaryFile() as tf:
        tf.write(VT_MODULE_RULE)
        tf.seek(0)

        processed_file = run_yara_validator(tf.name, generate_values=True)
        assert len(processed_file.yara_rules) == 1

        rule = processed_file.yara_rules[0]
        assert "vt" in rule.rule_plyara["imports"]

        validation_errors = rule.rule_return.return_errors()
        assert "Missing required metadata" in validation_errors
        assert "category" in validation_errors
        assert "Error Compiling YARA file with yara" not in processed_file.return_file_errors()
