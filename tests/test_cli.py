import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from git import Repo


@pytest.mark.parametrize("ignore", [True, False])
def test_ignore_private_rule(ignore):
    rule = """
private rule IsPE {
    meta:
        description = "Ientifies Portable Executable binaries that has a valid magic in DOS and NT header"
    condition:
        (uint16(0) == 0x5A4D or uint16(0) == 0x4D5A) and uint32(uint32(0x3c)) == 0x00004550
}
"""

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yara") as temp_rule_file:
        temp_rule_file.write(rule)
        temp_rule_file.flush()

        cmd = ["cccs-yara", "--verbose=WARN", "validate"]
        if ignore:
            cmd.append("--ignore-private-rules")

        cmd.append(temp_rule_file.name)

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Check the output based on whether private rules are ignored
        if ignore:
            assert "Skipping Private Rule" in result.stderr
        else:
            assert "Invalid Rule File" in result.stderr


def test_createfile_writes_single_validated_file():
    rules = """
rule one {
    meta:
        modified = "2024-05-07"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "CCCS"
        source = "CCCS"
        category = "TOOL"
        tool = "exemplar"
        description = "first"
    condition:
        true
}

rule two {
    meta:
        modified = "2024-05-07"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "CCCS"
        source = "CCCS"
        category = "TOOL"
        tool = "exemplar"
        description = "second"
    condition:
        true
}
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".yara", dir=temp_dir, delete=False) as rule_file:
                rule_file.write(rules)

            cmd = ["cccs-yara", "validate", "-o", "createfile", rule_file.name]
            subprocess.run(cmd, capture_output=True, text=True, check=True)

            stem = Path(rule_file.name).stem
            validated_path = Path(temp_dir) / f"{stem}_validated.yara"
            assert validated_path.exists()

            content = validated_path.read_text(encoding="utf-8")
            assert "rule one" in content
            assert "rule two" in content
        finally:
            try:
                Path(rule_file.name).unlink()
            except OSError:
                pass


def test_splitrules_writes_one_file_per_rule_name():
    rules = """
rule one {
    meta:
        modified = "2024-05-07"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "CCCS"
        source = "CCCS"
        category = "TOOL"
        tool = "exemplar"
        description = "first"
    condition:
        true
}

rule two {
    meta:
        modified = "2024-05-07"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "CCCS"
        source = "CCCS"
        category = "TOOL"
        tool = "exemplar"
        description = "second"
    condition:
        true
}
"""

    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            with tempfile.NamedTemporaryFile(mode="w+", suffix=".yara", dir=temp_dir, delete=False) as rule_file:
                rule_file.write(rules)
                rule_file.flush()

                cmd = ["cccs-yara", "validate", "-o", "splitrules", rule_file.name]
                subprocess.run(cmd, capture_output=True, text=True, check=True)

                first_rule_path = Path(temp_dir) / "one.yara"
                second_rule_path = Path(temp_dir) / "two.yara"
                single_file_path = Path(temp_dir) / f"{Path(rule_file.name).stem}_validated.yara"

                assert first_rule_path.exists()
                assert second_rule_path.exists()
                assert not single_file_path.exists()

                assert "rule one" in first_rule_path.read_text(encoding="utf-8")
                assert "rule two" in second_rule_path.read_text(encoding="utf-8")
        finally:
            # Ensure cleanup on all platforms.
            try:
                Path(rule_file.name).unlink()
            except OSError:
                pass


def test_validate_with_default_metadata():
    rule = """
rule dm_test {
    meta:
        sharing = "TLP:CLEAR"
        category = "TOOL"
        tool = "exemplar"
        description = "default metadata test"
    strings:
        $ = "test"
    condition:
        all of them
}
"""
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".yara", delete=False) as f:
        f.write(rule)
        f.flush()
        path = Path(f.name)

    try:
        cmd = [
            "cccs-yara",
            "--verbose=WARN",
            "validate",
            "-dm",
            '{"author": "TestAuthor", "source": "TestSource"}',
            "-o",
            "inplace",
            str(path),
        ]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        content = path.read_text()
        assert "TestAuthor" in content
        assert "TESTSOURCE" in content
    finally:
        path.unlink()


@pytest.mark.parametrize(
    "repository,paths",
    [
        ("https://github.com/BartBlaze/Yara-rules.git", [""]),
        ("https://github.com/kevoreilly/CAPEv2.git", ["analyzer/windows/data/yara", "data/yara"]),
    ],
    ids=["BartBlaze/Yara-rules", "kevoreilly/CAPEv2"],
)
def test_public_rulesets(repository, paths):
    """Test enrichment on a set of public YARA rules."""
    default_metadata = {"classification": "TLP:CLEAR", "source": repository.split("/", 4)[3]}
    with tempfile.TemporaryDirectory() as temp_dir:
        # Clone the repository to a temporary directory
        Repo.clone_from(repository, temp_dir, depth=1)

        # Run the CLI command to validate and enrich the rules in the cloned repository
        rule_paths = [os.path.join(temp_dir, p) for p in paths]
        cmd = [
            "cccs-yara",
            "validate",
            "-e",
            "-r",
            "--json",  # Product JSON report for analysis
            "-dm",  # Insert default metadata for enrichment
            json.dumps(default_metadata),
        ] + rule_paths
        p = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Ensure the command completed successfully
        assert p.returncode == 0

        # Check the statistics output to ensure that rules were processed
        with open("rule_validation_report.json", "r", encoding="utf-8") as f:
            report = json.load(f)
            valid_rules_percentage = report["valid"] / report["total"] * 100 if report["total"] > 0 else 0

            # Aiming for at least 90% of the rules to be valid after enrichment
            assert valid_rules_percentage >= 90.0, (
                f"Expected at least 90% valid rules, but got {valid_rules_percentage}%"
            )
