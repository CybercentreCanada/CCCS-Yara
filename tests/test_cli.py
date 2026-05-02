import subprocess
import tempfile
from pathlib import Path

import pytest


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
