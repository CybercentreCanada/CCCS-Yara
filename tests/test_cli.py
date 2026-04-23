import subprocess
import tempfile
from pathlib import Path

import pytest


def test_info_command():
    result = subprocess.run(
        ["cccs-yara", "info"],
        capture_output=True,
        text=True,
    )

    # Assert that the command executed successfully
    assert result.returncode == 0


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

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        # Assert that the command executed successfully
        assert result.returncode == 0

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
        rule_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".yara", dir=temp_dir, delete=False)
        try:
            rule_file.write(rules)
            rule_file.flush()
            rule_file.close()

            result = subprocess.run(
                ["cccs-yara", "validate", "-o", "createfile", rule_file.name],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0

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
        rule_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".yara", dir=temp_dir, delete=False)
        try:
            rule_file.write(rules)
            rule_file.flush()
            rule_file.close()

            result = subprocess.run(
                ["cccs-yara", "validate", "-o", "splitrules", rule_file.name],
                capture_output=True,
                text=True,
            )

            assert result.returncode == 0

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
