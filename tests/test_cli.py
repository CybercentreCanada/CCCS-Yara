import subprocess
import tempfile

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
