import re
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import time

import pytest
import yara

from yara_validator.validator import META_TRAILING_COMMENT, run_yara_validator

META = """        id = "4x6BuPD3vcf4PGXa7kb7Ll"
        fingerprint = "d63666d2e38b862af82b3cfa6f36a840f4aced801cd4d17518e881ee8e5b31fa"
        version = "1.0"
        date = "2026-08-20"
        modified = "2026-08-20"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "CCCS"
        author = "CCCS"
        description = "Fake rule for testing"
        category = "INFO"
        info = "TEST"
        reference = "Test\""""

# every comment style a section header can carry, the header regexes were anchored to the end of the
# line so each of these broke the match in the same way
COMMENT_STYLES = pytest.mark.parametrize(
    "comment",
    [" // single line", " /* inline block */", "// no space", "\t// tabbed", " /* two\n       lines */",
     " /* block */ // and a line comment"],
    ids=["single_line", "inline_block", "no_space", "tabbed", "two_line_block", "block_then_line"],
)


def build_rule(name="testing", meta_cmt="", strings_cmt="", cond_cmt="", strings=('$a = "Hello World"',)):
    body = "\n".join("        {string}".format(string=string) for string in strings)
    return """rule {name}
{{
    meta:{meta_cmt}
{META}

    strings:{strings_cmt}
{body}
    condition:{cond_cmt}
        any of them
}}
""".format(name=name, meta_cmt=meta_cmt, META=META, strings_cmt=strings_cmt, body=body, cond_cmt=cond_cmt)


def validate_in_place(source):
    # mirrors the call chain cli.py uses for the --in-place option
    with NamedTemporaryFile(suffix=".yar") as tf:
        tf.write(source.encode())
        tf.seek(0)

        processed_file = run_yara_validator(tf.name, generate_values=True)
        processed_file.strings_of_rules_to_original_file()
        Path(tf.name).write_text(processed_file.return_edited_file_string())

        return Path(tf.name).read_text()


def assert_rule_intact(original, rewritten):
    # only the metadata section may be altered by the rebuild and the result must still compile
    yara.compile(source=rewritten)
    for line in original.splitlines():
        stripped = line.strip()
        if stripped.startswith(("$", "strings:", "condition:", "rule ", "}")):
            assert stripped in rewritten


@COMMENT_STYLES
def test_comment_on_meta_header(comment):
    # the metadata offsets were left unset, which assigned a list to the validated rule
    source = build_rule(meta_cmt=comment)
    assert_rule_intact(source, validate_in_place(source))


@COMMENT_STYLES
def test_comment_on_strings_header_keeps_strings(comment):
    # the rebuild resumed at the condition section, deleting the strings section on the way
    source = build_rule(strings_cmt=comment, strings=('$a = "Hello World"', '$b = "Second"', "$c = { DE AD BE EF }"))
    rewritten = validate_in_place(source)

    assert "strings:" in rewritten
    for string_name in ("$a", "$b", "$c"):
        assert string_name + " = " in rewritten
    assert_rule_intact(source, rewritten)


@COMMENT_STYLES
def test_comment_on_condition_header(comment):
    source = build_rule(cond_cmt=comment)
    assert_rule_intact(source, validate_in_place(source))


def test_comments_on_every_header_at_once():
    # no clean header is left for the end of the metadata section to be found on
    source = build_rule(meta_cmt=" // m", strings_cmt=" // s", cond_cmt=" // c")
    assert_rule_intact(source, validate_in_place(source))


@pytest.mark.parametrize(
    "first_cmt,second_cmt",
    [(" // c", ""), ("", " // c"), (" // c", " // c")],
    ids=["first_rule", "second_rule", "both_rules"],
)
def test_multi_rule_file_keeps_every_rule(first_cmt, second_cmt):
    # the deletion was applied per rule and so compounded across a file
    source = (
        build_rule(name="ruleone", strings_cmt=first_cmt, strings=('$a = "Hello World"', '$b = "Second"'))
        + "\n"
        + build_rule(name="ruletwo", strings_cmt=second_cmt, strings=('$c = "Third"', '$d = "Fourth"'))
    )
    rewritten = validate_in_place(source)

    assert rewritten.count("strings:") == 2
    for string_name in ("$a", "$b", "$c", "$d"):
        assert string_name + " = " in rewritten
    assert_rule_intact(source, rewritten)


def test_comment_between_rules_is_preserved():
    source = build_rule(name="ruleone") + "\n// a comment between rules\n" + build_rule(name="ruletwo")
    rewritten = validate_in_place(source)

    assert "// a comment between rules" in rewritten
    assert_rule_intact(source, rewritten)


def test_header_comments_are_not_discarded():
    source = build_rule(meta_cmt=" // meta note", strings_cmt=" // strings note", cond_cmt=" // condition note")
    rewritten = validate_in_place(source)

    for note in ("// meta note", "// strings note", "// condition note"):
        assert note in rewritten


def test_repeated_runs_are_stable():
    # the run that deleted the strings reported the rule valid, only the next run reported it invalid
    source = build_rule(strings_cmt=" // note")
    with NamedTemporaryFile(suffix=".yar") as tf:
        tf.write(source.encode())
        tf.seek(0)

        previous = None
        for _ in range(3):
            processed_file = run_yara_validator(tf.name, generate_values=True)
            processed_file.strings_of_rules_to_original_file()
            Path(tf.name).write_text(processed_file.return_edited_file_string())
            current = Path(tf.name).read_text()

            assert "strings:" in current
            assert '$a = "Hello World"' in current
            yara.compile(source=current)
            if previous is not None:
                assert current == previous
            previous = current


def build_block_comment_rule(name="testing", commented_lines=("meta: // old header",)):
    commented = "\n".join("    {line}".format(line=line) for line in commented_lines)
    return """rule {name}
{{
    meta:
{META}
    /*
{commented}
    */

    strings: // a comment inside strings
        $a = "Hello World"
    condition: // condition note
        any of them
}}
""".format(name=name, META=META, commented=commented)


@pytest.mark.parametrize(
    "commented_lines",
    [("meta: // old header",), ("meta:",), ("strings:", "    a string that is commented out")],
    ids=["meta_header_with_comment", "meta_header", "strings_header"],
)
def test_commented_out_section_header_is_not_matched(commented_lines):
    # matching one moved the start of the metadata section inside the comment, and the splice then
    # dropped the closing delimiter of that comment
    source = build_block_comment_rule(commented_lines=commented_lines)
    rewritten = validate_in_place(source)

    # the block comment sits in the metadata section, which is regenerated, everything after it stays
    for note in ("// a comment inside strings", "// condition note"):
        assert note in rewritten
    assert_rule_intact(source, rewritten)


def build_unclosed_meta_header_rule(name="testing"):
    return """rule {name}
{{
    meta: /* opened on the header
    closed on the line below */
{META}

    strings: // a comment inside strings
        $a = "Hello World"
    condition:
        any of them
}}
""".format(name=name, META=META)


def test_block_comment_spanning_the_metadata_header_leaves_the_rule_alone():
    # the comment spans lines that are regenerated, so the rule is kept rather than rebuilt
    source = build_unclosed_meta_header_rule()

    assert validate_in_place(source).rstrip("\n") == source.rstrip("\n")


def test_quote_inside_a_block_comment_is_not_a_metadata_value():
    # the quote of the comment used to pair with the quote of the value, taking the */ between them
    stale = "0" * 64
    source = build_rule().replace(
        '        info = "TEST"', '        /* the 6" pipe */ info = "TEST"').replace(
        "d63666d2e38b862af82b3cfa6f36a840f4aced801cd4d17518e881ee8e5b31fa", stale)
    rewritten = validate_in_place(source)

    # the rule has to take the rebuild rather than be skipped, the regenerated fingerprint says so
    assert stale not in rewritten
    assert_rule_intact(source, rewritten)


def test_delimiter_inside_a_metadata_value_is_not_a_comment():
    source = build_rule().replace('info = "TEST"', 'info = "TEST /* not a comment"')
    rewritten = validate_in_place(source)

    assert '$a = "Hello World"' in rewritten
    assert_rule_intact(source, rewritten)


def test_fallback_does_not_write_the_plyara_rebuild():
    # that rebuild carries the imports of the file and the spacing plyara regenerates
    source = 'import "pe"\n\n' + build_unclosed_meta_header_rule().replace(
        "        any of them", "        pe.number_of_sections == 1")
    rewritten = validate_in_place(source)

    assert rewritten.count('import "pe"') == 1
    assert rewritten.rstrip("\n") == source.rstrip("\n")


def test_rule_without_a_section_header_of_its_own_is_left_alone():
    # a condition sharing its line with the header is valid YARA the splice cannot handle
    source = build_rule().replace(
        "    strings:\n        $a = \"Hello World\"\n", "").replace(
        "    condition:\n        any of them", "    condition: filesize < 100KB")

    assert validate_in_place(source).rstrip("\n") == source.rstrip("\n")


def test_meta_header_with_many_block_comments_does_not_hang():
    # a .* nested in the repetition of the header regex backtracks on a header that fails to match
    line = "    meta:" + " /* c */" * 200 + " not a comment"
    started = time()

    assert not re.match(r"^\s*meta\s*:" + META_TRAILING_COMMENT, line)
    assert time() - started < 1
