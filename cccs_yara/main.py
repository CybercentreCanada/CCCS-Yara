# Main entry point for the YARA validator package
import re
from functools import lru_cache
from typing import Dict, List, Tuple, Union

from plyara import Plyara
from plyara.utils import rebuild_yara_rule
from pydantic import BaseModel, ValidationError

from cccs_yara.validator import RuleValidatorModel


@lru_cache(maxsize=128)
def compile_aliases(pattern: str) -> re.Pattern:
    """Compile alias patterns for field aliases.

    Args:
        pattern (str): A regex pattern string to compile.

    Returns:
        re.Pattern: A compiled regex pattern.
    """
    return re.compile(pattern)


def validate_yara_rule(
    rule_content: Union[str, dict],
    default_metadata: dict = {},
    validator_model: BaseModel = RuleValidatorModel,
    field_aliases: Dict[str, str] = {"hash": "hash.*", "sharing": "classification", "date": "creation_date"},
    filename: str = "",
) -> List[Tuple[dict, List[dict]]]:
    """Validate a YARA rule file using the RuleValidatorModel.

    Args:
        rule_content (str): The content of the YARA rule file to validate.
        default_metadata (dict): Default metadata values to use if not present in the rule.
        validator_model (BaseModel): The Pydantic model to use for validation.
        field_aliases (dict): A dictionary of field aliases to use during validation.
        filename (str): The filename of the YARA rule file being validated.

    Returns:
        RuleValidatorModel: The validated YARA rule model.
    """
    if field_aliases:
        # Compile alias patterns
        field_aliases = {key: compile_aliases(pattern) for key, pattern in field_aliases.items()}

    if isinstance(rule_content, dict):
        # If the input is already a dict (parsed rule), validate directly
        try:
            rule_content["filename"] = filename
            rule_content.setdefault("metadata_kv", {})
            rule_content["original_kv"] = rule_content["metadata_kv"].copy()
            rule_content["metadata_kv"] = validator_model.model_validate(
                rule_content["metadata_kv"],
                context={
                    "rule": rule_content,
                    "default_metadata": default_metadata,
                    "aliases": field_aliases,
                },
            ).model_dump(exclude_none=True)
            return [(rule_content, [])]
        except ValidationError as e:
            return [(rule_content, e.errors())]
    else:
        p = Plyara(meta_as_kv=True)
        parsed_rules = p.parse_string(rule_content)
        validated_rules = []

        for rule in parsed_rules:
            try:
                rule.setdefault("metadata_kv", {})
                rule["original_kv"] = rule["metadata_kv"].copy()
                rule["filename"] = filename
                rule["metadata_kv"] = validator_model.model_validate(
                    rule["metadata_kv"],
                    context={"rule": rule, "default_metadata": default_metadata, "aliases": field_aliases},
                ).model_dump(exclude_none=True)
                validated_rules.append((rule, []))
            except ValidationError as e:
                validated_rules.append((rule, e.errors()))
        return validated_rules


def rebuild_rule(rule):
    new_metadata = []
    for key, value in rule["metadata_kv"].items():
        if isinstance(value, set):
            for v in value:
                new_metadata.append({key: v})
        else:
            new_metadata.append({key: value})
    rule["metadata"] = new_metadata
    return rebuild_yara_rule(rule)
