#! /usr/bin/env python3

import argparse
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path
from textwrap import dedent
from typing import List, Tuple

from cccs_yara.enrichment import Enricher
from cccs_yara.main import rebuild_rule, validate_yara_rule
from cccs_yara.validator import RuleValidatorModel

# Colors for terminal output
COLOUR_SUCCESS = "\033[92m"
COLOUR_WARNING = "\033[93m"
COLOUR_FAIL = "\033[91m"
COLOUR_ENDC = "\033[0m"


SUPPORTED_FILE_EXTENSIONS = [".yar", ".yara", ".rules"]
YARA_FILENAME_REGEX = re.compile(rf"({'|'.join(SUPPORTED_FILE_EXTENSIONS)})$".replace(".", r"\."))


@lru_cache(maxsize=128)
def get_rule_content(path: Path) -> str:
    """Reads and returns the content of a YARA rule file.

    Args:
        path (Path): The path to the YARA rule file.

    Returns:
        str: The content of the YARA rule file.
    """
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def get_paths_to_validate(options_paths: List[str], recursive: bool) -> List[Path]:
    """Returns a set of pathlib.Path objects for all YARA rules that will be validated."""
    paths_to_validate = set()

    for path in [Path(path_name) for path_name in options_paths]:
        # If given path is a directory, look for .rules or .yara files inside
        if path.exists():
            if path.is_dir():
                glob_pattern = "**/*" if recursive else "*"
                for supported_ext in SUPPORTED_FILE_EXTENSIONS:
                    paths_to_validate.update(path.glob(f"{glob_pattern}{supported_ext}"))
            elif YARA_FILENAME_REGEX.match(path.suffix):
                paths_to_validate.add(path)
        else:
            print("{message:40}{path}".format(message="Path does not exist:", path=str(path)))

    return sorted(paths_to_validate)


# Print the YARA standard based on the Pydantic model
def print_standard(validator_model: RuleValidatorModel):
    print("Printing the CCCS YARA Standard:")

    schema = validator_model.model_json_schema()
    # Iterate through the properties and print their details
    for property_name, property_info in schema["properties"].items():
        # Set terminal color based on whether the property is required
        if property_name in schema.get("required", []):
            print(COLOUR_FAIL)
        else:
            print(COLOUR_WARNING)
        print(f"{property_name} [{'Required' if property_name in schema.get('required', []) else 'Optional'}]")
        for property_key, property_value in property_info.items():
            if property_key == "title":
                continue
            if property_key == "default" and property_value is None:
                continue
            if property_key == "anyOf" and {"type": "null"} in property_value:
                property_data = property_value[0]
                field_type = property_data["type"]
                if field_type == "array":
                    field_type += f" of {property_data['items']['type']}"
                print(f"  type: {field_type}")
                if "pattern" in property_data.get("items", {}):
                    print(f"  pattern: {property_data['items']['pattern']}")
            else:
                print(f"  {property_key}: {property_value}")

    # Reset terminal color
    print(COLOUR_ENDC)


def process_rule_file(
    yara_rule_path: Path,
    options: argparse.Namespace,
    validator_kwargs: dict,
    enricher: Enricher,
    logger: logging.Logger,
) -> Tuple[int, int]:
    total = 0
    failed = 0

    logger.info(
        "{message:40}{y_file}".format(
            message="Validating Rule file:",
            y_file=yara_rule_path,
        )
    )

    yara_rule_content = get_rule_content(yara_rule_path)
    for rule, errors in validate_yara_rule(yara_rule_content, **validator_kwargs)[::-1]:
        total += 1
        # If ignoring private rules and the rule is private, skip validation
        if options.ignore_private_rules and "private" in rule.get("scopes", []):
            logger.warning(
                f"{COLOUR_WARNING}   Skipping Private Rule: {yara_rule_path}:{rule['rule_name']}{COLOUR_ENDC}"
            )
            continue

        if errors and enricher:
            rule["metadata_kv"] = rule.get("original_kv", {}).copy()
            enricher.enrich_yara_rule(rule)
            rule, errors = validate_yara_rule(rule, **validator_kwargs)[0]

        # Here you can handle each rule and its associated errors
        if errors:
            failed += 1
            logger.error(
                f"{COLOUR_FAIL}🍩 Invalid Rule File: {yara_rule_path}:{rule['start_line']} ({rule['rule_name']}){COLOUR_ENDC}"
            )
            for error in errors:
                logger.error(f"  - `{error['loc'][0]}` is invalid: {error['msg']}")
        else:
            # Print valid rule only
            logger.info(
                f"{COLOUR_SUCCESS}   Valid Rule File: {yara_rule_path}:{rule['start_line']} ({rule['rule_name']}){COLOUR_ENDC}"
            )

        # If no changes flag is set, skip writing changes but print what the changes would be
        original_metadata = rule.get("metadata", [])
        new_metadata = []
        for key, value in rule["metadata_kv"].items():
            if isinstance(value, set):
                for v in value:
                    new_metadata.append({key: v})
            else:
                new_metadata.append({key: value})
        additions = [item for item in new_metadata if item not in original_metadata]
        removals = [item for item in original_metadata if item not in new_metadata]

        if additions or removals:
            logger.warning(
                f"{COLOUR_WARNING}🔧 Proposed Changes for: {yara_rule_path}:{rule['rule_name']} based on enrichment"
            )
            for change in new_metadata + removals:
                key, value = list(change.items())[0]

                color = COLOUR_ENDC
                symbol = " "
                if change in additions:
                    color = COLOUR_SUCCESS
                    symbol = "+"
                elif change in removals:
                    color = COLOUR_FAIL
                    symbol = "-"

                logger.warning(f"{color}  {symbol} {key} = {value}{COLOUR_ENDC}")

        if options.output == "inplace" and not errors:
            # Change the rule content in place using the start and stop lines
            yara_rule_content_lines = yara_rule_content.splitlines()
            rule_start_line = rule.get("start_line", 1) - 1
            rule_stop_line = rule.get("stop_line", len(yara_rule_content_lines))

            # Remove imports from rule before rebuilding
            rule.pop("imports", None)

            new_rule_content = rebuild_rule(rule)
            new_rule_content_lines = new_rule_content.splitlines()
            yara_rule_content_lines = (
                yara_rule_content_lines[:rule_start_line]
                + new_rule_content_lines
                + yara_rule_content_lines[rule_stop_line:]
            )
            yara_rule_content = "\n".join(yara_rule_content_lines)

    # After processing all rules in the file, write changes if applicable
    if options.output == "inplace":
        # Write changes back to the original file
        logger.debug(f"Writing changes in place to file: {yara_rule_path}")
        with open(yara_rule_path, "w", encoding="utf-8") as f:
            f.write(yara_rule_content)
    elif options.output == "createfile":
        # Write changes to a new file
        new_file_path = yara_rule_path.with_name(f"{yara_rule_path.stem}_validated{yara_rule_path.suffix}")
        logger.debug(f"Writing validated rule to new file for: {new_file_path}")
        with open(new_file_path, "w", encoding="utf-8") as f:
            f.write(rebuild_rule(rule))

    return total, failed


def execute_command(options):
    # Retrieve the JSON schema from the Pydantic model
    logger = logging.getLogger(__name__)
    logger.handlers = [logging.StreamHandler()]
    logger.setLevel(getattr(logging, options.verbose))

    if options.validator:
        # If a custom validator model is provided, import and use it
        logger.debug(f"Using custom validator model: {options.validator}")
        module_path, model_name = options.validator.split(":")
        module = __import__(module_path, fromlist=[model_name])
        validator_model = getattr(module, model_name)
    else:
        logger.debug(f"Using default validator model: {RuleValidatorModel.__name__}")
        validator_model = RuleValidatorModel

    if options.command == "info":
        # Print the YARA standard if requested
        logger.debug("Preparing to print the YARA standard...")
        print_standard(validator_model)
    elif options.command == "validate":
        logger.debug("Preparing to validate YARA rules...")

        logger.debug("Gathering YARA rules to validate...")
        paths_to_validate = get_paths_to_validate(options.paths, options.recursive)

        total_analyzed = 0
        total_failed = 0

        enricher = None
        if options.enrich:
            logger.debug("Initializing YARA rule enricher...")
            enricher = Enricher()

        default_metadata = {}
        if options.default_metadata:
            try:
                logger.debug("Parsing default metadata JSON...")
                default_metadata = json.loads(options.default_metadata)
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing default metadata JSON: {e}")
                return

        # Validate each YARA rule file
        with ThreadPoolExecutor() as executor:
            futures = {
                yara_rule_path: executor.submit(
                    process_rule_file,
                    yara_rule_path,
                    options,
                    dict(
                        validator_model=validator_model,
                        default_metadata=default_metadata,
                        filename=yara_rule_path.name,
                    ),
                    enricher,
                    logger,
                )
                for yara_rule_path in list(paths_to_validate)
            }

            for yara_rule_path, future in futures.items():
                try:
                    total, failed = future.result()
                    total_analyzed += total
                    total_failed += failed
                except Exception as e:
                    logger.error(f"Error processing YARA rule file ({yara_rule_path}): {e}")

        total_valid = total_analyzed - total_failed
        valid_percentage = (total_valid / total_analyzed * 100) if total_analyzed > 0 else 0
        invalid_percentage = (total_failed / total_analyzed * 100) if total_analyzed > 0 else 0

        logger.error(
            dedent(f"""{COLOUR_ENDC}
        ----------------------------------------------------------------------------
        Statistics:
            Total Yara Rules Analyzed:  {total_analyzed}
            Valid Yara Rules:           {COLOUR_SUCCESS}{total_valid} ({valid_percentage:.2f}%){COLOUR_ENDC}
            Invalid Yara Rules:         {COLOUR_FAIL}{total_failed} ({invalid_percentage:.2f}%){COLOUR_ENDC}
        ---------------------------------------------------------------------------
        """)
        )


def main():
    print("""\
      ____ ____ ____ ____   __   __ _    ____      _
     / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \\
    | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \\
    | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \\
     \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\\
     """)

    # Defining the parser and arguments to parse,
    parser = argparse.ArgumentParser(description="CCCS YARA CLI to validate and enrich YARA rules.")
    # Be able to specify a custom validator model
    parser.add_argument(
        "--validator",
        type=str,
        default=None,
        required=False,
        dest="validator",
        help="Path to Pydantic model configuration, i.e. yara_validator.validator:RuleValidatorModel",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        choices=["INFO", "DEBUG", "WARN", "ERROR"],
        default="ERROR",
        dest="verbose",
        help="Control the verbosity of logging output. Options are INFO, DEBUG, WARN, ERROR. "
        "Default is ERROR to track only errors. "
        "WARN to track warnings and errors such as proposed changes. "
        "INFO to track high-level processing information. "
        "DEBUG to track detailed debugging information.",
    )

    subparsers = parser.add_subparsers(title="subcommands", dest="command")

    # Info command to display YARA standard information for diagnostic purposes
    subparsers.add_parser("info", help="Display information about the YARA validator.")

    # Validate command to validate YARA rules against the CCCS YARA standard
    validate_command = subparsers.add_parser("validate", help="Validate YARA rules against the CCCS YARA standard.")
    validate_command.add_argument(
        "paths", nargs="*", type=str, default=[], help="A list of files or folders to be enriched."
    )

    validate_command.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        default=False,
        dest="recursive",
        help="Recursively search folders provided.",
    )
    validate_command.add_argument(
        "-e",
        "--enrich",
        action="store_true",
        default=False,
        dest="enrich",
        help="Enrich the YARA rules with additional metadata from knowledge sources.",
    )
    validate_command.add_argument(
        "-dm",
        "--default-metadata",
        type=str,
        default="",
        dest="default_metadata",
        help="A JSON string representing default metadata to apply to rules during validation.",
    )
    validate_command.add_argument(
        "-o",
        "--output",
        choices=["inplace", "createfile"],
        required=False,
        dest="output",
        help="Decide how to handle output of validated rules. "
        "Options are 'inplace' to modify files in place and "
        "'createfile' to write validated rules to new files named after the rule.",
    )
    validate_command.add_argument(
        "--ignore-private-rules",
        action="store_true",
        default=False,
        dest="ignore_private_rules",
        help="Ignore private rules during validation.",
    )
    args = parser.parse_args()
    if not args.command:
        # If no command is provided, print help message
        parser.print_help()
    elif args.command == "validate" and not args.paths:
        print("No paths provided to validate. Use --help for more information.")
    else:
        # Otherwise, call the main function with the provided options
        execute_command(args)


if __name__ == "__main__":
    main()
