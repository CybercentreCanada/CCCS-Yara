import plyara.utils
from pathlib import Path
import collections
import yaml
import re

# for querying the MITRE ATT&CK data
from stix2 import FileSystemSource
from stix2 import Filter
from cfg.filter_casefold import FilterCasefold
from validator_functions import Validators, TagOpt

# set current working directory
SCRIPT_LOCATION = Path(__file__).resolve().parent
MITRE_STIX_DATA_PATH= SCRIPT_LOCATION.parent / 'cti/enterprise-attack'
VALIDATOR_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_Yara_values.yml'
CONFIGURATION_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_Yara.yml'

# constants to deal with various required string comparisons
SCOPES = 'scopes'
GLOBAL = '^global$'
ASCII = 'ascii'

# constants to store the string tag used to reference to particular important tags
METADATA = 'metadata'
REPORT = 'report'
HASH = 'hash'
ACTOR = 'actor'
AUTHOR = 'author'


"""
RUN THE VALIDATOR BY CALLING THIS FUNCTION IF YOU ARE NOT USING THE cccs_yara.py script
"""
def run_yara_validator(yara_file):
    """
    This is the base function that should be called to validate a rule. It will take as an argument the file path,
        create a YaraValidator object, parse that file with plyara and pass that parsed object and the string representation
        of the yara file to YaraValidator.valadation

        NOTE the current function assumes one rule per file and will only process the first rule found.
    :param yara_file:
    :return:
    """
    validator = YaraValidator()

    parser = plyara.Plyara()
    yara_rule_file = open(yara_file, encoding='utf-8')
    yara_rule_file_string = yara_rule_file.read()
    rule0 = parser.parse_string(yara_rule_file_string)[0]
    yara_rule_file.close()
    rule_return = validator.validation(rule0, yara_rule_file_string)

    return rule_return

class YaraValidatorReturn:
    """
    YaraValidatorReturn class used to pass the validity of the processed rules, what metadata tags have issues if not valid,
        a string representation of the original rule and if the rule is valid a string representation of the valid rule
        with all the created metadata tags, etc.
    """
    def __init__(self, original_rule):
        # Overall rule validity flag
        self.rule_validity = True
        # each possible metadata tag
        self.metadata_tags = collections.OrderedDict()
        # Overall warning flag
        self.rule_warnings = False
        # collection of all the warnings
        self.warnings = collections.OrderedDict()
        # the original_rule
        self.rule_to_validate = original_rule
        # set
        self.validated_rule = None

    def update_validity(self, rule_validity, metadata_tag, message):
        if self.rule_validity:
           self.rule_validity = rule_validity

        self.metadata_tags[metadata_tag] = message

    def update_warning(self, rule_warning, warning_tag, message):
        if not self.rule_warnings:
            self.rule_warnings = rule_warning

        self.warnings[warning_tag] = message

    def __build_return_string(self, collection):
        return_string = ""
        for index, tag in enumerate(collection):
            if index > 0:
                return_string = return_string + "\n"
            return_string = return_string + tag + ": " + collection[tag]

        return return_string

    def __build_return_string_cmlt(self, collection):
        return_string = ""
        for index, tag in enumerate(collection):
            if index > 0:
                return_string = return_string + "\n"
            return_string = return_string + "{indent:>9}{tag:30} {collection}".format(indent="- ", tag=tag + ":", collection=collection[tag])

        return return_string

    def return_errors(self):
        error_string = ""
        if not self.rule_validity:
            error_string = self.__build_return_string(self.metadata_tags)

        return error_string

    def return_errors_for_cmlt(self):
        error_string = ""
        if not self.rule_validity:
            error_string = self.__build_return_string_cmlt(self.metadata_tags)

        return error_string

    def return_warnings(self):
        warning_string = ""
        if self.rule_warnings:
            warning_string = self.__build_return_string(self.warnings)

        return warning_string

    def return_warnings_for_cmlt(self):
        warning_string = ""
        if self.rule_warnings:
            warning_string = self.__build_return_string_cmlt(self.warnings)

        return warning_string

    def return_original_rule(self):
        return self.rule_to_validate

    def return_validated_rule(self):
        return self.validated_rule

    def set_validated_rule(self, valid_rule):
        self.validated_rule = valid_rule

    def __find_meta_start_end(self, rule_to_process):
        """
        A string representation of a yara rule is passed into this function, it performs the splitlines() function,
            searches for the start and the end indexes of the meta section of the first yara rule.
        :param rule_to_process: The Rule to be processed
        :return: a tuple of the array of lines for the rule processed, the start of meta index and the end of meta index
        """
        rule_to_process_lines = rule_to_process.splitlines()
        rule_start = 0
        rule_end = 0
        meta_regex = "^\s*meta\s*:\s*$"
        next_section = "^\s*strings\s*:\s*$"

        for index, line in enumerate(rule_to_process_lines):
            if rule_start > 0:
                if re.match(next_section, line):
                    rule_end = index
                    break
            else:
                if re.match(meta_regex, line):
                    rule_start = index

        return rule_to_process_lines, rule_start, rule_end

    def rebuild_rule(self):
        """
        Rebuilds the rule if it is valid and as long as there are any changes. This was created to maintain
            any comments outside of the metadata section
        :return: No return
        """
        if self.validated_rule[-1] == '\n':
            self.validated_rule = self.validated_rule[:-1]

        if self.rule_to_validate is None or self.validated_rule is None:
            exit()
        elif self.rule_to_validate == self.validated_rule:
            return

        yara_valid_lines, yara_valid_meta_start, yara_valid_meta_end = self.__find_meta_start_end(self.rule_to_validate)
        yara_cccs_lines, yara_cccs_meta_start, yara_cccs_meta_end = self.__find_meta_start_end(self.validated_rule)

        if yara_valid_meta_start != 0 and yara_valid_meta_end != 0 and yara_cccs_meta_start != 0 and yara_cccs_meta_end != 0:
            yara_new_file = yara_valid_lines[0:yara_valid_meta_start] + yara_cccs_lines[yara_cccs_meta_start:yara_cccs_meta_end] + yara_valid_lines[yara_valid_meta_end:]
            yara_new_file = "\n".join(yara_new_file)
            if self.rule_to_validate != yara_new_file:
                self.validated_rule = yara_new_file

class TagAttributes:
    """
    TagAttributes class is used to populate the YaraValidator.required_fields dict and stores values such as the type of method used to
        validate the given metadata tag, regex expression or funcion name used to verify, the optionality of the metadata tag,
        the max count of the metadata tag and the position of the matching Positional object in the YaraValidator.required_fields_index
    """
    function = None
    argument = None
    optional = None
    max_count = None
    position = None
    found = False
    valid = False

    def __init__(self, tag_validator, tag_optional, tag_max_count, tag_position, tag_argument):
        self.function = tag_validator
        self.argument = tag_argument
        self.optional = tag_optional
        self.max_count = tag_max_count
        self.position = tag_position

    def attributefound(self):
        self.found = True

    def attributevalid(self):
        self.valid = True

    def attributeinvalid(self):
        self.valid = False

    def attributereset(self):
        self.found = False
        self.valid = False

class Positional:
    """
    Positional class used to create positional objects for the YaraValidator.required_fields_index. This allows for tracking the count
        of each metadata tag found and the relative start and end positions given the canonical order
    """
    def __init__(self, position_index, position_count = 0):
        self.starting_index = position_index
        self.count = position_count
        self.current_offset = 0

    def set_values(self, position_index, position_count = 0):
        self.starting_index = position_index
        self.count = position_count
        self.current_offset = 0

    def increment_count(self):
        self.count = self.count + 1

    def increment_offset(self):
        self.current_offset = self.current_offset + 1
        if self.current_offset >= self.count:
            self.current_offset = 0

    def reindex(self, previous_values):
        self.starting_index = previous_values[0] + previous_values[1]

    def current_values(self):
        return self.starting_index, self.count

    def index(self):
        return self.starting_index + self.current_offset

class YaraValidator:
    """
    Class for YaraValidator that does most of the work for validating yara rules to the CCCS Yara Standard
    """
    previous_position_values = None

    def reindex_metadata_tags(self):
        """
        Reindex the starting index of the positional objects contained in self.required_fields_index. This is so that
            the canonical order is maintained relative to optional and multiple instances of some metadata
        :return: none, it works on the self.required_fields_index and makes changes to that
        """
        previous_position_values = None

        for position_index, position in enumerate(self.required_fields_index):
            if position_index > 0:
                position.reindex(previous_position_values)

            previous_position_values = position.current_values()

    def resort_metadata_tags(self, rule_to_sort):
        """
        Resorts the array of metadata tags for valid rules into the canonical order
        :param rule_to_sort: the plyara parsed rule that is being validated
        :return: No return, it simply replaces the rules metadata array with the sorted array
        """
        metadata_tags = rule_to_sort[METADATA]
        correct_order = [None] * len(metadata_tags)
        tracking_added = 0
        tracking_left = 0
        for tag in list(metadata_tags):
            if len(tag.keys()) == 1:
                key = list(tag.keys())[0]
                value = list(tag.values())[0]

                if key in self.required_fields:
                    positional = self.required_fields_index[self.required_fields[key].position]
                    correct_order[positional.index()] = metadata_tags.pop(tracking_left)
                    positional.increment_offset()
                    tracking_added = tracking_added + 1
                elif key in self.required_fields_children:
                    positional = self.required_fields_index[self.required_fields_children[key].position]
                    correct_order[positional.index()] = metadata_tags.pop(tracking_left)
                    positional.increment_offset()
                    tracking_added = tracking_added + 1
                else:
                    tracking_left = tracking_left + 1
            else:
                tracking_left = tracking_left + 1

        # takes all unrecognized or multivalue metadata and appends them to the end of the array of metadata
        for tag in list(metadata_tags):
            correct_order[tracking_added] = metadata_tags.pop(0)
            tracking_added = tracking_added + 1

        rule_to_sort[METADATA] = correct_order

    def process_key(self, key, fields, rule_processing_key, tag_index):
        """
        The primary function that determines how to treat a specific metadata tag for validation, it will either call
            the function or perform the regex comparison
        :param key: the name of the metadata tag that is being processed
        :param fields: the dictonary of metadata tags to check against this can differ depending on where validation is in the process
        :param rule_processing_key: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the key being processed is
        :return:
        """
        if not fields[key].function(rule_processing_key, tag_index, key):
            rule_response = "Field has Invalid Value:\t" + str(rule_processing_key[METADATA][tag_index][key])
            return False, rule_response
        return True, ""

    def is_ascii(self, rule_string):
        """
        Takes the string of the rule and parses it to check if there are only ascii characters present.
        :param rule_string: the string representation of the yara rule
        :return: true if there are only ascii characters in the string
        """
        return len(rule_string) == len(rule_string.encode())

    def validation(self, rule_to_validate, rule_to_validate_string):
        """
        Called to validate a yara rule. This is the primary function.
        :param rule_to_validate: the plyara parsed rule that is being validated
        :param rule_to_validate_string: the string representation of the yara rule to verify, this is passed to the YaraValidatorReturn object for use later
        :return: the valid object of the YaraValidatorReturn class
        """
        valid = YaraValidatorReturn(rule_to_validate_string)

        if not METADATA in rule_to_validate:
            valid.update_validity(False, METADATA, "No Metadata Present")
            return valid

        if not self.is_ascii(rule_to_validate_string):
            valid.update_validity(False, ASCII, "There are Non-ASCII Characters Present in the Rule.")
            return valid

        if SCOPES in rule_to_validate:
            for scope in rule_to_validate[SCOPES]:
                if re.match(GLOBAL, scope):
                    valid.update_validity(False, SCOPES, "This is a Global Rule.")
                    return valid

        metadata_tags = rule_to_validate[METADATA]
        index_of_empty_tags = []
        tags_not_initially_found = []
        for tag_index, tag in enumerate(metadata_tags):
            if len(tag.keys()) == 1:
                key = list(tag.keys())[0]
                value = list(tag.values())[0]

                if value == '':
                    index_of_empty_tags.append(tag_index)
                elif key in self.required_fields:
                    validity, rule_response = self.process_key(key, self.required_fields, rule_to_validate, tag_index)
                    if not validity:
                        valid.update_validity(validity, key, rule_response)
                elif str(key).lower() in self.required_fields:
                    valid.update_warning(True, key, "Warning, this metadata tag would be validated if it were lowercase.")
                else:
                    tag_index_and_tag = {key: tag_index}
                    tags_not_initially_found.append(tag_index_and_tag)

        tags_not_initially_found.reverse()
        for tag_to_check in tags_not_initially_found:
            if len(tag_to_check.keys()) == 1:
                key_to_match = list(tag_to_check.keys())[0]
                metadata_tag_index = list(tag_to_check.values())[0]

                tag = rule_to_validate[METADATA][metadata_tag_index]
                if len(tag.keys()) == 1:
                    key = list(tag.keys())[0]
                    value = list(tag.values())[0]

                    if key in self.required_fields_children:
                        validity, rule_response = self.process_key(key, self.required_fields_children, rule_to_validate, metadata_tag_index)
                        if not validity:
                            valid.update_validity(validity, key, rule_response)

        for empty_tag in sorted(index_of_empty_tags, reverse=True):
            if list(rule_to_validate[METADATA][empty_tag].values())[0] == '':
                metadata_tags.pop(empty_tag)

        self.generate_required_optional_tags(rule_to_validate)

        for key, value in self.required_fields.items():
            if not value.found and not str(key).upper() in self.category_types:
                if value.optional == TagOpt.REQ_PROVIDED:
                    valid.update_validity(False, key, "Missing Required Metadata Tag")
                #else:
                    #valid.update_warning(True, key, "Optional Field Not Provided")
            else:
                if self.required_fields_index[value.position].count > value.max_count and value.max_count != -1:
                    valid.update_validity(False, key, "Too Many Instances of Metadata Tag.")

        if valid.rule_validity:
            self.reindex_metadata_tags()
            self.resort_metadata_tags(rule_to_validate)
            valid.set_validated_rule(plyara.utils.rebuild_yara_rule(rule_to_validate))
            valid.rebuild_rule()

        self.warning_check(rule_to_validate, valid)

        return valid

    def warning_check(self, rule_to_check, valid):
        """
        Loops through all of the potential warning functions.
        :param rule_to_check: the finalized rule
        :param valid: the rule's YaraValidatorReturn
        :return:
        """
        for warning in self.warning_functions:
            warning(rule_to_check, valid)

    def warning_author_no_report_check(self, rule_to_check, valid):
        if self.required_fields.get(AUTHOR) and self.required_fields.get(REPORT):
            if self.required_fields[AUTHOR].found and not self.required_fields[REPORT].found:
                metadata_tags = rule_to_check[METADATA]
                for tag in metadata_tags:
                    if len(tag.keys()) == 1:
                        key = list(tag.keys())[0]
                        value = list(tag.values())[0]
                        if key == AUTHOR and (value == "RevEng@CCCS" or value == "reveng@CCCS"):
                            valid.update_warning(True, REPORT, "Rule is authored by the CCCS but no report is referenced.")

    def warning_author_no_hash_check(self, rule_to_check, valid):
        if self.required_fields.get(AUTHOR) and self.required_fields.get(HASH):
            if self.required_fields[AUTHOR].found and not self.required_fields[HASH].found:
                metadata_tags = rule_to_check[METADATA]
                for tag in metadata_tags:
                    if len(tag.keys()) == 1:
                        key = list(tag.keys())[0]
                        value = list(tag.values())[0]
                        if key == AUTHOR and value == "RevEng@CCCS":
                            valid.update_warning(True, HASH, "Rule is authored by the CCCS but no hash is referenced.")

    def warning_actor_no_mitre_group(self, rule_to_check, valid):
        if self.required_fields.get(ACTOR) and self.required_fields[ACTOR].argument.get("child_place_holder"):
            place_holder = self.required_fields[ACTOR].argument.get("child_place_holder")
            if self.required_fields[ACTOR].found and not self.required_fields[place_holder].found:
                metadata_tags = rule_to_check[METADATA]
                for tag in metadata_tags:
                    if len(tag.keys()) == 1:
                        key = list(tag.keys())[0]
                        value = list(tag.values())[0]
                        if key == ACTOR:
                            warning_message = "Actor: " + value + " was not found in MITRE ATT&CK dataset."
                            valid.update_warning(True, ACTOR, warning_message)

    def generate_required_optional_tags(self, rule_to_validate):
        req_optional_keys = self.return_req_optional()

        for key in req_optional_keys:
            if not self.required_fields[key].found:
                if self.required_fields[key].function == self.validators.valid_regex:
                    self.required_fields[key].attributefound()
                else:
                    self.required_fields[key].function(rule_to_validate, self.required_fields_index[self.required_fields[key].position].index(), key)

    def return_req_optional(self):
        keys_to_return = []
        for key in self.required_fields.keys():
            if self.required_fields[key].optional == TagOpt.REQ_OPTIONAL:
                if not self.required_fields[key].found:
                    keys_to_return.append(key)

            if self.__mitre_group_alias() and self.required_fields[ACTOR].found:
                keys_to_return.append(self.required_fields[ACTOR].argument.get("child_place_holder"))
            return keys_to_return

    def __mitre_group_alias(self):
        """
        Private function to return the value of mitre_group_alias which would be set if any actor value was found
        :return: the value of the validators.mitre_group_alias variable
        """
        return self.validators.mitre_group_alias

    def __parse_scheme(self, cfg_to_parse):
        cfg_being_parsed = ""
        for index, cfg in enumerate(self.scheme[cfg_to_parse]):
            if index > 0:
                cfg_being_parsed = cfg_being_parsed + "|"

            cfg_being_parsed = cfg_being_parsed + "^" + str(cfg['value']) + "$"

        return cfg_being_parsed

    def handle_child_parent_tags(self, tag, params, tags_in_child_parent_relationship, place_holder="_child"):
        """
        Child tags create TagAttributes instances as temporary place holders in self.required_fields and
        the place holders will be used to create the actual TagAttributes instances in self.required_fields_children.
        This method creates a place holder for a child tag and adds the name of the place holder to a parent tag.
        :param tag: string name of a tag in CCCS_Yara.yml file
        :param params: parameters of the corresponding tag in a dictionary format
        :param place_holder: string to be attached to a tag name -> will be used as a place holder name
        :param tags_in_child_parent_relationship: list of tags that contain either parent or child argument
        :return: void
        """
        argument = params.get("argument")
        if argument:
            if argument.get("parent"):
                self.required_fields[tag + place_holder] = self.required_fields.pop(tag)
                tags_in_child_parent_relationship.append(argument.get("parent"))
            elif argument.get("child"):
                child_tag = argument["child"]
                argument.update({"child_place_holder": child_tag + place_holder})
                tags_in_child_parent_relationship.append(argument.get("child"))

    def validate_child_parent_tags(self, configuration, tags_in_child_parent_relationship):
        """
        Checks if any tags in child-parent relationships are missing from CCCS_Yara.yml configuration page
        :param configuration: CCCS_Yara.yml configuration in dictionary format
        :param tags_in_child_parent_relationship: a list of tags in child-parent relationships
        :return: void
        """
        for tag in tags_in_child_parent_relationship:
            if configuration.get(tag) is None:
                print("CCCS_Yara.yml: \"" + tag + "\" is required (in a child-parent relationship)")
                exit(1)

    def read_regex_values(self, file_name, regex_tag):
        """
        Parses multiple values under the name "regex_tag" from given YAML file to make a single line of expression
        :param file_name: name of the file to reference
        :param regex_tag: name of the tag in the file that contains multiple regex expressions
        :return: single line of regex expression
        """
        regex_yaml_path = SCRIPT_LOCATION.parent / file_name
        with open(regex_yaml_path, "r") as yaml_file:
            scheme = yaml.safe_load(yaml_file)

        cfg_being_parsed = ""
        for index, cfg in enumerate(scheme[regex_tag]):
            if index > 0:
                cfg_being_parsed = cfg_being_parsed + "|"

            cfg_being_parsed = cfg_being_parsed + "^" + str(cfg['value']) + "$"

        return cfg_being_parsed

    def read_yara_cfg(self, tag, params, tag_position):
        """
        Creates a TagAttributes object for self.required_fields based on the CCCS_Yara.yml configuration
        :param tag: string name of a tag in CCCS_Yara.yml file
        :param params: parameters of the corresponding metadata tag in dictionary format
        :param tag_position: index (position) of the key in CCCS_Yara.yml file
        :return: TagAttributes instance
        """
        # parameters for creating a TagAttributes instance
        tag_max_count = None
        tag_optional = None
        tag_validator = None
        tag_argument = None

        # check if the tag is optional
        optional = params.get("optional")
        if optional is not None:
            if optional is True or re.fullmatch("(?i)^y$|yes", str(optional)):
                tag_optional = TagOpt.OPT_OPTIONAL
            elif optional is False or re.fullmatch("(?i)^n$|no", str(optional)):
                tag_optional = TagOpt.REQ_PROVIDED
            elif re.fullmatch("(?i)optional", str(optional)):
                tag_optional = TagOpt.REQ_OPTIONAL
            else:
                print("CCCS_Yara.yml: \"" + tag + "\" has an invalid parameter - optional")
                exit(1)
        else:
            print("CCCS_Yara.yml: \"" + tag + "\" has a missing parameter - optional")
            exit(1)

        # check if the tag is unique
        unique = params.get("unique")
        if unique is not None:
            if unique is True or re.fullmatch("(?i)^y$|yes", str(unique)):
                tag_max_count = 1
            elif unique is False or re.fullmatch("(?i)^n$|no", str(unique)):
                tag_max_count = -1
            elif isinstance(unique, int):
                tag_max_count = unique
            else:
                print("CCCS_Yara.yml: \"" + tag + "\" has an invalid parameter - unique")
                exit(1)
        else:
            print("CCCS_Yara.yml: \"" + tag + "\" has a missing parameter - unique")
            exit(1)

        # check which validator to use
        if params.get("validator"):  # validate the corresponding tag using the "validator"
            tag_validator = self.validators.names.get(params["validator"])
            if not tag_validator:
                print("CCCS_Yara.yml: Validatior \"" + params["validator"] + "\" of \"" + tag + "\" is not defined")
                exit(1)

            tag_argument = params.get("argument")

            if tag_validator == self.validators.valid_regex: # argument must have "regex expression" parameter when using "valid_regex"
                if tag_argument is None:  # if argument field is empty or does not exist
                    print("CCCS_Yara.yml: \"" + tag + "\" has a missing parameter - argument")
                    exit(1)

                elif isinstance(tag_argument, dict):
                    input_fileName = tag_argument.get("fileName")
                    input_valueName = tag_argument.get("valueName")
                    input_regexExpression= tag_argument.get("regexExpression")

                    # check if fileName/valueName and regexExpression are mutually exclusive
                    if input_fileName:
                        if input_valueName:
                            if input_regexExpression:
                                print("CCCS_Yara.yml: \"" + tag + "\" has too many parameters - fileName | valueName | regexExpression")
                                exit(1)
                            else:
                                tag_argument.update({"regexExpression": self.read_regex_values(input_fileName, input_valueName)})
                        else:
                            if input_regexExpression:
                                print("CCCS_Yara.yml: \"" + tag + "\" has too many parameters - fileName | regexExpression")
                                exit(1)
                            else:
                                print("CCCS_Yara.yml: \"" + tag + "\" is missing a parameter - valueName")
                                exit(1)
                    else:
                        if input_valueName:
                            if input_regexExpression:
                                print("CCCS_Yara.yml: \"" + tag + "\" has too many parameters - valueName | regexExpression")
                                exit(1)
                            else:
                                print("CCCS_Yara.yml: \"" + tag + "\" is missing a parameter - fileName")
                                exit(1)
                        elif not input_regexExpression:
                            print("CCCS_Yara.yml: \"" + tag + "\" is missing a parameter - regexExpression")
                            exit(1)
                else:
                    print("CCCS_Yara.yml: \"" + tag + "\" has a parameter with invalid format - argument")
                    exit(1)
        else:
            print("CCCS_Yara.yml: \"" + tag + "\" has a missing parameter - validator")
            exit(1)

        return TagAttributes(tag_validator, tag_optional, tag_max_count, tag_position, tag_argument)

    def import_yara_cfg(self):
        """
        Updates self.required_fields based on the CCCS_Yara.yml configuration
        :return: void
        """
        tags_in_child_parent_relationship = []
        for index, item in enumerate(self.yara_config.items()):  # python 3.6+ dictionary preserves the insertion order
            cfg_tag = item[0]
            cfg_params = item[1]  # {parameter : value}

            self.required_fields[cfg_tag] = self.read_yara_cfg(cfg_tag, cfg_params, index)  # add a new TagAttributes instance
            self.handle_child_parent_tags(cfg_tag, cfg_params, tags_in_child_parent_relationship)  # replace the name of child tag with its place holder
        self.validate_child_parent_tags(self.yara_config, tags_in_child_parent_relationship)  # check if any tags in child-parent relationship are missing

    def __init__(self):
        # initialize the file system source for the MITRE ATT&CK data
        self.fs = FileSystemSource(MITRE_STIX_DATA_PATH)

        with open(VALIDATOR_YAML_PATH, "r") as yaml_file:
            self.scheme = yaml.safe_load(yaml_file)

        with open(CONFIGURATION_YAML_PATH, "r") as config_file:
            self.yara_config = yaml.safe_load(config_file)

        self.validators = Validators()
        self.required_fields = {}
        self.import_yara_cfg()

        self.required_fields_index = [Positional(i) for i in range(len(self.required_fields))]

        self.category_types = self.__parse_scheme('category_types')
        self.mitre_group_alias = None
        self.required_fields_children = {}
        self.validators.update(self.required_fields, self.required_fields_index, self.required_fields_children, self.category_types, self.mitre_group_alias)
        self.warning_functions = [
            self.warning_author_no_report_check,
            self.warning_author_no_hash_check,
            self.warning_actor_no_mitre_group
        ]
