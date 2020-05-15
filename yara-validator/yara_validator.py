import collections
import re
from pathlib import Path

import plyara
import yaml
from plyara.utils import rebuild_yara_rule
# for querying the MITRE ATT&CK data
from stix2 import FileSystemSource

from validator_functions import Validators, MetadataOpt, StringEncoding, check_encoding

# set current working directory
SCRIPT_LOCATION = Path(__file__).resolve().parent
MITRE_STIX_DATA_PATH = SCRIPT_LOCATION.parent / 'cti/enterprise-attack'
CONFIG_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_YARA.yml'
CONFIG_VALUES_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_YARA_values.yml'

# constants to deal with various required string comparisons
SCOPES = 'scopes'
GLOBAL = r'^global$'

# constants to store the string metadata used to reference to particular important metadata
METADATA = 'metadata'
REPORT = 'report'
HASH = 'hash'
ACTOR = 'actor'
AUTHOR = 'author'


def run_yara_validator(yara_file, one_rule_files=False, string_encoding=StringEncoding.ASCII):
    """
    This is the base function that should be called to validate a rule. It will take as an argument the file path,
        create a YaraValidator object, parse that file with plyara and pass that parsed object and the string representation
        of the YARA file to YaraValidator.valadation

        NOTE: If the one_rule_files option is set, the function assumes one rule per file
              and will only process the first rule found.
    :param one_rule_files:
    :param yara_file:
    :param string_encoding:
    :return:
    """

    parser = plyara.Plyara()
    if isinstance(yara_file, str) or isinstance(yara_file, Path):
        with open(yara_file, encoding='utf-8') as yf:
            try:
                yara_rule_file_string = yf.read()
            except UnicodeDecodeError as e:
                print('UnicodeDecodeError: ' + str(e))
                rule_list = []
                valid = YaraValidatorReturn('')
                rule_response = 'UnicodeDecodeError:\t{!r}'.format(str(e))
                valid.update_validity(False, yara_file, rule_response)
                rule_list.append(valid)
                return rule_list
            except Exception as e:
                print('There was an error opening the file: ' + str(e))
                valid = YaraValidatorReturn('')
                rule_response = 'There was an error opening the file:\t{!r}'.format(str(e))
                valid.update_validity(False, yara_file, rule_response)
                return valid
    else:
        yara_rule_file_string = yara_file

    if not check_encoding(yara_rule_file_string, string_encoding):
        print('Encoding mismatch for file')
        valid = YaraValidatorReturn(yara_rule_file_string)
        rule_response = 'Encoding mismatch for file:\t{!r}'.format(str(string_encoding))
        valid.update_validity(False, yara_file, rule_response)
        return valid

    try:
        parsed_rules = parser.parse_string(yara_rule_file_string)
    except plyara.exceptions.ParseTypeError as e:
        print('Error reported by plyara library: plyara.exceptions.ParseTypeError: ' + str(e))
        valid = YaraValidatorReturn(yara_rule_file_string)
        rule_response = 'Error reported by plyara library: plyara.exceptions.ParseTypeError:\t{!r}'.format(str(e))
        valid.update_validity(False, yara_file, rule_response)
        return valid
    except Exception as e:
        print('Error Parsing YARA file with plyara: ' + str(e))
        valid = YaraValidatorReturn(yara_rule_file_string)
        rule_response = 'Error Parsing YARA file with plyara:\t{!r}'.format(str(e))
        valid.update_validity(False, yara_file, rule_response)
        return valid

    rule_list = []

    for index, rule in enumerate(parsed_rules):
        validator = YaraValidator(MITRE_STIX_DATA_PATH, CONFIG_YAML_PATH, CONFIG_VALUES_YAML_PATH)
        validated_rule = validator.validation(rule, rebuild_yara_rule(rule), StringEncoding.UTF8)
        if one_rule_files:
            return validated_rule
        rule_list.append(validated_rule)
    return rule_list


class YaraValidatorReturn:
    """
    YaraValidatorReturn class used to pass the validity of the processed rules, what metadata values have issues if
        not valid, a string representation of the original rule and if the rule is valid a string representation of the
        valid rule with all the created metadata values, etc.
    """

    def __init__(self, original_rule):
        self.rule_name = None
        # Overall rule validity flag
        self.rule_validity = True
        # each possible metadata value
        self.metadata_vals = collections.OrderedDict()
        # Overall warning flag
        self.rule_warnings = False
        # collection of all the warnings
        self.warnings = collections.OrderedDict()
        # the original_rule
        self.rule_to_validate = original_rule
        # set
        self.validated_rule = None

    def update_validity(self, rule_validity, metadata_val, message):
        if self.rule_validity:
            self.rule_validity = rule_validity

        self.metadata_vals[metadata_val] = message

    def update_warning(self, rule_warning, warning_val, message):
        if not self.rule_warnings:
            self.rule_warnings = rule_warning

        self.warnings[warning_val] = message

    def __build_return_string(self, collection):
        return_string = ''
        for index, metadata in enumerate(collection):
            if index > 0:
                return_string += '\n'
            return_string = '{}{}: {}'.format(return_string, metadata, collection[metadata])

        return return_string

    def __build_return_string_cmlt(self, collection):
        format_string = '{indent:>8} {key:30} {value}'
        return_string = '\n'.join([
            format_string.format(indent='-', key=k + ':', value=v)
            for k, v in collection.items()
        ])

        return return_string

    def return_errors(self):
        error_string = ''
        if not self.rule_validity:
            error_string = self.__build_return_string(self.metadata_vals)

        return error_string

    def return_errors_for_cmlt(self):
        error_string = ''
        if not self.rule_validity:
            error_string = self.__build_return_string_cmlt(self.metadata_vals)

        return error_string

    def return_warnings(self):
        warning_string = ''
        if self.rule_warnings:
            warning_string = self.__build_return_string(self.warnings)

        return warning_string

    def return_warnings_for_cmlt(self):
        warning_string = ''
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
        A string representation of a YARA rule is passed into this function, it performs the splitlines() function,
            searches for the start and the end indexes of the meta section of the first YARA rule.
        :param rule_to_process: The Rule to be processed
        :return: a tuple of the array of lines for the rule processed, and a list of start and end of meta indices
        """
        rule_to_process_lines = rule_to_process.splitlines()
        meta_offsets = []
        meta_start = 0
        meta_end = 0
        meta_regex = r'^\s*meta\s*:\s*$'
        next_section = r'^\s*(?:strings|condition)\s*:\s*$'

        for index, line in enumerate(rule_to_process_lines):
            if re.match(meta_regex, line):
                meta_start = index
            elif re.match(next_section, line) and meta_start > 0:
                meta_end = index
                break

        return rule_to_process_lines, meta_start, meta_end

    def rebuild_rule(self):
        """
        Rebuilds the rule if it is valid and as long as there are any changes. This was created to maintain
            any comments outside of the metadata section
        :return: No return
        """

        if self.rule_to_validate is None or self.validated_rule is None:
            exit()
        elif self.rule_to_validate == self.validated_rule:
            return

        yara_valid_lines, yara_valid_meta_start, yara_valid_meta_end = self.__find_meta_start_end(self.rule_to_validate)
        yara_cccs_lines, yara_cccs_meta_start, yara_cccs_meta_end = self.__find_meta_start_end(self.validated_rule)

        yara_new_file = []
        if yara_valid_meta_start != 0 and yara_valid_meta_end != 0 and yara_cccs_meta_start != 0 and yara_cccs_meta_end != 0:
            yara_new_file = yara_valid_lines[0:yara_valid_meta_start] + yara_cccs_lines[
                                                                        yara_cccs_meta_start:yara_cccs_meta_end] + yara_valid_lines[
                                                                                                                   yara_valid_meta_end:]
            yara_new_file = '\n'.join(yara_new_file)

        if self.rule_to_validate != yara_new_file:
            self.validated_rule = yara_new_file


class MetadataAttributes:
    """
    MetadataAttributes class is used to populate the YaraValidator.required_fields dict and stores values such as the
    type of method used to validate the given metadata value, regex expression or funcion name used to verify,
    the optionality of the metadata value, the max count of the metadata value and the position of the matching
    Positional object in the YaraValidator.required_fields_index
    """
    function = None
    argument = None
    optional = None
    max_count = None
    position = None
    found = False
    valid = False

    def __init__(self, meta_validator, meta_optional, meta_max_count, meta_position, meta_argument):
        self.function = meta_validator
        self.argument = meta_argument
        self.optional = meta_optional
        self.max_count = meta_max_count
        self.position = meta_position

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
    Positional class used to create positional objects for the YaraValidator.required_fields_index.
        This allows for tracking the count of each metadata value found and the relative start and
        end positions given the canonical order
    """

    def __init__(self, position_index, position_count=0):
        self.starting_index = position_index
        self.count = position_count
        self.current_offset = 0

    def set_values(self, position_index, position_count=0):
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
    Class for YaraValidator that does most of the work for validating YARA rules to the defined YARA Metadata Standard.
    """

    def __init__(self, stix_data_path, validator_yaml, validator_yaml_values):
        # initialize the file system source for the MITRE ATT&CK data
        self.STIX_DATA_PATH = stix_data_path
        self.fs = FileSystemSource(self.STIX_DATA_PATH)

        self.validator_yaml_values = validator_yaml_values
        with open(validator_yaml_values, 'r', encoding='utf8') as yaml_file:
            self.scheme = yaml.safe_load(yaml_file)

        self.validator_yaml = validator_yaml
        with open(validator_yaml, 'r', encoding='utf8') as config_file:
            self.yara_config = yaml.safe_load(config_file)

        self.validators = Validators()
        self.required_fields = {}
        self.import_yara_cfg()

        self.required_fields_index = [Positional(i) for i in range(len(self.required_fields))]

        self.category_types = self.__parse_scheme('category_types')
        self.required_fields_children = {}
        self.validators.update(self.required_fields, self.required_fields_index, self.required_fields_children,
                               self.category_types)
        self.warning_functions = [
            self.warning_author_no_report_check,
            self.warning_author_no_hash_check,
            self.warning_actor_no_mitre_group
        ]

    previous_position_values = None

    def reindex_metadata_keys(self):
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

    def sort_metadata_keys(self, rule_to_sort):
        """
        Sorts the array of metadata keys for valid rules into the canonical order
        :param rule_to_sort: the plyara parsed rule that is being validated
        :return: No return, it simply replaces the rules metadata array with the sorted array
        """
        metadata_key_value_pairs = rule_to_sort[METADATA]
        correct_order = [None] * len(metadata_key_value_pairs)
        tracking_added = 0
        tracking_left = 0
        for key_value_pair in list(metadata_key_value_pairs):
            if len(key_value_pair.keys()) == 1:
                key = list(key_value_pair.keys())[0]
                value = list(key_value_pair.values())[0]

                if key in self.required_fields:
                    positional = self.required_fields_index[self.required_fields[key].position]
                    correct_order[positional.index()] = metadata_key_value_pairs.pop(tracking_left)
                    positional.increment_offset()
                    tracking_added = tracking_added + 1
                elif key in self.required_fields_children:
                    positional = self.required_fields_index[self.required_fields_children[key].position]
                    correct_order[positional.index()] = metadata_key_value_pairs.pop(tracking_left)
                    positional.increment_offset()
                    tracking_added = tracking_added + 1
                else:
                    tracking_left = tracking_left + 1
            else:
                tracking_left = tracking_left + 1

        # takes all unrecognized or multivalue metadata and appends them to the end of the array of metadata
        for key_value_pair in list(metadata_key_value_pairs):
            correct_order[tracking_added] = key_value_pair.pop(0)
            tracking_added = tracking_added + 1

        rule_to_sort[METADATA] = correct_order

    def process_key(self, key, fields, rule_processing_key, metadata_index):
        """
        The primary function that determines how to treat a specific metadata value for validation, it will either call
            the function or perform the regex comparison
        :param key: the name of the metadata value that is being processed
        :param fields: the dictonary of metadata values to check against this can differ depending on where validation is in the process
        :param rule_processing_key: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the key being processed is
        :return:
        """
        if not fields[key].function(rule_processing_key, metadata_index, key):
            rule_response = 'Field has Invalid Value:\t{!r}'.format(rule_processing_key[METADATA][metadata_index][key])
            return False, rule_response
        return True, ''

    def validation(self, rule_to_validate, rule_to_validate_string, string_encoding, generate_values=True):
        """
        Called to validate a YARA rule. This is the primary function.
        :param rule_to_validate: the plyara parsed rule that is being validated
        :param rule_to_validate_string: the string representation of the YARA rule to verify, this is passed to the YaraValidatorReturn object for use later
        :param string_encoding: if there is a desired string encoding to check and which it is
        :param generate_values: if values need to be generated or not
        :return: the valid object of the YaraValidatorReturn class
        """
        valid = YaraValidatorReturn(rule_to_validate_string)
        valid.rule_name = rule_to_validate.get('rule_name', None)

        if METADATA not in rule_to_validate:
            valid.update_validity(False, METADATA, 'No Metadata Present')
            return valid

        if SCOPES in rule_to_validate:
            for scope in rule_to_validate[SCOPES]:
                if re.match(GLOBAL, scope):
                    valid.update_validity(False, SCOPES, 'This is a Global Rule.')
                    return valid

        metadata_vals = rule_to_validate[METADATA]
        index_of_empty_metadata = []
        meta_not_initially_found = []
        for metadata_index, metadata in enumerate(metadata_vals):
            if len(metadata.keys()) == 1:
                key = list(metadata.keys())[0]
                value = list(metadata.values())[0]

                if value == '':
                    index_of_empty_metadata.append(metadata_index)
                elif key in self.required_fields:
                    validity, rule_response = self.process_key(key, self.required_fields, rule_to_validate,
                                                               metadata_index)
                    if not validity:
                        valid.update_validity(validity, key, rule_response)
                elif str(key).lower() in self.required_fields:
                    valid.update_warning(True, key,
                                         'Warning, this metadata key would be validated if it were lowercase.')
                else:
                    metadata_index_and_metadata = {key: metadata_index}
                    meta_not_initially_found.append(metadata_index_and_metadata)

        meta_not_initially_found.reverse()
        for metadata_to_check in meta_not_initially_found:
            if len(metadata_to_check.keys()) == 1:
                key_to_match = list(metadata_to_check.keys())[0]
                metadata_index = list(metadata_to_check.values())[0]

                metadata = rule_to_validate[METADATA][metadata_index]
                if len(metadata.keys()) == 1:
                    key = list(metadata.keys())[0]
                    value = list(metadata.values())[0]

                    if key in self.required_fields_children:
                        validity, rule_response = self.process_key(key, self.required_fields_children, rule_to_validate,
                                                                   metadata_index)
                        if not validity:
                            valid.update_validity(validity, key, rule_response)

        for empty_metadata in sorted(index_of_empty_metadata, reverse=True):
            if list(rule_to_validate[METADATA][empty_metadata].values())[0] == '':
                metadata_vals.pop(empty_metadata)

        if generate_values:
            self.generate_required_optional_metadata(rule_to_validate)

        for key, value in self.required_fields.items():
            if not value.found and not str(key).upper() in self.category_types:
                if value.optional == MetadataOpt.REQ_PROVIDED:
                    valid.update_validity(False, key, 'Missing required metadata')
                elif value.optional == MetadataOpt.REQ_OPTIONAL:
                    valid.update_warning(False, key, 'Missing metadata that could have been generated')
            else:
                if self.required_fields_index[value.position].count > value.max_count and value.max_count != -1:
                    valid.update_validity(False, key, 'Too many instances of metadata value.')

        if valid.rule_validity:
            self.reindex_metadata_keys()
            self.sort_metadata_keys(rule_to_validate)
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
                metadata_values = rule_to_check[METADATA]
                for value in metadata_values:
                    if len(value.keys()) == 1:
                        key = list(value.keys())[0]
                        value = list(value.values())[0]
                        if key == AUTHOR and (value == 'RevEng@CCCS' or value == 'reveng@CCCS'):
                            valid.update_warning(True, REPORT,
                                                 'Rule is authored by the CCCS but no report is referenced.')

    def warning_author_no_hash_check(self, rule_to_check, valid):
        if self.required_fields.get(AUTHOR) and self.required_fields.get(HASH):
            if self.required_fields[AUTHOR].found and not self.required_fields[HASH].found:
                metadata_values = rule_to_check[METADATA]
                for metadata in metadata_values:
                    if len(metadata.keys()) == 1:
                        key = list(metadata.keys())[0]
                        value = list(metadata.values())[0]
                        if key == AUTHOR and value == 'RevEng@CCCS':
                            valid.update_warning(True, HASH, 'Rule is authored by the CCCS but no hash is referenced.')

    def warning_actor_no_mitre_group(self, rule_to_check, valid):
        if self.required_fields.get(ACTOR) and self.required_fields[ACTOR].argument.get('child_place_holder'):
            place_holder = self.required_fields[ACTOR].argument.get('child_place_holder')
            if self.required_fields[ACTOR].found and not self.required_fields[place_holder].found:
                metadata_values = rule_to_check[METADATA]
                for value in metadata_values:
                    if len(value.keys()) == 1:
                        key = list(value.keys())[0]
                        value = list(value.values())[0]
                        if key == ACTOR:
                            warning_message = 'Actor: {!r} was not found in MITRE ATT&CK dataset.'.format(value)
                            valid.update_warning(True, ACTOR, warning_message)

    def generate_required_optional_metadata(self, rule_to_validate):
        req_optional_keys = self.return_req_optional()

        for key in req_optional_keys:
            if not self.required_fields[key].found:
                if self.required_fields[key].function == self.validators.valid_regex:
                    self.required_fields[key].attributefound()
                else:
                    self.required_fields[key].function(rule_to_validate, self.required_fields_index[
                        self.required_fields[key].position].index(), key)

    def return_req_optional(self):
        keys_to_return = []
        for key in self.required_fields.keys():
            if self.required_fields[key].optional == MetadataOpt.REQ_OPTIONAL:
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
        cfg_being_parsed = ''
        for index, cfg in enumerate(self.scheme[cfg_to_parse]):
            if index > 0:
                cfg_being_parsed = cfg_being_parsed + '|'

            cfg_being_parsed = cfg_being_parsed + '^' + str(cfg['value']) + '$'

        return cfg_being_parsed

    def handle_child_parent_metadata(self, metadata, params, metadata_in_child_parent_relationship,
                                     place_holder='_child'):
        """
        Child metadata create MetadataAttributes instances as temporary place holders in self.required_fields and
        the place holders will be used to create the actual MetadataAttributes instances in self.required_fields_children.
        This method creates a place holder for a child metadata and adds the name of the place holder to a parent metadata.
        :param metadata: string name of a metadata in CCCS_YARA.yml file
        :param params: parameters of the corresponding metadata in a dictionary format
        :param place_holder: string to be attached to a metadata name -> will be used as a place holder name
        :param metadata_in_child_parent_relationship: list of metadata that contain either parent or child argument
        :return: void
        """
        argument = params.get('argument')
        if argument:
            if argument.get('parent'):
                self.required_fields[metadata + place_holder] = self.required_fields.pop(metadata)
                metadata_in_child_parent_relationship.append(argument.get('parent'))
            elif argument.get('child'):
                child_metadata = argument['child']
                argument.update({'child_place_holder': child_metadata + place_holder})
                metadata_in_child_parent_relationship.append(argument.get('child'))

    def validate_child_parent_metadata(self, configuration, metadata_in_child_parent_relationship):
        """
        Checks if any metadata in child-parent relationships are missing from CCCS_YARA.yml configuration page
        :param configuration: CCCS_YARA.yml configuration in dictionary format
        :param metadata_in_child_parent_relationship: a list of metadata in child-parent relationships
        :return: void
        """
        for metadata in metadata_in_child_parent_relationship:
            if configuration.get(metadata) is None:
                print('CCCS_YARA.yml: {!r} is required (in a child-parent relationship)'.format(metadata))
                exit(1)

    def read_regex_values(self, file_name, regex_metadata):
        """
        Parses multiple values under the name 'regex_metadata' from given YAML file to make a single line of expression
        :param file_name: name of the file to reference
        :param regex_metadata: name of the metadata in the file that contains multiple regex expressions
        :return: single line of regex expression
        """
        regex_yaml_path = SCRIPT_LOCATION.parent / file_name
        with open(regex_yaml_path, 'r', encoding='utf8') as yaml_file:
            scheme = yaml.safe_load(yaml_file)

        cfg_being_parsed = ''
        for index, cfg in enumerate(scheme[regex_metadata]):
            if index > 0:
                cfg_being_parsed = cfg_being_parsed + '|'

            cfg_being_parsed = cfg_being_parsed + '^' + str(cfg['value']) + '$'

        return cfg_being_parsed

    def read_yara_cfg(self, metadata, params, metadata_position):
        """
        Creates a MetadataAttributes object for self.required_fields based on the provided YAML configuration
        :param metadata: string name of metadata in provided YAML configuration
        :param params: parameters of the corresponding metadata value in dictionary format
        :param metadata_position: index (position) of the key in YAML configuration file
        :return: MetadataAttributes instance
        """
        # parameters for creating a MetadataAttributes instance
        metadata_max_count = None
        metadata_optional = None
        metadata_validator = None
        metadata_argument = None

        # check if the metadata is optional
        optional = params.get('optional')
        if optional is not None:
            if optional is True or re.fullmatch(r'(?i)^y$|yes', str(optional)):
                metadata_optional = MetadataOpt.OPT_OPTIONAL
            elif optional is False or re.fullmatch(r'(?i)^n$|no', str(optional)):
                metadata_optional = MetadataOpt.REQ_PROVIDED
            elif re.fullmatch(r'(?i)optional', str(optional)):
                metadata_optional = MetadataOpt.REQ_OPTIONAL
            else:
                print('{!r}: {!r} has an invalid parameter - optional'.format(self.validator_yaml, metadata))
                exit(1)
        else:
            print('{!r}: {!r} has a missing parameter - optional'.format(self.validator_yaml, metadata))
            exit(1)

        # check if the metadata is unique
        unique = params.get('unique')
        if unique is not None:
            if unique is True or re.fullmatch(r'(?i)^y$|yes', str(unique)):
                metadata_max_count = 1
            elif unique is False or re.fullmatch(r'(?i)^n$|no', str(unique)):
                metadata_max_count = -1
            elif isinstance(unique, int):
                metadata_max_count = unique
            else:
                print('{!r}: {!r} has an invalid parameter - unique'.format(self.validator_yaml, metadata))
                exit(1)
        else:
            print('{!r}: {!r} has a missing parameter - unique'.format(self.validator_yaml, metadata))
            exit(1)

        # check which validator to use
        if params.get('validator'):  # validate the corresponding metadata using the 'validator'
            metadata_validator = self.validators.names.get(params['validator'])
            if not metadata_validator:
                print(
                    '{!r}: Validator {!r} of {!r} is not defined'.format(self.validator_yaml, params['validator'],
                                                                         metadata))
                exit(1)

            metadata_argument = params.get('argument')

            # argument must have 'regex expression' parameter when using 'valid_regex'
            if metadata_validator == self.validators.valid_regex:
                self.my_method_name(metadata, metadata_argument)
        else:
            print('{!r}: {!r} has a missing parameter - validator'.format(self.validator_yaml, metadata))
            exit(1)

        return MetadataAttributes(metadata_validator, metadata_optional, metadata_max_count, metadata_position,
                                  metadata_argument)

    def my_method_name(self, metadata, metadata_argument):
        if metadata_argument is None:  # if argument field is empty or does not exist
            print('{!r}: {!r} has a missing parameter - argument'.format(self.validator_yaml, metadata))
            exit(1)

        elif isinstance(metadata_argument, dict):
            input_fileName = metadata_argument.get('fileName')
            input_valueName = metadata_argument.get('valueName')
            input_regexExpression = metadata_argument.get('regexExpression')

            # check if fileName/valueName and regexExpression are mutually exclusive
            if input_fileName:
                if input_valueName:
                    if input_regexExpression:
                        print(
                            '{!r}: {!r} has too many parameters - fileName | valueName | regexExpression'.format(
                                self.validator_yaml, metadata))
                        exit(1)
                    else:
                        metadata_argument.update(
                            {'regexExpression': self.read_regex_values(input_fileName, input_valueName)})
                else:
                    if input_regexExpression:
                        print(
                            '{!r}: {!r} has too many parameters - fileName | regexExpression'.format(
                                self.validator_yaml, metadata))
                        exit(1)
                    else:
                        print('{!r}: {!r} is missing a parameter - valueName'.format(self.validator_yaml, metadata))
                        exit(1)
            else:
                if input_valueName:
                    if input_regexExpression:
                        print(
                            '{!r}: {!r} has too many parameters - valueName | regexExpression'.format(
                                self.validator_yaml, metadata))
                        exit(1)
                    else:
                        print('{!r}: {!r} is missing a parameter - fileName'.format(self.validator_yaml, metadata))
                        exit(1)
                elif not input_regexExpression:
                    print('{!r}: {!r} is missing a parameter - regexExpression'.format(self.validator_yaml, metadata))
                    exit(1)
        else:
            print('{!r}: {!r} has a parameter with invalid format - argument'.format(self.validator_yaml, metadata))
            exit(1)

    def import_yara_cfg(self):
        """
        Updates self.required_fields based on the YAML configuration
        :return: void
        """
        metadata_in_child_parent_relationship = []
        for index, item in enumerate(self.yara_config.items()):  # python 3.6+ dictionary preserves the insertion order
            cfg_metadata = item[0]
            cfg_params = item[1]  # {parameter : value}

            self.required_fields[cfg_metadata] = self.read_yara_cfg(cfg_metadata, cfg_params,
                                                                    index)  # add a new MetadataAttributes instance
            self.handle_child_parent_metadata(cfg_metadata, cfg_params,
                                              metadata_in_child_parent_relationship)  # replace the name of child metadata with its place holder
        self.validate_child_parent_metadata(self.yara_config,
                                            metadata_in_child_parent_relationship)  # check if any metadata in child-parent relationship are missing

