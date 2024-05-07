import collections
import re
import os
from pathlib import Path

import plyara
import yaml
# for querying the MITRE ATT&CK data
from stix2 import FileSystemSource

from yara_validator.constants import SCRIPT_LOCATION, VALIDATOR_CFG, CONFIG_YAML_PATH, CONFIG_VALUES_YAML_PATH, MITRE_STIX_DATA_PATH
from yara_validator.validator_functions import Validators, MetadataOpt, StringEncoding, check_encoding
from yara_validator.yara_file_processor import YaraFileProcessor

# constants to deal with various required string comparisons
SCOPES = 'scopes'
GLOBAL = r'^global$'

# constants to store the string metadata used to reference to particular important metadata
METADATA = 'metadata'
REPORT = 'report'
HASH = 'hash'
ACTOR = 'actor'
AUTHOR = 'author'
CATEGORY = 'category'
CATEGORY_TYPE = 'info|exploit|technique|tool|malware'
SOURCE = 'source'
REFERENCE = 'reference'
MITRE_ATT = 'mitre_att'
CHILD_PLACE_HOLDER = 'child_place_holder'
MITRE_SOFTWAREID_GEN = 'mitre_softwareid_gen'
VALUE = 'value'
STRING_ENCODING = 'string_encoding'
WHITE_SPACE_REPLACEMENT = 'white_space_replacement'
CHAR_TO_REPLACE = 'char_to_replace'
CHAR_REPLACEMENT = 'char_replacement'
COUNT_OF_REPLACED = 'count_of_replaced'


METADATA_ALIASES = {
    'date': ['creation_date'],
    'modified': ['last_modified'],
    'minimum_yara': ['yara_version'],
}


def check_validator_cfg(validator_cfg):
    """
    Validates the loaded configuration file to ensure all values are valid
    :param  validator_cfg: the location of the configuration file
    :return:
    """
    string_encoding = validator_cfg.get(STRING_ENCODING).get(VALUE)
    if string_encoding is not None:
        potential_values = set(item.value for item in StringEncoding)
        if string_encoding not in potential_values:
            print('{!r}: {!r} has an invalid parameter - {!r}'.format(VALIDATOR_CFG,
                                                                      STRING_ENCODING,
                                                                      string_encoding))
            exit(1)
    else:
        print('{!r}: {!r} has a missing parameter - string_encoding'.format(VALIDATOR_CFG,
                                                                            STRING_ENCODING))
        exit(1)

    white_space_replacement_values = validator_cfg.get(WHITE_SPACE_REPLACEMENT).get(VALUE)
    if white_space_replacement_values is not None:
        char_to_replace = white_space_replacement_values.get(CHAR_TO_REPLACE).encode('utf-8').decode('unicode_escape')
        if char_to_replace is None or not re.fullmatch('\s', char_to_replace):
            print('{!r}: {!r} has an invalid parameter - {!r}'.format(VALIDATOR_CFG,
                                                                      CHAR_TO_REPLACE,
                                                                      char_to_replace))
            exit(1)
        else:
            white_space_replacement_values[CHAR_TO_REPLACE] = char_to_replace

        char_replacement = white_space_replacement_values.get(CHAR_REPLACEMENT)\
            .encode('utf-8').decode('unicode_escape')
        if char_replacement is None or not re.fullmatch('\s', char_replacement):
            print('{!r}: {!r} has an invalid parameter - {!r}'.format(VALIDATOR_CFG,
                                                                      CHAR_REPLACEMENT,
                                                                      char_replacement))
            exit(1)
        else:
            white_space_replacement_values[CHAR_REPLACEMENT] = char_replacement

        count_of_replaced = white_space_replacement_values.get(COUNT_OF_REPLACED)
        if count_of_replaced is None or count_of_replaced <= 0:
            print('{!r}: {!r} has an invalid parameter - {!r}'.format(VALIDATOR_CFG,
                                                                      COUNT_OF_REPLACED,
                                                                      count_of_replaced))
            exit(1)
    else:
        print('{!r}: {!r} has a missing parameter - string_encoding'.format(VALIDATOR_CFG,
                                                                            WHITE_SPACE_REPLACEMENT))
        exit(1)


def run_yara_validator(yara_file, generate_values=True, check_import_modules=True, config_path=None,
                       config_values_path=None, validator_config_path=None):
    """
    This is the base function that should be called to validate a rule. It will take as an argument the file path,
        create a YaraValidator object, parse that file with plyara and pass that parsed object and the string
        representation of the yara file to YaraValidator.valadation
    :param yara_file: The file variable passed in. Usually a string or Path variable
    :param generate_values: determine if the values the validator can generate should be generated or not, default True
    :param check_import_modules: determines if the check for modules that have not been imported is run, default True
    :return:
    """
    if config_path:
        global CONFIG_YAML_PATH
        CONFIG_YAML_PATH = config_path

    if config_values_path:
        global CONFIG_VALUES_YAML_PATH
        CONFIG_VALUES_YAML_PATH = config_values_path

    if validator_config_path:
        global VALIDATOR_CFG
        CONFIG_VALUES_YAML_PATH = validator_config_path

    with open(VALIDATOR_CFG, 'r', encoding='utf8') as config_file:
        validator_configuration = yaml.safe_load(config_file)

    check_validator_cfg(validator_configuration)
    char_to_replace = validator_configuration.get(WHITE_SPACE_REPLACEMENT).get(VALUE).get(CHAR_TO_REPLACE)
    char_replacement = validator_configuration.get(WHITE_SPACE_REPLACEMENT).get(VALUE).get(CHAR_REPLACEMENT)
    count_of_replaced = validator_configuration.get(WHITE_SPACE_REPLACEMENT).get(VALUE).get(COUNT_OF_REPLACED)
    yara_file_processor = YaraFileProcessor(yara_file, char_to_replace, char_replacement, count_of_replaced,
                                            check_import_modules)

    # If there are any issues with the yara file read process exit out and return the error
    if yara_file_processor.return_file_error_state():
        return yara_file_processor

    if not check_encoding(yara_file_processor.return_original_rule(),
                          validator_configuration.get(STRING_ENCODING).get(VALUE)):
        file_response = 'Some characters present in file are not:\t{!r}'\
            .format(str(validator_configuration.get(STRING_ENCODING).get(VALUE)))
        yara_file_processor.update_file_error(True, str(yara_file_processor.original_rule_file.name), file_response)
        return yara_file_processor

    with open(CONFIG_VALUES_YAML_PATH, 'r', encoding='utf8') as yaml_file:
        scheme = yaml.safe_load(yaml_file)

    with open(CONFIG_YAML_PATH, 'r', encoding='utf8') as config_file:
        yara_config = yaml.safe_load(config_file)

    validator = YaraValidator(MITRE_STIX_DATA_PATH, CONFIG_YAML_PATH, CONFIG_VALUES_YAML_PATH, yara_config, scheme)

    for rule in yara_file_processor.yara_rules:
        try:
            validator.reset()
            rule.add_rule_return(validator.validation(rule.rule_plyara, rule.rule_string, generate_values))
        except Exception as e:
            raise Exception(
                f"{rule.rule_plyara.get('rule_name', None)} produced the following exception: {str(e)}. Halting validation..")

    return yara_file_processor


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
        format_string = '{indent:>9} {key:30} {value}'
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

    def warning_state(self):
        return self.rule_warnings

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

    def check_argument_list_var(self, variable_name):
        if not self.argument or not isinstance(self.argument, dict):
            self.argument = {variable_name: []}
        elif not self.argument.get(variable_name) or not isinstance(self.argument.get(variable_name), list):
            self.argument.update({variable_name: []})

        return self.argument.get(variable_name)


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

    def __init__(self, stix_data_path, validator_yaml, validator_yaml_values, yara_config, scheme):
        # initialize the file system source for the MITRE ATT&CK data
        self.STIX_DATA_PATH = stix_data_path
        self.fs = FileSystemSource(self.STIX_DATA_PATH)

        self.validator_yaml_values = validator_yaml_values
        self.scheme = scheme
        self.validator_yaml = validator_yaml
        self.yara_config = yara_config

        self.validators = Validators()
        self.required_fields = {}
        self.metadata_keys_regex = r''
        self.metadata_keys_filter = r'^malware_type$|^actor_type$|original_.*'
        self.import_yara_cfg()

        self.required_fields_index = [Positional(i) for i in range(len(self.required_fields))]

        self.category_types = self.__parse_scheme('category_types')
        self.required_fields_children = {}
        self.validators.update(self.required_fields, self.required_fields_index, self.required_fields_children,
                               self.category_types)
        self.warning_functions = [
            self.warning_author_no_report_check,
            self.warning_author_no_hash_check,
            self.warning_actor_no_mitre_group,
            self.warning_no_category_type,
            self.warning_no_reference_specified,
            self.warning_common_metadata_errors
        ]

    previous_position_values = None

    def reset(self):
        # Reset back to factory settings for required field validation
        for value in self.required_fields.values():
            self.required_fields_index[value.position].count = 0
            value.found = False
            value.valid = False

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
            correct_order[tracking_added] = metadata_key_value_pairs.pop(0)
            tracking_added = tracking_added + 1

        rule_to_sort[METADATA] = correct_order

    def process_key(self, key, fields, rule_processing_key, metadata_index, alias):
        """
        The primary function that determines how to treat a specific metadata value for validation, it will either call
            the function or perform the regex comparison
        :param key: the name of the metadata value that is being processed
        :param fields: the dictonary of metadata values to check against this can differ depending on where validation is in the process
        :param rule_processing_key: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the key being processed is
        :return:
        """
        field_f = fields.get(alias, fields.get(key))
        if not field_f.function(rule_processing_key, metadata_index, key, alias):
            rule_response = 'Field has Invalid Value:\t{!r}'.format(rule_processing_key[METADATA][metadata_index][key])
            return False, rule_response
        return True, ''

    def validation(self, rule_to_validate, rule_to_validate_string, generate_values=True):
        """
        Called to validate a YARA rule. This is the primary function.
        :param rule_to_validate: the plyara parsed rule that is being validated
        :param rule_to_validate_string: the string representation of the YARA rule to verify, this is passed to the YaraValidatorReturn object for use later
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
        meta_alias_map = {i: k for k, v in METADATA_ALIASES.items() for i in v}
        for metadata_index, metadata in enumerate(metadata_vals):
            if len(metadata.keys()) == 1:
                key = list(metadata.keys())[0]
                value = list(metadata.values())[0]

                # Check if this key has been deprecated and aliases to a new field name
                alias = meta_alias_map.get(key)

                if value == '':
                    index_of_empty_metadata.append(metadata_index)
                elif key in self.required_fields or alias in self.required_fields:
                    validity, rule_response = self.process_key(key, self.required_fields, rule_to_validate,
                                                               metadata_index, alias)
                    if alias:
                        valid.update_warning(True, key,
                                             f'Warning, this metadata key has been deprecated in favour of "{alias}". '
                                             'This will be automatically fixed with -i/c.')
                    if not validity:
                        valid.update_validity(validity, key, rule_response)
                elif str(key).lower() in self.required_fields:
                    valid.update_warning(True, key,
                                         'Warning, this metadata key would be validated if it were lowercase.')
                else:
                    metadata_index_and_metadata = {key: metadata_index}
                    meta_not_initially_found.append(metadata_index_and_metadata)

        while meta_not_initially_found:
            no_children_keys_found = True
            for metadata_to_check in list(meta_not_initially_found):
                key_to_match = list(metadata_to_check.keys())[0]
                metadata_index = list(metadata_to_check.values())[0]

                try:
                    metadata = rule_to_validate[METADATA][metadata_index]
                except IndexError:
                    for i, meta in enumerate(rule_to_validate[METADATA]):
                        metadata = meta.get(key_to_match)
                        if metadata is not None:
                            metadata = meta
                            metadata_index = i
                            break

                if len(metadata.keys()) == 1:
                    key = list(metadata.keys())[0]
                    value = list(metadata.values())[0]
                    alias = meta_alias_map.get(key)

                    if key in self.required_fields_children:
                        no_children_keys_found = False
                        meta_not_initially_found.remove(metadata_to_check)
                        validity, rule_response = self.process_key(key, self.required_fields_children, rule_to_validate,
                                                                   metadata_index, alias)
                        if not validity:
                            valid.update_validity(validity, key, rule_response)

            if no_children_keys_found:
                meta_not_initially_found = []

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
                    valid.update_validity(False, key, '⚙️ Missing metadata that could have been generated with the -i'
                                                      ' or -c flag for the cli')
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
        if self.required_fields.get(ACTOR) and self.required_fields[ACTOR].argument.get(CHILD_PLACE_HOLDER):
            place_holder = self.required_fields[ACTOR].argument.get(CHILD_PLACE_HOLDER)
            if self.required_fields[ACTOR].found and not self.required_fields[place_holder].found:
                metadata_values = rule_to_check[METADATA]
                for value in metadata_values:
                    if len(value.keys()) == 1:
                        key = list(value.keys())[0]
                        value = list(value.values())[0]
                        if key == ACTOR:
                            warning_message = 'Actor: {!r} was not found in MITRE ATT&CK dataset.'.format(value)
                            valid.update_warning(True, ACTOR, warning_message)

    def warning_no_category_type(self, rule_to_check, valid):
        category_child_place_holder = self.required_fields[CATEGORY].argument.get(CHILD_PLACE_HOLDER)
        if self.required_fields.get(CATEGORY).found and not self.required_fields.get(category_child_place_holder).found:
            metadata_values = rule_to_check[METADATA]
            for value in metadata_values:
                if len(value.keys()) == 1:
                    key = list(value.keys())[0]
                    value = list(value.values())[0]
                    if key == CATEGORY:
                        warning_message = 'Category: {!r} was selected but there is no associated metadata with more ' \
                                          'information i.e. malware: "name of the malware".'.format(value)
                        valid.update_warning(True, CATEGORY_TYPE, warning_message)

    def warning_no_reference_specified(self, rule_to_check, valid):
        if self.required_fields.get(
                SOURCE, None) and self.required_fields[SOURCE].found and not self.required_fields[REFERENCE].found:
            metadata_values = rule_to_check[METADATA]
            for metadata in metadata_values:
                if SOURCE in metadata.keys() and REFERENCE not in metadata.keys():
                    valid.update_warning(True, REFERENCE, 'Source was given without a reference.')

    def warning_common_metadata_errors(self, rule_to_check, valid):
        metadata_values = rule_to_check[METADATA]
        for value in metadata_values:
            if len(value.keys()) == 1:
                key = list(value.keys())[0]
                value = list(value.values())[0]
                if re.fullmatch(self.metadata_keys_regex, key) and not re.fullmatch(self.metadata_keys_filter, key):
                    warning_message = 'Key: {!r} has a similar name to a key in the standard but was not validated' \
                        'because it did not match the standard.'.format(key)
                    valid.update_warning(True, key, warning_message)

    def generate_required_optional_metadata(self, rule_to_validate):
        req_optional_keys = self.return_req_optional(rule_to_validate)

        for key in req_optional_keys:
            if not self.required_fields[key].found:
                if self.required_fields[key].function == self.validators.valid_regex:
                    self.required_fields[key].attributefound()
                else:
                    self.required_fields[key].function(rule_to_validate, self.required_fields_index[
                        self.required_fields[key].position].index(), key)

    def return_req_optional(self, rule_to_validate):
        keys_to_return = []
        for key in self.required_fields.keys():
            if self.required_fields[key].optional == MetadataOpt.REQ_OPTIONAL:
                if not self.required_fields[key].found:
                    keys_to_return.append(key)

        if self.__mitre_group_alias() and self.required_fields[ACTOR].found:
            keys_to_return.append(self.required_fields[ACTOR].argument.get(CHILD_PLACE_HOLDER))

        category_type = self.required_fields[CATEGORY].argument.get(CHILD_PLACE_HOLDER)
        if self.required_fields[category_type].check_argument_list_var(MITRE_SOFTWAREID_GEN):
            self.validators.mitre_software_generator(rule_to_validate, CATEGORY, MITRE_ATT)

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

            if argument.get('child'):
                child_metadata = argument['child']
                argument.update({CHILD_PLACE_HOLDER: child_metadata + place_holder})
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
        regex_yaml_path = CONFIG_VALUES_YAML_PATH if "CCCS_YARA_values.yml" in file_name else \
            SCRIPT_LOCATION.parent / file_name
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
            if cfg_metadata == 'info|exploit|technique|tool|malware':
                self.metadata_keys_regex = self.metadata_keys_regex\
                    + '^info.+|^exploit.+|^technique.+|^tool.+|^malware.+|'
            else:
                self.metadata_keys_regex = self.metadata_keys_regex + '^' + cfg_metadata + '.+|'
            self.required_fields[cfg_metadata] = self.read_yara_cfg(cfg_metadata, cfg_params,
                                                                    index)  # add a new MetadataAttributes instance
            # replace the name of child metadata with its place holder
            self.handle_child_parent_metadata(cfg_metadata, cfg_params, metadata_in_child_parent_relationship)
        # check if any metadata in child-parent relationship are missing
        self.validate_child_parent_metadata(self.yara_config, metadata_in_child_parent_relationship)
        self.metadata_keys_regex = self.metadata_keys_regex[:-1]
