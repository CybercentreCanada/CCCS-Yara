import datetime  # for date checking function
import hashlib
import re
import uuid
from enum import Enum
from pathlib import Path

import baseconv  # for the UUID
import packaging.version
import stix2.exceptions
from stix2 import FileSystemSource
from stix2 import Filter

from stix2_patch.filter_casefold import FilterCasefold

METADATA = 'metadata'
BASE62_REGEX = r'^[0-9a-zA-z]+$'
UNIVERSAL_REGEX = r'^[^a-z]*$'
MITRE_GROUP_NAME = 'name'


# potential values of MetadataAttributes.optional variable
class MetadataOpt(Enum):
    REQ_PROVIDED = 'req_provided'
    REQ_OPTIONAL = 'req_optional'
    OPT_OPTIONAL = 'opt_optional'


# potential values for the encoding check
class StringEncoding(Enum):
    ASCII = 'ascii'
    UTF8 = 'utf-8'
    NONE = 'none'


def __is_ascii(rule_string):
    """
    Takes the string of the rule and parses it to check if there are only ascii characters present.
    :param rule_string: the string representation of the yara rule
    :return: true if there are only ascii characters in the string
    """
    return len(rule_string) == len(rule_string.encode())


def __is_utf8(rule_string):
    """
    Takes the string of the rule and parses it to check if there are only utf-8 characters present.
    :param rule_string: the string representation of the yara rule
    :return: true if there are only utf-8 characters in the string
    """
    try:
        rule_string.encode('utf-8')
    except UnicodeEncodeError:
        return False
    else:
        return True


def check_encoding(rule_string, encoding_flag):
    if encoding_flag == StringEncoding.ASCII.value:
        if not __is_ascii(rule_string):
            return False
    elif encoding_flag == StringEncoding.UTF8.value:
        if not __is_utf8(rule_string):
            return False

    return True


class Validators:
    def __init__(self):
        self.required_fields = None
        self.required_fields_index = None
        self.required_fields_children = None
        self.category_types = None
        self.mitre_group_alias = None
        self.names = {
            'None': self.valid_none,
            'valid_regex': self.valid_regex,
            'valid_uuid': self.valid_uuid,
            'valid_fingerprint': self.valid_fingerprint,
            'valid_version': self.valid_version,
            'valid_date': self.valid_date,
            'valid_last_modified': self.valid_last_modified,
            'valid_source': self.valid_source,
            'valid_category': self.valid_category,
            'valid_category_type': self.valid_category_type,
            'valid_mitre_att': self.valid_mitre_att,
            'valid_actor': self.valid_actor,
            'mitre_group_generator': self.mitre_group_generator,
            'valid_al_config_dumper': self.valid_al_config_dumper,
            'valid_al_config_parser': self.valid_al_config_parser
        }

    def update(self, required_fields, required_fields_index, required_fields_children, category_types):
        self.required_fields = required_fields
        self.required_fields_index = required_fields_index
        self.required_fields_children = required_fields_children
        self.category_types = category_types
        self.mitre_group_alias = None

    def valid_none(self, rule_to_validate, metadata_index, metadata_key):
        self.required_fields[metadata_key].attributefound()
        self.required_fields_index[self.required_fields[metadata_key].position].increment_count()
        self.required_fields[metadata_key].attributevalid()
        return True

    def valid_regex(self, rule_to_validate, metadata_index, metadata_key):
        """
        Validates the metadata value using provided regex expression
        :param rule_to_validate: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the id metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value of the metadata value follows the regex expression or
            False if the value is does not match the expression
        """
        value = list(rule_to_validate[METADATA][metadata_index].values())[0]

        self.required_fields[metadata_key].attributefound()
        self.required_fields_index[self.required_fields[metadata_key].position].increment_count()

        regex_expression = self.required_fields[metadata_key].argument.get('regexExpression')

        if re.fullmatch(regex_expression, value):
            self.required_fields[metadata_key].attributevalid()
        elif re.fullmatch(regex_expression, str(value).upper()):
            self.required_fields[metadata_key].attributevalid()
            rule_to_validate[METADATA][metadata_index][metadata_key] = str(value).upper()
        else:
            self.required_fields[metadata_key].attributeinvalid()
            return False
        return True

    def valid_uuid(self, rule_to_generate_uuid, metadata_index, metadata_key):
        """
        Creates a valid UUID for the id metadata value and inserts it or verifies an existing id metadata value
        :param rule_to_generate_uuid: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the id metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if a the value of the id metadata value is of the correct size or if a new UUID is generated or
            False if the existing value is not of the correct size
        """
        UUID = metadata_key
        self.required_fields[UUID].attributefound()
        self.required_fields_index[self.required_fields[UUID].position].increment_count()

        rule_uuid = {UUID: str(baseconv.base62.encode(uuid.uuid4().int))}
        if Helper.valid_metadata_index(rule_to_generate_uuid, metadata_index):
            if list(rule_to_generate_uuid[METADATA][metadata_index].keys())[0] == UUID:
                if Helper.validate_uuid(list(rule_to_generate_uuid[METADATA][metadata_index].values())[0]):
                    self.required_fields[UUID].attributevalid()
                else:
                    self.required_fields[UUID].attributeinvalid()
            else:
                rule_to_generate_uuid[METADATA].insert(metadata_index, rule_uuid)
                self.required_fields[UUID].attributevalid()
        else:
            rule_to_generate_uuid[METADATA].append(rule_uuid)
            self.required_fields[UUID].attributevalid()

        return self.required_fields[UUID].valid

    def valid_fingerprint(self, rule_to_generate_id, metadata_index, metadata_key):
        """
        Calculates a valid fingerprint for the fingerprint metadata value and inserts it or replaces the existing value
            of the fingerprint metadata value.
            Current functionality is not to check the value of an existing fingerprint metadata value and just overwrite
            it as this is automatically filled out.
        :param rule_to_generate_id: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the fingerprint metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: This should return True all the time as there will always be a return from self.calculate_rule_hash
        """
        FINGERPRINT = metadata_key
        self.required_fields[FINGERPRINT].attributefound()
        self.required_fields_index[self.required_fields[FINGERPRINT].position].increment_count()

        rule_hash = Helper.calculate_rule_hash(rule_to_generate_id)
        if rule_hash:
            rule_id = {FINGERPRINT: rule_hash}
            if Helper.valid_metadata_index(rule_to_generate_id, metadata_index):
                if list(rule_to_generate_id[METADATA][metadata_index].keys())[0] == FINGERPRINT:
                    rule_to_generate_id[METADATA][metadata_index] = rule_id
                    self.required_fields[FINGERPRINT].attributevalid()
                else:
                    rule_to_generate_id[METADATA].insert(metadata_index, rule_id)
                    self.required_fields[FINGERPRINT].attributevalid()
            else:
                rule_to_generate_id[METADATA].append(rule_id)
                self.required_fields[FINGERPRINT].attributevalid()

        return self.required_fields[FINGERPRINT].valid

    def valid_version(self, rule_to_version_check, metadata_index, metadata_key):
        """
        This value can be generated: there is the option to verify if an existing version format is correct, insert a
            generated version if none was found and if the potential default metadata index would be out of bounds
            appends a generated version
        :param rule_to_version_check: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the version metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the version is of the correct format and False if it is not
        """
        VERSION = metadata_key
        self.required_fields[VERSION].attributefound()
        self.required_fields_index[self.required_fields[VERSION].position].increment_count()

        rule_version = {VERSION: '1.0'}
        if Helper.valid_metadata_index(rule_to_version_check, metadata_index):
            if list(rule_to_version_check[METADATA][metadata_index].keys())[0] == VERSION:
                if isinstance(packaging.version.parse(list(rule_to_version_check[METADATA][metadata_index].values())[0]),
                              packaging.version.Version):
                    self.required_fields[VERSION].attributevalid()
                else:
                    self.required_fields[VERSION].attributeinvalid()
            else:
                rule_to_version_check[METADATA].insert(metadata_index, rule_version)
                self.required_fields[VERSION].attributevalid()
        else:
            rule_to_version_check[METADATA].append(rule_version)
            self.required_fields[VERSION].attributevalid()

        return self.required_fields[VERSION].valid

    def valid_date(self, rule_to_date_check, metadata_index, metadata_key):
        """
        This value can be generated: there is the option to verify if an existing date is correct, insert a generated
            date if none was found and if the potential default metadata index would be out of bounds appends
            a generated date
        :param rule_to_date_check: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the last_modified metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value matches the valid date format and False if it does not match it
        """
        DATE = metadata_key
        self.required_fields[DATE].attributefound()
        self.required_fields_index[self.required_fields[DATE].position].increment_count()

        if Helper.valid_metadata_index(rule_to_date_check, metadata_index):
            if list(rule_to_date_check[METADATA][metadata_index].keys())[0] == DATE:
                if Helper.validate_date(list(rule_to_date_check[METADATA][metadata_index].values())[0]):
                    self.required_fields[DATE].attributevalid()
                else:
                    self.required_fields[DATE].attributeinvalid()
            else:
                rule_date = {DATE: Helper.current_valid_date()}
                rule_to_date_check[METADATA].insert(metadata_index, rule_date)
                self.required_fields[DATE].attributevalid()
        else:
            rule_date = {DATE: Helper.current_valid_date()}
            rule_to_date_check[METADATA].append(rule_date)
            self.required_fields[DATE].attributevalid()

        return self.required_fields[DATE].valid

    def valid_first_imported(self, rule_to_date_check, metadata_index, metadata_key):
        """
        This value can be generated: there is the option to verify if an existing date is correct, insert a generated
            date if none was found and if the potential default metadata index would be out of bounds appends
            a generated date
        :param rule_to_date_check: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the last_modified metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value matches the valid date format and False if it does not match it
        """
        FIRST_IMPORTED = metadata_key
        self.required_fields[FIRST_IMPORTED].attributefound()
        self.required_fields_index[self.required_fields[FIRST_IMPORTED].position].increment_count()

        if Helper.valid_metadata_index(rule_to_date_check, metadata_index):
            if list(rule_to_date_check[METADATA][metadata_index].keys())[0] == FIRST_IMPORTED:
                if Helper.validate_date(list(rule_to_date_check[METADATA][metadata_index].values())[0]):
                    self.required_fields[FIRST_IMPORTED].attributevalid()
                else:
                    self.required_fields[FIRST_IMPORTED].attributeinvalid()
            else:
                rule_date = {FIRST_IMPORTED: Helper.current_valid_date()}
                rule_to_date_check[METADATA].insert(metadata_index, rule_date)
                self.required_fields[FIRST_IMPORTED].attributevalid()
        else:
            rule_date = {FIRST_IMPORTED: Helper.current_valid_date()}
            rule_to_date_check[METADATA].append(rule_date)
            self.required_fields[FIRST_IMPORTED].attributevalid()

        return self.required_fields[FIRST_IMPORTED].valid

    def valid_last_modified(self, rule_to_date_check, metadata_index, metadata_key):
        """
        This value can be generated: there is the option to verify if an existing date is correct, insert a generated
            date if none was found and if the potential default metadata index would be out of bounds appends a
                generated date
        :param rule_to_date_check: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the last_modified metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value matches the valid date format and False if it does not match it
        """
        LAST_MODIFIED = metadata_key
        self.required_fields[LAST_MODIFIED].attributefound()
        self.required_fields_index[self.required_fields[LAST_MODIFIED].position].increment_count()

        current_date = Helper.current_valid_date()
        if Helper.valid_metadata_index(rule_to_date_check, metadata_index):
            if list(rule_to_date_check[METADATA][metadata_index].keys())[0] == LAST_MODIFIED:
                rule_to_date_check[METADATA][metadata_index][LAST_MODIFIED] = current_date
                if Helper.validate_date(list(rule_to_date_check[METADATA][metadata_index].values())[0]):
                    self.required_fields[LAST_MODIFIED].attributevalid()
                else:
                    self.required_fields[LAST_MODIFIED].attributeinvalid()
            else:
                rule_date = {LAST_MODIFIED: current_date}
                rule_to_date_check[METADATA].insert(metadata_index, rule_date)
                self.required_fields[LAST_MODIFIED].attributevalid()
        else:
            rule_date = {LAST_MODIFIED: current_date}
            rule_to_date_check[METADATA].append(rule_date)
            self.required_fields[LAST_MODIFIED].attributevalid()

        return self.required_fields[LAST_MODIFIED].valid

    def valid_source(self, rule_to_source_check, metadata_index, metadata_key):
        """
        Validates the source
        :param rule_to_source_check:
        :param metadata_index: used to reference what the array index of the last_modified metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value matches the UNIVERSAL_REGEX and False if it does not match it
        """
        SOURCE = metadata_key
        REFERENCE = self.required_fields[SOURCE].argument.get('required')
        IFVALUE_REGEX = r'' + self.required_fields[SOURCE].argument.get('ifvalue')
        self.required_fields[SOURCE].attributefound()
        self.required_fields_index[self.required_fields[SOURCE].position].increment_count()

        metadata = rule_to_source_check[METADATA]
        source_to_check = metadata[metadata_index][SOURCE]
        if re.fullmatch(UNIVERSAL_REGEX, source_to_check):
            self.required_fields[SOURCE].attributevalid()
        elif re.fullmatch(UNIVERSAL_REGEX, str(source_to_check).upper()):
            source_to_check = str(source_to_check).upper()
            metadata[metadata_index][SOURCE] = source_to_check
            self.required_fields[SOURCE].attributevalid()
        else:
            self.required_fields[SOURCE].attributeinvalid()

        if re.fullmatch(IFVALUE_REGEX, source_to_check):
            # Because the source is OPENSOURCE a reference is required
            self.required_fields[REFERENCE].optional = MetadataOpt.REQ_PROVIDED

        return self.required_fields[SOURCE].valid

    def valid_mitre_att(self, rule_to_validate_mitre_att, metadata_index, metadata_key):
        """
        Pulls the value of the mitre_att metadata value and passes it to validate_mitre_att_by_id
        :param rule_to_validate_mitre_att: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the mitre_att metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value was found in the MITRE ATT&CK database and False if it was not found
        """
        MITRE_ATT = metadata_key
        self.required_fields[MITRE_ATT].attributefound()
        self.required_fields_index[self.required_fields[MITRE_ATT].position].increment_count()

        metadata = rule_to_validate_mitre_att[METADATA]
        mitre_att_to_validate = str(metadata[metadata_index][MITRE_ATT]).upper()
        metadata[metadata_index][MITRE_ATT] = mitre_att_to_validate
        if Helper.validate_mitre_att_by_id(mitre_att_to_validate):
            self.required_fields[MITRE_ATT].attributevalid()
        else:
            self.required_fields[MITRE_ATT].attributeinvalid()

        return self.required_fields[MITRE_ATT].valid

    def valid_al_config_dumper(self, rule_to_validate_al_config_d, metadata_index, metadata_key):
        """
        Makes the al_config_parser metadata value required if this is found first.
        :param rule_to_validate_al_config_d: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the actor metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True all the time because the value is never verified...
        """
        AL_CONFIG_D = metadata_key
        self.required_fields[AL_CONFIG_D].attributefound()
        self.required_fields_index[self.required_fields[AL_CONFIG_D].position].increment_count()

        # Because there is an al_config_dumper al_config_parser becomes required
        self.required_fields[AL_CONFIG_D].optional = MetadataOpt.REQ_PROVIDED

        # Because we are not validating the value... So much pain!
        self.required_fields[AL_CONFIG_D].attributevalid()

        return self.required_fields[AL_CONFIG_D].valid

    def valid_al_config_parser(self, rule_to_validate_al_config_p, metadata_index, metadata_key):
        """
        Makes the al_config_dumper metadata value required if this is found first.
        :param rule_to_validate_al_config_p: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the actor metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True all the time because the value is never verified...
        """
        AL_CONFIG_P = metadata_key
        self.required_fields[AL_CONFIG_P].attributefound()
        self.required_fields_index[self.required_fields[AL_CONFIG_P].position].increment_count()

        # Because there is an al_config_parser al_config_dumper becomes required
        self.required_fields[AL_CONFIG_P].optional = MetadataOpt.REQ_PROVIDED

        # Because we are not validating the value... So much pain!
        self.required_fields[AL_CONFIG_P].attributevalid()

        return self.required_fields[AL_CONFIG_P].valid

    def valid_category(self, rule_to_validate_category, metadata_index, metadata_key):
        """
        Pulls the value of the category metadata value and checks if it is a valid category type.
            Valid options are stored in self.category_types. If the category value is valid and a new metadata
            metadata with a name the same as the category value is added to be searched for.
            This new metadata value links to the same object as the initially created self.required_fields[CATEGORY_TYPE].
        :param rule_to_validate_category: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the category metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value was found in self.category_types and False if it was not found
        """
        CATEGORY = metadata_key
        self.required_fields[CATEGORY].attributefound()
        self.required_fields_index[self.required_fields[CATEGORY].position].increment_count()
        child_metadata_place_holder = self.required_fields[CATEGORY].argument.get('child_place_holder')

        metadata = rule_to_validate_category[METADATA]
        rule_category_to_check = metadata[metadata_index][CATEGORY]
        if rule_category_to_check in self.category_types:
            self.required_fields[CATEGORY].attributevalid()
            add_category_type_to_required = {
                str(rule_category_to_check).lower(): self.required_fields[child_metadata_place_holder]}
            self.required_fields_children.update(add_category_type_to_required)
        elif str(rule_category_to_check).upper() in self.category_types:
            rule_category_to_check = str(rule_category_to_check).upper()
            metadata[metadata_index][CATEGORY] = rule_category_to_check
            self.required_fields[CATEGORY].attributevalid()
            add_category_type_to_required = {
                str(rule_category_to_check).lower(): self.required_fields[child_metadata_place_holder]}
            self.required_fields_children.update(add_category_type_to_required)
        else:
            self.required_fields[CATEGORY].attributeinvalid()

        return self.required_fields[CATEGORY].valid

    def valid_category_type(self, rule_to_validate_type, metadata_index, metadata_key):
        """
        This will be called by the new metadata created by the valid_category function. Because it references the same object
            as that initialized as CATEGORY_TYPE we can use that to reference the reqired metadata in this function.
        :param rule_to_validate_type: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the category_type metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value matches the Regex expression and False if it was not found
        """
        CATEGORY = 'category'
        child_metadata_place_holder = self.required_fields[CATEGORY].argument.get('child_place_holder')
        self.required_fields[child_metadata_place_holder].attributefound()
        self.required_fields_index[self.required_fields[child_metadata_place_holder].position].increment_count()

        metadata = rule_to_validate_type[METADATA]
        rule_category_key_to_check = list(metadata[metadata_index].keys())[0]
        rule_category_value_to_check = list(metadata[metadata_index].values())[0]
        if re.fullmatch(UNIVERSAL_REGEX, rule_category_value_to_check):
            self.required_fields[child_metadata_place_holder].attributevalid()
        elif re.fullmatch(UNIVERSAL_REGEX, str(rule_category_value_to_check).upper()):
            rule_category_value_to_check = str(rule_category_value_to_check).upper()
            metadata[metadata_index][rule_category_key_to_check] = rule_category_value_to_check
            self.required_fields[child_metadata_place_holder].attributevalid()
        else:
            self.required_fields[child_metadata_place_holder].attributeinvalid()

        return self.required_fields[child_metadata_place_holder].valid

    def valid_actor(self, rule_to_validate_actor, metadata_index, metadata_key):
        """
        Validates the actor, makes the actor_type metadata value required.
            Adds a required metadata value for mitre_group to hold the a potential alias value.
            Also stores the value of the actor metadata value in self.mitre_group_alias variable for use with the
            mitre_group_generator function
        :param rule_to_validate_actor: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the actor metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: True if the value matches the self.mitre_group_alias_regex and False if it does not
        """
        ACTOR = metadata_key
        ACTOR_TYPE = self.required_fields[ACTOR].argument.get('required')
        child_metadata = self.required_fields[ACTOR].argument.get('child')
        child_metadata_place_holder = self.required_fields[ACTOR].argument.get('child_place_holder')
        mitre_group_alias_regex = r'^[^a-z]+$'

        self.required_fields[ACTOR].attributefound()
        self.required_fields_index[self.required_fields[ACTOR].position].increment_count()

        # Because there is an actor actor_type becomes required
        self.required_fields[ACTOR_TYPE].optional = MetadataOpt.REQ_PROVIDED
        metadata = rule_to_validate_actor[METADATA]
        actor_to_check = metadata[metadata_index][ACTOR]
        if re.fullmatch(mitre_group_alias_regex, actor_to_check):
            self.required_fields[ACTOR].attributevalid()
            add_mitre_group_to_required = {child_metadata: self.required_fields[child_metadata_place_holder]}
            self.required_fields_children.update(add_mitre_group_to_required)
            self.mitre_group_alias = actor_to_check
        elif re.fullmatch(mitre_group_alias_regex, str(actor_to_check).upper()):
            actor_to_check = str(actor_to_check).upper()
            metadata[metadata_index][ACTOR] = actor_to_check
            self.required_fields[ACTOR].attributevalid()
            add_mitre_group_to_required = {child_metadata: self.required_fields[child_metadata_place_holder]}
            self.required_fields_children.update(add_mitre_group_to_required)
            self.mitre_group_alias = actor_to_check
        else:
            self.required_fields[ACTOR].attributeinvalid()

        return self.required_fields[ACTOR].valid

    def mitre_group_generator(self, rule_to_generate_group, metadata_index, metadata_key):
        """
        This will only be looked for if the actor metadata value has already been processed.
            Current functionality is not to check the value of an existing mitre_group metadata value and just overwrite
            it as this is automatically filled out. Also if no alias is found it will be removed.
        :param rule_to_generate_group: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the mitre_group metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: This should return True all the time as there will always be a return from self.get_group_from_alias
        """
        ACTOR = 'actor'
        place_holder = self.required_fields[ACTOR].argument.get('child_place_holder')
        if self.required_fields.get(metadata_key):  # if child place holder is passed as metadata_key
            MITRE_GROUP = self.required_fields[self.required_fields[metadata_key].argument['parent']].argument['child']
        else:
            MITRE_GROUP = metadata_key

        mitre_group = str(Helper.get_group_from_alias(self.mitre_group_alias)).upper()
        rule_group = {MITRE_GROUP: mitre_group}
        if Helper.valid_metadata_index(rule_to_generate_group, metadata_index):
            if list(rule_to_generate_group[METADATA][metadata_index].keys())[0] == MITRE_GROUP:
                if mitre_group:
                    rule_to_generate_group[METADATA][metadata_index] = rule_group
                    self.required_fields[place_holder].attributefound()
                    self.required_fields[place_holder].attributevalid()
                    self.required_fields_index[self.required_fields[place_holder].position].increment_count()
                else:
                    rule_to_generate_group[METADATA].pop(metadata_index)
                    return True
            else:
                if mitre_group:
                    rule_to_generate_group[METADATA].insert(metadata_index, rule_group)
                    self.required_fields[place_holder].attributefound()
                    self.required_fields[place_holder].attributevalid()
                    self.required_fields_index[self.required_fields[place_holder].position].increment_count()
                else:
                    return True
        else:
            if mitre_group:
                rule_to_generate_group[METADATA].append(rule_group)
                self.required_fields[place_holder].attributefound()
                self.required_fields[place_holder].attributevalid()
                self.required_fields_index[self.required_fields[place_holder].position].increment_count()
            else:
                return True

        return self.required_fields[place_holder].valid

    def mitre_software_generator(self, rule_to_generate_software, metadata_index, metadata_key):
        """
        This will only be looked for if the info|exploit|technique|tool|malware metadata value has already been
            processed. Current functionality is not to check the value of an existing mitre_group metadata value and
            just overwrite it as this is automatically filled out. Also if no alias is found it will be removed.
        :param rule_to_generate_software: the plyara parsed rule that is being validated
        :param metadata_index: used to reference what the array index of the mitre_group metadata value is
        :param metadata_key: the name of the metadata value that is being processed
        :return: This should return True all the time as there will always be a return from self.get_group_from_alias
        """
        ACTOR = 'actor'
        place_holder = self.required_fields[ACTOR].argument.get('child_place_holder')
        if self.required_fields.get(metadata_key):  # if child place holder is passed as metadata_key
            MITRE_GROUP = self.required_fields[self.required_fields[metadata_key].argument['parent']].argument['child']
        else:
            MITRE_GROUP = metadata_key

        mitre_group = str(Helper.get_group_from_alias(self.mitre_group_alias)).upper()
        rule_group = {MITRE_GROUP: mitre_group}
        if Helper.valid_metadata_index(rule_to_generate_group, metadata_index):
            if list(rule_to_generate_group[METADATA][metadata_index].keys())[0] == MITRE_GROUP:
                if mitre_group:
                    rule_to_generate_group[METADATA][metadata_index] = rule_group
                    self.required_fields[place_holder].attributefound()
                    self.required_fields[place_holder].attributevalid()
                    self.required_fields_index[self.required_fields[place_holder].position].increment_count()
                else:
                    rule_to_generate_group[METADATA].pop(metadata_index)
                    return True
            else:
                if mitre_group:
                    rule_to_generate_group[METADATA].insert(metadata_index, rule_group)
                    self.required_fields[place_holder].attributefound()
                    self.required_fields[place_holder].attributevalid()
                    self.required_fields_index[self.required_fields[place_holder].position].increment_count()
                else:
                    return True
        else:
            if mitre_group:
                rule_to_generate_group[METADATA].append(rule_group)
                self.required_fields[place_holder].attributefound()
                self.required_fields[place_holder].attributevalid()
                self.required_fields_index[self.required_fields[place_holder].position].increment_count()
            else:
                return True

        return self.required_fields[place_holder].valid


class Helper:
    SCRIPT_LOCATION = Path(__file__).resolve().parent
    MITRE_STIX_DATA_PATH = SCRIPT_LOCATION.parent / 'cti/enterprise-attack'
    VALIDATOR_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_YARA_values.yml'
    CONFIGURATION_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_YARA.yml'

    fs = FileSystemSource(MITRE_STIX_DATA_PATH)

    @staticmethod
    def valid_metadata_index(rule, index):
        """
        Ensures that the index will not return an out of bounds error
        :param rule: the plyara parsed rule that is being validated
        :param index: the potential index
        :return: True if the potential index will not be out of bounds and false otherwise
        """
        count_of_metadata = len(rule[METADATA])
        if index >= count_of_metadata:
            return False
        else:
            return True

    @staticmethod
    def validate_uuid(uuid_to_check):
        """
        Validates the uuid by checking the base62_uuid matches the potential characters and is of the correct length
        :param uuid_to_check: the value to be
        :return: True if the decoded value of the id is 127 bits in length and False otherwise
        """
        if re.fullmatch(BASE62_REGEX, uuid_to_check):
            return 20 <= len(uuid_to_check) <= 22
        else:
            return False

    @staticmethod
    def regex_match_string_names_for_values(string_name_preface, string_name_expression, string_substitutions):
        """
        Looks to replace YARA string references in conditions such as $a*. The function looks to match all matching
            string names and compile a completed list of those string values
        :param string_name_preface: Can be one of '$', '!', '#', or '@'
        :param string_name_expression: The string name expression that will be converted into a regex pattern
        :param string_substitutions: the dict of all string substitutions and values
        :return: the completed list of string values whose string names match the expression
        """
        string_name, string_suffix = string_name_expression[:-1], string_name_expression[-1:]
        string_name_regex = r'^\{}.{}$'.format(string_name, string_suffix)
        string_value_matches = []
        for key in string_substitutions.keys():
            if re.fullmatch(string_name_regex, key):
                string_value_matches.append(string_name_preface + string_substitutions[key])

        return string_value_matches

    @staticmethod
    def sort_strings_add_commas(list_of_strings):
        """
        Takes a list of string values and rebuilds it as a string with comma delimiters so it would look like a hard
            coded YARA list of strings
        :param list_of_strings: the list of collected string values
        :return: the sorted list
        """
        list_of_strings.sort()
        count_of_strings = len(list_of_strings)

        for index, string in enumerate(list_of_strings):
            if index + 1 < count_of_strings:
                list_of_strings.insert(index + index + 1, ',')

        return list_of_strings

    # This comes from 'https://gist.github.com/Neo23x0/577926e34183b4cedd76aa33f6e4dfa3' Cyb3rOps.
    # There have been significant changes to this function to better generate a hash of the strings and conditions
    @staticmethod
    def calculate_rule_hash(rule):
        """
        Calculates a hash over the relevant YARA rule content (string contents, sorted condition)
        Requires a YARA rule object as generated by 'plyara': https://github.com/plyara/plyara
        :param rule: YARA rule object
        :return hash: generated hash
        """
        hash_strings = []
        condition_string_prefaces = ('$', '!', '#', '@')
        # dictionary for substitutions
        string_substitutions = {}
        all_strings = []
        # original code used md5
        # m = hashlib.md5()
        m = hashlib.sha3_256()
        # Adding all string contents to the list
        if 'strings' in rule:
            for s in rule['strings']:
                if s['type'] == 'byte':
                    # original code just needed to append the converted hex code as a string.
                    # We need to create the dictionary entries for substitutions as well
                    # hash_strings.append(re.sub(r'[^a-fA-F?0-9]+', '', s['value']))
                    byte_code_string = re.sub(r'[^a-fA-F?0-9]+', '', s['value'])
                    dict_entry = {s['name']: byte_code_string}
                    string_substitutions.update(dict_entry)
                    hash_strings.append(byte_code_string)
                else:
                    # The following line was the only portion of this else statement in the original code
                    # This change takes modifiers into account for string arguments
                    # hash_strings.append(s['value'])
                    string_and_modifiers = ['"' + s['value'] + '"']
                    if 'modifiers' in s:
                        modifiers = ' '.join(s['modifiers'])
                        string_and_modifiers.append(modifiers)
                    string_and_modifiers = ' '.join(string_and_modifiers)
                    all_strings.append('$' + string_and_modifiers)
                    dict_entry = {s['name']: string_and_modifiers}
                    string_substitutions.update(dict_entry)
                    # hash_strings.append('$' + string_and_modifiers)
        all_strings = Helper.sort_strings_add_commas(all_strings)
        # Adding the components of the condition to the list (except the variables)
        all_wild_card_1 = r'\$\*'
        all_wild_card_2 = r'them'
        for e in rule['condition_terms']:
            if re.match(all_wild_card_1, e) or re.match(all_wild_card_2, e):
                hash_strings.extend(all_strings)
            elif e.startswith(condition_string_prefaces):
                if len(e) > 1:
                    string_preface, string_name = e[:1], e[1:]
                    string_name = '$' + string_name
                    if e.endswith('*'):
                        hash_strings.extend(Helper.sort_strings_add_commas(
                            Helper.regex_match_string_names_for_values(string_preface, string_name,
                                                                       string_substitutions)))
                        # hash_strings.extend('Pull all the matching strings')
                    else:
                        if string_name in string_substitutions:
                            substituted = string_preface + string_substitutions[string_name]
                            hash_strings.append(substituted)
                        else:
                            hash_strings.append(e)
                else:
                    hash_strings.append(e)
            else:
                hash_strings.append(e)
        # Generate a hash from the sorted contents
        # hash_strings.sort()
        m.update(''.join(hash_strings).encode('utf8'))
        return m.hexdigest()

    @staticmethod
    def validate_date(date_to_validate):
        """
        Verifies a date is in the correct format.
        :param date_to_validate: the value of the last_modifed metadata value
        :return: True if the value is in the correct format or False if it is not valid
        """
        try:
            if date_to_validate != datetime.datetime.strptime(date_to_validate, '%Y-%m-%d').strftime('%Y-%m-%d'):
                raise ValueError
            return True
        except ValueError:
            return False

    @staticmethod
    def current_valid_date():
        """
        Generates the current date in the valid format
        :return: the current date in the valid format
        """
        return datetime.datetime.now().strftime('%Y-%m-%d')

    @staticmethod
    def get_tactic_by_id(id_code):
        """
        Used if the id_code is prefaced with TA
        :param id_code: The value of the mitre_att metadata value
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        return Helper.fs.query([
            Filter('type', '=', 'x-mitre-tactic'),
            Filter('external_references.external_id', '=', id_code)
        ])

    @staticmethod
    def get_technique_by_id(id_code):
        """
        Used if the id_code is prefaced with T
        :param id_code: The value of the mitre_att metadata value
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        return Helper.fs.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('external_references.external_id', '=', id_code)
        ])

    @staticmethod
    def get_software_by_id(id_code):
        """
        Used if the id_code is prefaced with S
        :param id_code: The value of the mitre_att metadata value
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        malware_return = Helper.fs.query([
            Filter('type', '=', 'malware'),
            Filter('external_references.external_id', '=', id_code)
        ])

        tool_return = Helper.fs.query([
            Filter('type', '=', 'tool'),
            Filter('external_references.external_id', '=', id_code)
        ])

        if malware_return:
            return malware_return
        elif tool_return:
            return tool_return

    @staticmethod
    def get_tactic_by_id(id_code):
        """
        Used if the id_code is prefaced with TA
        :param id_code: The value of the mitre_att metadata value
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        return Helper.fs.query([
            Filter('type', '=', 'x-mitre-tactic'),
            Filter('external_references.external_id', '=', id_code)
        ])

    @staticmethod
    def get_group_by_id(id_code):
        """
        Used if the id_code is prefaced with G
        :param id_code: The value of the mitre_att metadata value
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        return Helper.fs.query([
            Filter('type', '=', 'intrusion-set'),
            Filter('external_references.external_id', '=', id_code)
        ])

    @staticmethod
    def get_mitigation_by_id(id_code):
        """
        Used if the id_code is prefaced with M
        :param id_code: The value of the mitre_att metadata value
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        return Helper.fs.query([
            Filter('type', '=', 'course-of-action'),
            Filter('external_references.external_id', '=', id_code)
        ])

    @staticmethod
    def get_mitreattck_by_id(id_code):
        """
        Used if the id_code is prefaced with an unknown letter. This is about 20x more inefficient then the queries
            that specify types in the filters
            It is used as a catch all in case new MITRE ATT&CK ID Code types are added in the future
        :param id_code: The value of the mitre_att metadata value
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        try:
            Helper.fs.query([
                Filter('external_references.external_id', '=', id_code)
            ])
        except stix2.exceptions.InvalidValueError:
            return ''

    @staticmethod
    def validate_mitre_att_by_id(id_code):
        """
        Checks the preface of the id_code and sends the id_code to specific functions
            This is done because using specified filters based on the type is about 20 times more efficient then
            the entire MITRE ATT&CK database with the id_code.
            There is a catch all provided in the case that there are new ID Code types added in the future
        :param id_code: The value of the mitre_att metadata value
        :return: The return from the specified get_ function
        """
        if id_code.startswith('TA'):
            return Helper.get_tactic_by_id(id_code)
        elif id_code.startswith('T'):
            return Helper.get_technique_by_id(id_code)
        elif id_code.startswith('S'):
            return Helper.get_software_by_id(id_code)
        elif id_code.startswith('G'):
            return Helper.get_group_by_id(id_code)
        elif id_code.startswith('M'):
            return Helper.get_mitigation_by_id(id_code)
        else:
            return Helper.get_mitreattck_by_id(id_code)

    @staticmethod
    def get_group_from_alias(alias):
        """
        Maps any alias to the potential MITRE ATT&CK group name, if the provided name is a known alias.
        :param alias: The alias to check
        :return: Either returns the MITRE ATT&CK group name or returns empty string, '', if the query returns null
        """
        group_from_alias = Helper.fs.query([
            Filter('type', '=', 'intrusion-set'),
            FilterCasefold('aliases', 'casefold', alias)
        ])

        if not group_from_alias:
            return ''

        return group_from_alias[0][MITRE_GROUP_NAME]
