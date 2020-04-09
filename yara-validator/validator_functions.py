import re

# for the UUID
import baseconv
import uuid
import hashlib

# for version checking function
from packaging import version

# for date checking function
import datetime
from enum import Enum
from stix2 import Filter
from stix2 import FileSystemSource
from cfg.filter_casefold import FilterCasefold
from pathlib import Path

METADATA = 'metadata'
BASE62_REGEX = "^[0-9a-zA-z]+$"
UNIVERSAL_REGEX = '^[^a-z]*$'
OPENSOURCE_REGEX = '^OPENSOURCE$'
CATEGORY_TYPE_REGEX = '^[A-Z\-. 0-9_+\/]*$'
MITRE_GROUP_NAME = 'name'


# potential values of TagAttributes.optional variable
class TagOpt(Enum):
    REQ_PROVIDED = 'req_provided'
    REQ_OPTIONAL = 'req_optional'
    OPT_OPTIONAL = 'opt_optional'


class Validators:
    def __init__(self):
        self.required_fields = None
        self.required_fields_index = None
        self.required_fields_children = None
        self.category_types = None
        self.mitre_group_alias = None
        self.names = {
            "None": self.valid_none,
            "valid_regex": self.valid_regex,
            "valid_uuid": self.valid_uuid,
            "valid_fingerprint": self.valid_fingerprint,
            "valid_version": self.valid_version,
            "valid_date": self.valid_date,
            "valid_last_modified": self.valid_last_modified,
            "valid_source": self.valid_source,
            "valid_category": self.valid_category,
            "valid_category_type": self.valid_category_type,
            "valid_mitre_att": self.valid_mitre_att,
            "valid_actor": self.valid_actor,
            "mitre_group_generator": self.mitre_group_generator,
            "valid_al_config_dumper": self.valid_al_config_dumper,
            "valid_al_config_parser": self.valid_al_config_parser
        }

    def update(self, required_fields, required_fields_index, required_fields_children, category_types, mitre_group_alias):
        self.required_fields = required_fields
        self.required_fields_index = required_fields_index
        self.required_fields_children = required_fields_children
        self.category_types = category_types
        self.mitre_group_alias = mitre_group_alias

    def valid_none(self, rule_to_validate, tag_index, tag_key):
        self.required_fields[tag_key].attributefound()
        self.required_fields_index[self.required_fields[tag_key].position].increment_count()
        self.required_fields[tag_key].attributevalid()
        return True

    def valid_regex(self, rule_to_validate, tag_index, tag_key):
        """
        Validates the metadata tag using provided regex expression
        :param rule_to_validate: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the id metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value of the metadata tag follows the regex expression or
            False if the value is does not match the expression
        """
        value = list(rule_to_validate[METADATA][tag_index].values())[0]

        self.required_fields[tag_key].attributefound()
        self.required_fields_index[self.required_fields[tag_key].position].increment_count()

        regex_expression = self.required_fields[tag_key].argument.get("regexExpression")

        if re.fullmatch(regex_expression, value):
            self.required_fields[tag_key].attributevalid()
        elif re.fullmatch(regex_expression, str(value).upper()):
            self.required_fields[tag_key].attributevalid()
            rule_to_validate[METADATA][tag_index][tag_key] = str(value).upper()
        else:
            self.required_fields[tag_key].attributeinvalid()
            return False
        return True
    
    def valid_uuid(self, rule_to_generate_uuid, tag_index, tag_key):
        """
        Creates a valid UUID for the id metadata tag and inserts it or verifies an existing id metadata tag
        :param rule_to_generate_uuid: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the id metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if a the value of the id metadata tag is of the correct size or if a new UUID is generated or
            False if the existing value is not of the correct size
        """
        UUID = tag_key
        self.required_fields[UUID].attributefound()
        self.required_fields_index[self.required_fields[UUID].position].increment_count()

        rule_uuid = {UUID: str(baseconv.base62.encode(uuid.uuid4().int))}
        if Helper.valid_metadata_index(rule_to_generate_uuid, tag_index):
            if list(rule_to_generate_uuid[METADATA][tag_index].keys())[0] == UUID:
                if Helper.validate_uuid(list(rule_to_generate_uuid[METADATA][tag_index].values())[0]):
                    self.required_fields[UUID].attributevalid()
                else:
                    self.required_fields[UUID].attributeinvalid()
            else:
                rule_to_generate_uuid[METADATA].insert(tag_index, rule_uuid)
                self.required_fields[UUID].attributevalid()
        else:
            rule_to_generate_uuid[METADATA].append(rule_uuid)
            self.required_fields[UUID].attributevalid()

        return self.required_fields[UUID].valid

    def valid_fingerprint(self, rule_to_generate_id, tag_index, tag_key):
        """
        Calculates a valid fingerprint for the fingerprint metadata tag and inserts it or replaces the existing value
            of the fingerprint metadata tag.
            Current functionality is not to check the value of an existing fingerprint metadata tag and just overwrite
            it as this is automatically filled out.
        :param rule_to_generate_id: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the fingerprint metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: This should return True all the time as there will always be a return from self.calculate_rule_hash
        """
        FINGERPRINT = tag_key
        self.required_fields[FINGERPRINT].attributefound()
        self.required_fields_index[self.required_fields[FINGERPRINT].position].increment_count()

        rule_hash = Helper.calculate_rule_hash(rule_to_generate_id)
        if rule_hash:
            rule_id = {FINGERPRINT: rule_hash}
            if Helper.valid_metadata_index(rule_to_generate_id, tag_index):
                if list(rule_to_generate_id[METADATA][tag_index].keys())[0] == FINGERPRINT:
                    rule_to_generate_id[METADATA][tag_index] = rule_id
                    self.required_fields[FINGERPRINT].attributevalid()
                else:
                    rule_to_generate_id[METADATA].insert(tag_index, rule_id)
                    self.required_fields[FINGERPRINT].attributevalid()
            else:
                rule_to_generate_id[METADATA].append(rule_id)
                self.required_fields[FINGERPRINT].attributevalid()

        return self.required_fields[FINGERPRINT].valid

    def valid_version(self, rule_to_version_check, tag_index, tag_key):
        """
        This value can be generated: there is the option to verify if an existing version format is correct, insert a
            generated version if none was found and if the potential default metadata index would be out of bounds
            appends a generated version
        :param rule_to_version_check: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the version metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the version is of the correct format and False if it is not
        """
        VERSION = tag_key
        self.required_fields[VERSION].attributefound()
        self.required_fields_index[self.required_fields[VERSION].position].increment_count()

        rule_version = {VERSION: '1.0'}
        if Helper.valid_metadata_index(rule_to_version_check, tag_index):
            if list(rule_to_version_check[METADATA][tag_index].keys())[0] == VERSION:
                if isinstance(version.parse(list(rule_to_version_check[METADATA][tag_index].values())[0]), version.Version):
                    self.required_fields[VERSION].attributevalid()
                else:
                    self.required_fields[VERSION].attributeinvalid()
            else:
                rule_to_version_check[METADATA].insert(tag_index, rule_version)
                self.required_fields[VERSION].attributevalid()
        else:
            rule_to_version_check[METADATA].append(rule_version)
            self.required_fields[VERSION].attributevalid()

        return self.required_fields[VERSION].valid

    def valid_date(self, rule_to_date_check, tag_index, tag_key):
        """
        This value can be generated: there is the option to verify if an existing date is correct, insert a generated
            date if none was found and if the potential default metadata index would be out of bounds appends
            a generated date
        :param rule_to_date_check: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the last_modified metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value matches the valid date format and False if it does not match it
        """
        DATE = tag_key
        self.required_fields[DATE].attributefound()
        self.required_fields_index[self.required_fields[DATE].position].increment_count()

        if Helper.valid_metadata_index(rule_to_date_check, tag_index):
            if list(rule_to_date_check[METADATA][tag_index].keys())[0] == DATE:
                if Helper.validate_date(list(rule_to_date_check[METADATA][tag_index].values())[0]):
                    self.required_fields[DATE].attributevalid()
                else:
                    self.required_fields[DATE].attributeinvalid()
            else:
                rule_date = {DATE: Helper.current_valid_date()}
                rule_to_date_check[METADATA].insert(tag_index, rule_date)
                self.required_fields[DATE].attributevalid()
        else:
            rule_date = {DATE: Helper.current_valid_date()}
            rule_to_date_check[METADATA].append(rule_date)
            self.required_fields[DATE].attributevalid()

        return self.required_fields[DATE].valid

    def valid_first_imported(self, rule_to_date_check, tag_index, tag_key):
        """
        This value can be generated: there is the option to verify if an existing date is correct, insert a generated
            date if none was found and if the potential default metadata index would be out of bounds appends
            a generated date
        :param rule_to_date_check: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the last_modified metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value matches the valid date format and False if it does not match it
        """
        FIRST_IMPORTED = tag_key
        self.required_fields[FIRST_IMPORTED].attributefound()
        self.required_fields_index[self.required_fields[FIRST_IMPORTED].position].increment_count()

        if Helper.valid_metadata_index(rule_to_date_check, tag_index):
            if list(rule_to_date_check[METADATA][tag_index].keys())[0] == FIRST_IMPORTED:
                if Helper.validate_date(list(rule_to_date_check[METADATA][tag_index].values())[0]):
                    self.required_fields[FIRST_IMPORTED].attributevalid()
                else:
                    self.required_fields[FIRST_IMPORTED].attributeinvalid()
            else:
                rule_date = {FIRST_IMPORTED: Helper.current_valid_date()}
                rule_to_date_check[METADATA].insert(tag_index, rule_date)
                self.required_fields[FIRST_IMPORTED].attributevalid()
        else:
            rule_date = {FIRST_IMPORTED: Helper.current_valid_date()}
            rule_to_date_check[METADATA].append(rule_date)
            self.required_fields[FIRST_IMPORTED].attributevalid()

        return self.required_fields[FIRST_IMPORTED].valid

    def valid_last_modified(self, rule_to_date_check, tag_index, tag_key):
        """
        This value can be generated: there is the option to verify if an existing date is correct, insert a generated
            date if none was found and if the potential default metadata index would be out of bounds appends a
                generated date
        :param rule_to_date_check: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the last_modified metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value matches the valid date format and False if it does not match it
        """
        LAST_MODIFIED = tag_key
        self.required_fields[LAST_MODIFIED].attributefound()
        self.required_fields_index[self.required_fields[LAST_MODIFIED].position].increment_count()

        current_date = Helper.current_valid_date()
        if Helper.valid_metadata_index(rule_to_date_check, tag_index):
            if list(rule_to_date_check[METADATA][tag_index].keys())[0] == LAST_MODIFIED:
                rule_to_date_check[METADATA][tag_index][LAST_MODIFIED] = current_date
                if Helper.validate_date(list(rule_to_date_check[METADATA][tag_index].values())[0]):
                    self.required_fields[LAST_MODIFIED].attributevalid()
                else:
                    self.required_fields[LAST_MODIFIED].attributeinvalid()
            else:
                rule_date = {LAST_MODIFIED: current_date}
                rule_to_date_check[METADATA].insert(tag_index, rule_date)
                self.required_fields[LAST_MODIFIED].attributevalid()
        else:
            rule_date = {LAST_MODIFIED: current_date}
            rule_to_date_check[METADATA].append(rule_date)
            self.required_fields[LAST_MODIFIED].attributevalid()

        return self.required_fields[LAST_MODIFIED].valid
    
    def valid_source(self, rule_to_source_check, tag_index, tag_key):
        """
        Validates the source
        :param rule_to_source_check:
        :param tag_index: used to reference what the array index of the last_modified metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value matches the UNIVERSAL_REGEX and False if it does not match it
        """
        SOURCE = tag_key
        REFERENCE = self.required_fields[SOURCE].argument.get("required")
        self.required_fields[SOURCE].attributefound()
        self.required_fields_index[self.required_fields[SOURCE].position].increment_count()

        metadata = rule_to_source_check[METADATA]
        source_to_check = metadata[tag_index][SOURCE]
        if re.fullmatch(UNIVERSAL_REGEX, source_to_check):
            self.required_fields[SOURCE].attributevalid()
        elif re.fullmatch(UNIVERSAL_REGEX, str(source_to_check).upper()):
            source_to_check = str(source_to_check).upper()
            metadata[tag_index][SOURCE] = source_to_check
            self.required_fields[SOURCE].attributevalid()
        else:
            self.required_fields[SOURCE].attributeinvalid()

        if re.fullmatch(OPENSOURCE_REGEX, source_to_check):
            # Because the source is OPENSOURCE a reference is required
            self.required_fields[REFERENCE].optional = TagOpt.REQ_PROVIDED

        return self.required_fields[SOURCE].valid
    
    def valid_mitre_att(self, rule_to_validate_mitre_att, tag_index, tag_key):
        """
        Pulls the value of the mitre_att metadata tag and passes it to validate_mitre_att_by_id
        :param rule_to_validate_mitre_att: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the mitre_att metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value was found in the MITRE ATT&CK database and False if it was not found
        """
        MITRE_ATT = tag_key
        self.required_fields[MITRE_ATT].attributefound()
        self.required_fields_index[self.required_fields[MITRE_ATT].position].increment_count()

        metadata = rule_to_validate_mitre_att[METADATA]
        mitre_att_to_validate = str(metadata[tag_index][MITRE_ATT]).upper()
        metadata[tag_index][MITRE_ATT] = mitre_att_to_validate
        if Helper.validate_mitre_att_by_id(mitre_att_to_validate):
            self.required_fields[MITRE_ATT].attributevalid()
        else:
            self.required_fields[MITRE_ATT].attributeinvalid()

        return self.required_fields[MITRE_ATT].valid
    
    def valid_al_config_dumper(self, rule_to_validate_al_config_d, tag_index, tag_key):
        """
        Makes the al_config_parser metadata tag required if this is found first.
        :param rule_to_validate_al_config_d: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the actor metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True all the time because the value is never verified...
        """
        AL_CONFIG_D = tag_key
        self.required_fields[AL_CONFIG_D].attributefound()
        self.required_fields_index[self.required_fields[AL_CONFIG_D].position].increment_count()

        # Because there is an al_config_dumper al_config_parser becomes required
        self.required_fields[AL_CONFIG_D].optional = TagOpt.REQ_PROVIDED

        # Because we are not validating the value... So much pain!
        self.required_fields[AL_CONFIG_D].attributevalid()

        return self.required_fields[AL_CONFIG_D].valid
    
    def valid_al_config_parser(self, rule_to_validate_al_config_p, tag_index, tag_key):
        """
        Makes the al_config_dumper metadata tag required if this is found first.
        :param rule_to_validate_al_config_p: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the actor metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True all the time because the value is never verified...
        """
        AL_CONFIG_P = tag_key
        self.required_fields[AL_CONFIG_P].attributefound()
        self.required_fields_index[self.required_fields[AL_CONFIG_P].position].increment_count()

        # Because there is an al_config_parser al_config_dumper becomes required
        self.required_fields[AL_CONFIG_P].optional = TagOpt.REQ_PROVIDED

        # Because we are not validating the value... So much pain!
        self.required_fields[AL_CONFIG_P].attributevalid()

        return self.required_fields[AL_CONFIG_P].valid
    
    def valid_category(self, rule_to_validate_category, tag_index, tag_key):
        """
        Pulls the value of the category metadata tag and checks if it is a valid category type.
            Valid options are stored in self.category_types. If the category value is valid and a new metadata
            tag with a name the same as the category value is added to be searched for.
            This new metadata tag links to the same object as the initially created self.required_fields[CATEGORY_TYPE].
        :param rule_to_validate_category: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the category metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value was found in self.category_types and False if it was not found
        """
        CATEGORY = tag_key
        self.required_fields[CATEGORY].attributefound()
        self.required_fields_index[self.required_fields[CATEGORY].position].increment_count()
        child_tag_place_holder = self.required_fields[CATEGORY].argument.get("child_place_holder")

        metadata = rule_to_validate_category[METADATA]
        rule_category_to_check = metadata[tag_index][CATEGORY]
        if rule_category_to_check in self.category_types:
            self.required_fields[CATEGORY].attributevalid()
            add_category_type_to_required = {str(rule_category_to_check).lower(): self.required_fields[child_tag_place_holder]}
            self.required_fields_children.update(add_category_type_to_required)
        elif str(rule_category_to_check).upper() in self.category_types:
            rule_category_to_check = str(rule_category_to_check).upper()
            metadata[tag_index][CATEGORY] = rule_category_to_check
            self.required_fields[CATEGORY].attributevalid()
            add_category_type_to_required = {str(rule_category_to_check).lower(): self.required_fields[child_tag_place_holder]}
            self.required_fields_children.update(add_category_type_to_required)
        else:
            self.required_fields[CATEGORY].attributeinvalid()

        return self.required_fields[CATEGORY].valid
    
    def valid_category_type(self, rule_to_validate_type, tag_index, tag_key):
        """
        This will be called by the new tag created by the valid_category function. Because it references the same object
            as that initialized as CATEGORY_TYPE we can use that to reference the reqired tag in this function.
        :param rule_to_validate_type: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the category_type metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value matches the Regex expression and False if it was not found
        """
        CATEGORY = "category"
        child_tag_place_holder = self.required_fields[CATEGORY].argument.get("child_place_holder")
        self.required_fields[child_tag_place_holder].attributefound()
        self.required_fields_index[self.required_fields[child_tag_place_holder].position].increment_count()

        metadata = rule_to_validate_type[METADATA]
        rule_category_key_to_check = list(metadata[tag_index].keys())[0]
        rule_category_value_to_check = list(metadata[tag_index].values())[0]
        if re.fullmatch(CATEGORY_TYPE_REGEX, rule_category_value_to_check):
            self.required_fields[child_tag_place_holder].attributevalid()
        elif re.fullmatch(CATEGORY_TYPE_REGEX, str(rule_category_value_to_check).upper()):
            rule_category_value_to_check = str(rule_category_value_to_check).upper()
            metadata[tag_index][rule_category_key_to_check] = rule_category_value_to_check
            self.required_fields[child_tag_place_holder].attributevalid()
        else:
            self.required_fields[child_tag_place_holder].attributeinvalid()

        return self.required_fields[child_tag_place_holder].valid
    
    def valid_actor(self, rule_to_validate_actor, tag_index, tag_key):
        """
        Validates the actor, makes the actor_type metadata tag required.
            Adds a required metadata tag for mitre_group to hold the a potential alias value.
            Also stores the value of the actor metadata tag in self.mitre_group_alias variable for use with the
            mitre_group_generator function
        :param rule_to_validate_actor: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the actor metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: True if the value matches the self.mitre_group_alias_regex and False if it does not
        """
        ACTOR = tag_key
        ACTOR_TYPE = self.required_fields[ACTOR].argument.get("required")
        child_tag = self.required_fields[ACTOR].argument.get("child")
        child_tag_place_holder = self.required_fields[ACTOR].argument.get("child_place_holder")
        mitre_group_alias_regex = "^[A-Z 0-9\s._-]+$"

        self.required_fields[ACTOR].attributefound()
        self.required_fields_index[self.required_fields[ACTOR].position].increment_count()

        # Because there is an actor actor_type becomes required
        self.required_fields[ACTOR_TYPE].optional = TagOpt.REQ_PROVIDED
        metadata = rule_to_validate_actor[METADATA]
        actor_to_check = metadata[tag_index][ACTOR]
        if re.fullmatch(mitre_group_alias_regex, actor_to_check):
            self.required_fields[ACTOR].attributevalid()
            add_mitre_group_to_required = {child_tag: self.required_fields[child_tag_place_holder]}
            self.required_fields_children.update(add_mitre_group_to_required)
            self.mitre_group_alias = actor_to_check
        elif re.fullmatch(mitre_group_alias_regex, str(actor_to_check).upper()):
            actor_to_check = str(actor_to_check).upper()
            metadata[tag_index][ACTOR] = actor_to_check
            self.required_fields[ACTOR].attributevalid()
            add_mitre_group_to_required = {child_tag: self.required_fields[child_tag_place_holder]}
            self.required_fields_children.update(add_mitre_group_to_required)
            self.mitre_group_alias = actor_to_check
        else:
            self.required_fields[ACTOR].attributeinvalid()

        return self.required_fields[ACTOR].valid
    
    def mitre_group_generator(self, rule_to_generate_group, tag_index, tag_key):
        """
        This will only be looked for if the actor metadata tag has already been processed.
            Current functionality is not to check the value of an existing mitre_group metadata tag and just overwrite
            it as this is automatically filled out. Also if no alias is found it will be removed.
        :param rule_to_generate_group: the plyara parsed rule that is being validated
        :param tag_index: used to reference what the array index of the mitre_group metadata tag is
        :param tag_key: the name of the metadata tag that is being processed
        :return: This should return True all the time as there will always be a return from self.get_group_from_alias
        """
        ACTOR = "actor"
        place_holder = self.required_fields[ACTOR].argument.get("child_place_holder")
        if self.required_fields.get(tag_key):  # if child place holder is passed as tag_key
            MITRE_GROUP = self.required_fields[self.required_fields[tag_key].argument['parent']].argument['child']
        else:
            MITRE_GROUP = tag_key

        mitre_group = str(Helper.get_group_from_alias(self.mitre_group_alias)).upper()
        rule_group = {MITRE_GROUP: mitre_group}
        if Helper.valid_metadata_index(rule_to_generate_group, tag_index):
            if list(rule_to_generate_group[METADATA][tag_index].keys())[0] == MITRE_GROUP:
                if mitre_group:
                    rule_to_generate_group[METADATA][tag_index] = rule_group
                    self.required_fields[place_holder].attributefound()
                    self.required_fields[place_holder].attributevalid()
                    self.required_fields_index[self.required_fields[place_holder].position].increment_count()
                else:
                    rule_to_generate_group[METADATA].pop(tag_index)
                    return True
            else:
                if mitre_group:
                    rule_to_generate_group[METADATA].insert(tag_index, rule_group)
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
    VALIDATOR_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_Yara_values.yml'
    CONFIGURATION_YAML_PATH = SCRIPT_LOCATION.parent / 'CCCS_Yara.yml'

    fs = FileSystemSource(MITRE_STIX_DATA_PATH)

    @staticmethod
    def valid_metadata_index(rule, index):
        """
        Ensures that the index will not return an out of bounds error
        :param rule: the plyara parsed rule that is being validated
        :param index: the potential index
        :return: True if the potential index will not be out of bounds and false otherwise
        """
        count_of_tags = len(rule[METADATA])
        if index >= count_of_tags:
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
        Looks to replace yara string references in conditions such as $a*. The function looks to match all matching
            string names and compile a completed list of those string values
        :param string_name_preface: Can be one of "$", "!", "#", or "@"
        :param string_name_expression: The string name expression that will be converted into a regex pattern
        :param string_substitutions: the dict of all string substitutions and values
        :return: the completed list of string values whose string names match the expression
        """
        string_name, string_suffix = string_name_expression[:-1], string_name_expression[-1:]
        string_name_regex = "^\\" + string_name + "." + string_suffix + "$"
        string_value_matches = []
        for key in string_substitutions.keys():
            if re.fullmatch(string_name_regex, key):
                string_value_matches.append(string_name_preface+string_substitutions[key])

        return string_value_matches

    @staticmethod
    def resort_stings_add_commas(list_of_strings):
        """
        Takes a list of string values and rebuilds it as a sting with comma delimiters so it would look like a hard
            coded yara list of strings
        :param list_of_strings: the list of collected string values
        :return: the sorted list
        """
        list_of_strings.sort()
        count_of_strings = len(list_of_strings)

        for index, string in enumerate(list_of_strings):
            if index + 1 < count_of_strings:
                list_of_strings.insert(index+index+1, ',')

        return list_of_strings

    # This comes from "https://gist.github.com/Neo23x0/577926e34183b4cedd76aa33f6e4dfa3" Cyb3rOps.
    # There have been significant changes to this function to better generate a hash of the strings and conditions
    @staticmethod
    def calculate_rule_hash(rule):
        """
        Calculates a hash over the relevant YARA rule content (string contents, sorted condition)
        Requires a YARA rule object as generated by 'plyara': https://github.com/plyara/plyara
        :param rule: yara rule object
        :return hash: generated hash
        """
        hash_strings = []
        condition_string_prefaces = ("$", "!", "#", "@")
        # dictionary for substitutions
        string_substitutions = {}
        all_strings = []
        # original code used md5
        # m = hashlib.md5()
        m = hashlib.sha3_256()
        # Adding all string contents to the list
        if 'strings' in rule:
            for s in rule['strings']:
                if s['type'] == "byte":
                    # original code just needed to append the converted hex code as a string. We need to create the dictionary entries for substitutions as well
                    # hash_strings.append(re.sub(r'[^a-fA-F\?0-9]+', '', s['value']))
                    byte_code_string = re.sub(r'[^a-fA-F\?0-9]+', '', s['value'])
                    dict_entry = {s['name']: byte_code_string}
                    string_substitutions.update(dict_entry)
                    hash_strings.append(byte_code_string)
                else:
                    # The following line was the only portion of this else statement in the original code
                    # This change takes modifiers into account for string arguments
                    # hash_strings.append(s['value'])
                    string_and_modifiers = []
                    string_and_modifiers.append(s['value'])
                    if 'modifiers' in s:
                        for modifier in s['modifiers']:
                            string_and_modifiers.append(modifier)
                    string_and_modifiers = " ".join(string_and_modifiers)
                    all_strings.append("$" + string_and_modifiers)
                    dict_entry = {s['name']: string_and_modifiers}
                    string_substitutions.update(dict_entry)
                    # hash_strings.append("$"+string_and_modifiers)
        all_strings = Helper.resort_stings_add_commas(all_strings)
        # Adding the components of the condition to the list (except the variables)
        all_wild_card_1 = "\$\*"
        all_wild_card_2 = "them"
        for e in rule['condition_terms']:
            if re.match(all_wild_card_1, e) or re.match(all_wild_card_2, e):
                hash_strings.extend(all_strings)
            elif e.startswith(condition_string_prefaces):
                if len(e) > 1:
                    string_preface, string_name = e[:1], e[1:]
                    string_name = "$" + string_name
                    if e.endswith("*"):
                        hash_strings.extend(Helper.resort_stings_add_commas(
                            Helper.regex_match_string_names_for_values(string_preface, string_name,
                                                                     string_substitutions)))
                        # hash_strings.extend("Pull all the matching strings")
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
        m.update("".join(hash_strings).encode("ascii"))
        return m.hexdigest()

    @staticmethod
    def validate_date(date_to_validate):
        """
        Verifies a date is in the correct format.
        :param date_to_validate: the value of the last_modifed metadata tag
        :return: True if the value is in the correct format or False if it is not valid
        """
        try:
            if date_to_validate != datetime.datetime.strptime(date_to_validate, "%Y-%m-%d").strftime('%Y-%m-%d'):
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
        :param id_code: The value of the mitre_att metadata tag
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
        :param id_code: The value of the mitre_att metadata tag
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
        :param id_code: The value of the mitre_att metadata tag
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        malware_return =  Helper.fs.query([
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
        :param id_code: The value of the mitre_att metadata tag
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
        :param id_code: The value of the mitre_att metadata tag
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
        :param id_code: The value of the mitre_att metadata tag
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
        :param id_code: The value of the mitre_att metadata tag
        :return: The return of the query of the MITRE ATT&CK database, null if there are no matches
        """
        return Helper.fs.query([
            Filter('external_references.external_id', '=', id_code)
        ])

    @staticmethod
    def validate_mitre_att_by_id(id_code):
        """
        Checks the preface of the id_code and sends the id_code to specific functions
            This is done because using specified filters based on the type is about 20 times more efficient then
            the entire MITRE ATT&CK database with the id_code.
            There is a catch all provided in the case that there are new ID Code types added in the future
        :param id_code: The value of the mitre_att metadata tag
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
        :return: Either returns the MITRE ATT&CK group name or returns "" if the query returns null
        """
        group_from_alias =  Helper.fs.query([
            Filter('type', '=', 'intrusion-set'),
            FilterCasefold('aliases', 'casefold', alias)
        ])

        if not group_from_alias:
            return ""

        return group_from_alias[0][MITRE_GROUP_NAME]
