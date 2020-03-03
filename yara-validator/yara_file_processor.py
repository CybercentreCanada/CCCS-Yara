import plyara.utils
import collections
import re
from pathlib import Path


class YaraFileProcessor:
    """
    YaraFileProcessor class is used to process a given rule file and parse it into one or more
    """

    def __init__(self, rule_file):
        parser = plyara.Plyara()
        # Original rule file
        self.original_rule_file = rule_file
        yara_rule_file = open(rule_file, encoding='utf-8')
        # String representation of original rule file
        self.original_rule_string = yara_rule_file.read()
        yara_rule_file.close()
        # String representation to contain edits to the original rule
        self.edited_rule_string = ""
        # Plyara parsed ruler_file
        self.plyara_rule = parser.parse_string(self.original_rule_string)
        # The number of rules found in the file
        self.count_of_rules = len(self.plyara_rule)
        # Process the string and PlYara into an array of YaraRule objects
        self.yara_rules = []
        self.__process_rule_representiations_to_array()

    def __process_rule_representiations_to_array(self):
        """
        Processes the contents of the rule file into an array of YaraObjects, one object per yara rule found
            Each YaraObject contains the string representation of the rule, the plyara representation and
            a rule reutrn object
        :return:
        """
        if self.count_of_rules > 0:
            yara_rule_split_line = self.original_rule_string.splitlines()
            for plyara_rule in self.plyara_rule:
                string_of_rule = yara_rule_split_line[plyara_rule['start_line'] - 1:plyara_rule['stop_line']]
                string_of_rule = "\n".join(string_of_rule)
                yara_rule = YaraRule(string_of_rule, plyara_rule)
                self.yara_rules.append(yara_rule)

    def string_of_rule_to_original_file(self):
        """
        This rebuilds a rule string incorporating any changes from the rule return objects
        :return:
        """
        edited_rule_string = self.original_rule_string.splitlines()
        yara_rules_reversed = self.yara_rules
        yara_rules_reversed.reverse()
        for rule in yara_rules_reversed:
            if rule.rule_return:
                if isinstance(rule.rule_return, YaraReturn):
                    changed_rule_string = rule.rule_return.edited_rule.splitlines()
                else:
                    changed_rule_string = rule.rule_return.validated_rule.splitlines()
                edited_rule_string = edited_rule_string[0:rule.rule_plyara['start_line'] - 1]\
                                        + changed_rule_string + edited_rule_string[rule.rule_plyara['stop_line']:]

        edited_rule_string = "\n".join(edited_rule_string)
        self.edited_rule_string = edited_rule_string

    def string_of_rule_to_multi_file(self):
        """
        This will potentially rebuild a multi-rule yara file into an array of strings. Each string will represent a
            single yara rule which will incorporate any changes from the rule return objects.

            NO CONTENT YET
        :return:
        """

    def return_edited_rule_string(self):
        return self.edited_rule_string

class YaraRule:
    """
    YaraRule objects contain a string representation of a rule, a plyara representation of the rule and the RuleReturn
        object
    """

    def __init__(self, rule_string, rule_plyara):
        self.rule_string = rule_string
        self.rule_plyara = rule_plyara
        self.rule_return = YaraReturn(rule_string)

    def add_rule_return(self, rule_return):
        self.rule_return = rule_return

class YaraReturn:
    """
    YaraReturn class used to pass the error state of the processed rules, what metadata tags have issues,
        a string representation of the original rule and if the rule has no errors a string representation of the rule
        with all the created or changed metadata tags, etc.
    """
    def __init__(self, original_rule):
        # Overall rule error flag
        self.rule_errors = False
        # Overall warning flag
        self.rule_warnings = False
        # each possible metadata tag
        self.errors = collections.OrderedDict()
        # collection of all the warnings
        self.warnings = collections.OrderedDict()
        # the original_rule
        self.original_rule = original_rule
        # set
        self.edited_rule = None

    def update_error(self, rule_error, error_tag, message):
        if not self.rule_errors:
           self.rule_errors = rule_error

        self.errors[error_tag] = message

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
        if not self.rule_errors:
            error_string = self.__build_return_string(self.errors)

        return error_string

    def return_errors_for_cmlt(self):
        error_string = ""
        if not self.rule_errors:
            error_string = self.__build_return_string_cmlt(self.errors)

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
        return self.original_rule

    def return_edited_rule(self):
        return self.edited_rule

    def set_edited_rule(self, edited_rule):
        self.edited_rule = edited_rule

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
        Rebuilds the rule if there are no errors and as long as there are changes. This was created to maintain
            any comments outside of the metadata section
        :return: No return
        """
        if self.edited_rule[-1] == '\n':
            self.edited_rule = self.edited_rule[:-1]

        if self.original_rule is None or self.edited_rule is None:
            exit()
        elif self.original_rule == self.edited_rule:
            return

        yara_original_lines, yara_original_meta_start, yara_original_meta_end = self.__find_meta_start_end(self.original_rule)
        yara_edited_lines, yara_edited_meta_start, yara_edited_meta_end = self.__find_meta_start_end(self.edited_rule)

        if yara_original_meta_start != 0 and yara_original_meta_end != 0 and yara_edited_meta_start != 0 and yara_edited_meta_end != 0:
            yara_new_file = yara_original_lines[0:yara_original_meta_start] + yara_edited_lines[yara_edited_meta_start:yara_edited_meta_end] + yara_original_lines[yara_original_meta_end:]
            yara_new_file = "\n".join(yara_new_file)
            if self.original_rule != yara_new_file:
                self.edited_rule = yara_new_file