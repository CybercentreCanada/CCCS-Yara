import plyara.utils
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
        self.rule_return = None

    def add_rule_return(self, rule_return):
        self.rule_return = rule_return
