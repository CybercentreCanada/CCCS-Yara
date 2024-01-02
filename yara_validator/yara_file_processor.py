import plyara.utils
import collections
import re
import yara
from pathlib import Path

SYNTAX_ERRORS_INCLUDES = re.compile(r'.*can\'t open include file')
SYNTAX_ERRORS_UNDEFINED_MODULES = re.compile(
    r'.*undefined identifier (?="pe"|"elf"|"cuckoo"|"magic"|"hash"|"math"|"dotnet"|"time")')
SYNTAX_ERRORS_UNDEFINED = re.compile(r'.*undefined identifier')

class YaraFileProcessor:
    """
    YaraFileProcessor class is used to process a given rule file and parse it into one or more YARA rules
    """

    def __init__(self, rule_file, char_to_replace, char_replacement, count_of_replaced,
                 check_import_modules=True, check_rule_dependancies=False):
        # Original rule file
        self.original_rule_file = rule_file
        # Variables for the white space standardization
        self.char_to_replace = char_to_replace.encode('utf-8').decode('unicode_escape')
        self.char_replacement = char_replacement.encode('utf-8').decode('unicode_escape')
        self.count_of_replaced = count_of_replaced
        # String representation to contain edits to the original rule
        self.edited_rule_string = ''
        # Array to contain the YARA rules
        self.yara_rules = []
        # Overall rule error flag
        self.file_errors = False
        # Overall warning flag
        self.file_warnings = False
        # collection of all the file errors
        self.errors = collections.OrderedDict()
        # collection of all the file warnings (not used yet)
        self.warnings = collections.OrderedDict()

        # Plyara object for parsing the yara rule file
        parser = plyara.Plyara()
        parser.STRING_ESCAPE_CHARS.add("r")
        file_name = ''
        # This block attempts to read the file as utf-8. If there are any issues with the file format or reading
        #   the file it creates a yara_rule object and sets the error state
        if isinstance(rule_file, str) or isinstance(rule_file, Path):
            if isinstance(rule_file, str):
                file_as_path = Path(self.original_rule_file)
            else:
                file_as_path = self.original_rule_file
            file_name = file_as_path.name
            with open(rule_file, encoding='utf-8') as yf:
                try:
                    self.original_rule_string = yf.read()
                except UnicodeDecodeError as e:
                    print('UnicodeDecodeError: ' + str(e))
                    file_response = 'UnicodeDecodeError:\t{!r}'.format(str(e))
                    self.update_file_error(True, str(file_name), file_response)
                    return
                except Exception as e:
                    print('There was an error opening the file: ' + str(e))
                    file_response = 'There was an error opening the file:\t{!r}'.format(str(e))
                    self.update_file_error(True, str(file_name), file_response)
                    return
        else:
            self.original_rule_string = rule_file
            file_name = 'File_Contents'

        # This block attempts to compile the self.original_rule_string. If there are any issues compiling the file it
        #   creates a yara_rule objects and sets the error state
        try:
            rules = yara.compile(source=self.original_rule_string)
        except yara.SyntaxError as e:
            file_response = None
            error_string = str(e)
            if SYNTAX_ERRORS_INCLUDES.match(error_string):
                pass
            elif SYNTAX_ERRORS_UNDEFINED_MODULES.match(error_string):
                if check_import_modules:
                    # print('Error Compiling YARA file with yara: ' + str(e))
                    file_response = 'Error Compiling YARA file with yara:\t{!r}'.format(str(e))
            elif SYNTAX_ERRORS_UNDEFINED.match(error_string):
                if check_rule_dependancies:
                    # print('Error Compiling YARA file with yara: ' + str(e))
                    file_response = 'Error Compiling YARA file with yara:\t{!r}'.format(str(e))
            else:
                # print('Error Compiling YARA file with yara: ' + str(e))
                file_response = 'Error Compiling YARA file with yara:\t{!r}'.format(str(e))

            if file_response:
                self.update_file_error(True, str(file_name), file_response)
                return

        except Exception as e:
            # print('Error Compiling YARA file with yara: ' + str(e))
            file_response = 'Error Compiling YARA file with yara:\t{!r}'.format(str(e))
            self.update_file_error(True, str(file_name), file_response)
            return

        # This block attempts to parse the self.original_rule_string. If there are any issues parsing the file it a
        #   yara_rule object and sets the error state
        try:
            self.plyara_rule = parser.parse_string(self.original_rule_string)
        except plyara.exceptions.ParseTypeError as e:
            # print('Error reported by plyara library: plyara.exceptions.ParseTypeError: ' + str(e))
            file_response = 'Error reported by plyara library: plyara.exceptions.ParseTypeError:\t{!r}'.format(str(e))
            self.update_file_error(True, str(file_name), file_response)
            return
        except Exception as e:
            # print('Error Parsing YARA file with plyara: ' + str(e))
            file_response = 'Error Parsing YARA file with plyara:\t{!r}'.format(str(e))
            self.update_file_error(True, str(file_name), file_response)
            return

        # The number of rules found in the file
        self.count_of_rules = len(self.plyara_rule)
        # Process the string and PlYara into an array of YaraRule objects
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

    def __replace_for_each_one_to_many(self, line):
        """
        Takes a line, transforms it into a list, parses through the list looking for the self.char_to_replace character
            and replaces each instance found with self.char_replacement * self.count_of_replaced
        :param line: a line that starts with at least one self.char_to_replace_character
        :return:
        """
        new_list = []
        character_replace = [self.char_replacement] * self.count_of_replaced
        line_as_list = list(line)
        non_white_space_index = 0
        for index, character in enumerate(line_as_list):
            if re.match(self.char_to_replace, character):
                new_list = new_list + character_replace
            elif re.match(self.char_replacement, character):
                new_list.append(character)
            else:
                non_white_space_index = index
                break

        if non_white_space_index == 0:
            non_white_space_index = len(line_as_list)
        new_list = new_list + line_as_list[non_white_space_index:]

        newline = ''.join(new_list)
        return newline

    def __standardize_white_space(self, edited_rule_string):
        """
        Takes the edited_rule_string, scans the start of each line for the self.char_to_replace and passes any line
            found to start with that character to __replace_for_each_one_to_many
        :param edited_rule_string: the array of lines
        :return:
        """
        regex_of_char_to_replace = '^' + '[' + self.char_to_replace + self.char_replacement + ']' + '+'
        for index, line in enumerate(edited_rule_string):
            if re.match(regex_of_char_to_replace, line):
                edited_rule_string[index] = self.__replace_for_each_one_to_many(line)

    def strings_of_rules_to_original_file(self):
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

        self.__standardize_white_space(edited_rule_string)
        edited_rule_string = '\n'.join(edited_rule_string)
        self.edited_rule_string = edited_rule_string

    def strings_of_rules_to_multi_files(self):
        """
        This will potentially rebuild a multi-rule yara file into an array of strings. Each string will represent a
            single yara rule which will incorporate any changes from the rule return objects.

            NO CONTENT YET
        :return:
        """

    def update_file_error(self, file_error, error_tag, message):
        if not self.file_errors:
            self.file_errors = file_error

        self.errors[error_tag] = message

    def update_file_warning(self, file_warning, warning_tag, message):
        if not self.file_warnings:
            self.file_warnings = file_warning

        self.warnings[warning_tag] = message

    def return_edited_file_string(self):
        return self.edited_rule_string

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

    def return_file_error_state(self):
        """
        Loops through the self.yara_rules array and returns true if any of the rules are in an error state
        :return:
        """
        error_state = False
        if self.file_errors:
            error_state = self.file_errors
            return error_state

        for rule in self.yara_rules:
            if rule.rule_return:
                if isinstance(rule.rule_return, YaraReturn):
                    if rule.return_error():
                        error_state = rule.return_error()
                        break
                else:
                    if not rule.rule_return.rule_validity:
                        error_state = not rule.rule_return.rule_validity
                        break

        return error_state

    def return_rule_errors(self):
        """
        Returns the any file errors and loops through the self.yara_rules array and returns a string for any errors
        :return: error_string, a string of all of the errors concatenated together
        """
        import warnings
        warnings.warn(
            'YaraFileProcessor.return_rule_errors() is deprecated, use YaraFileProcessor.return_file_errors() instead',
            DeprecationWarning
        )
        error_string = ''

        if self.file_errors:
            error_string = self.__build_return_string(self.errors)

        for rule in self.yara_rules:
            if rule.rule_return:
                if isinstance(rule.rule_return, YaraReturn):
                    if rule.return_error():
                        error_string = error_string + rule.return_errors()
                else:
                    if not rule.rule_return.rule_validity:
                        error_string = error_string + rule.return_errors()

        return error_string

    def return_file_errors(self):
        """
        Returns the any file errors and loops through the self.yara_rules array and returns a string for any errors
        :return: error_string, a string of all of the errors concatenated together
        """
        error_string = ''

        if self.file_errors:
            error_string = self.__build_return_string(self.errors)

        for rule in self.yara_rules:
            if rule.rule_return:
                if isinstance(rule.rule_return, YaraReturn):
                    if rule.return_error():
                        error_string = error_string + rule.return_errors()
                else:
                    if not rule.rule_return.rule_validity:
                        error_string = error_string + rule.return_errors()

        return error_string

    def return_rule_errors_for_cmlt(self):
        """
        Loops throught the self.yara_rules array and returns a string for of errors in cmlt format
        :return:
        """
        import warnings
        warnings.warn(
            'YaraFileProcessor.return_rule_errors_for_cmlt() is deprecated, '
            'use YaraFileProcessor.return_file_errors_for_cmlt() instead',
            DeprecationWarning
        )
        error_string = ''

        if self.file_errors:
            error_string = self.__build_return_string_cmlt(self.errors)

        for rule in self.yara_rules:
            if rule.rule_return:
                if isinstance(rule.rule_return, YaraReturn):
                    if rule.return_error():
                        error_string = error_string + "{indent:>8} {name:10}".format(indent="- ",
                                                                                     name=rule.get_rule_name() + ":\n")
                        error_string = error_string + rule.rule_plyara["rule_name"] + "\n"
                        error_string = error_string + rule.return_errors_for_cmlt()
                else:
                    if not rule.rule_return.rule_validity:
                        error_string = error_string + "{indent:>8} {name:10}".format(indent="- ",
                                                                                     name=rule.get_rule_name() + ":\n")
                        error_string = error_string + rule.return_errors_for_cmlt()

        return error_string

    def return_file_errors_for_cmlt(self):
        """
        Loops throught the self.yara_rules array and returns a string for of errors in cmlt format
        :return:
        """
        error_string = ''

        if self.file_errors:
            error_string = self.__build_return_string_cmlt(self.errors)

        for rule in self.yara_rules:
            if rule.rule_return:
                if isinstance(rule.rule_return, YaraReturn):
                    if rule.return_error():
                        error_string = error_string + "{indent:>8} {name:10}".format(indent="- ",
                                                                                     name=rule.get_rule_name() + ":\n")
                        error_string = error_string + rule.rule_plyara["rule_name"] + "\n"
                        error_string = error_string + rule.return_errors_for_cmlt()
                else:
                    if not rule.rule_return.rule_validity:
                        error_string = error_string + "{indent:>8} {name:10}".format(indent="- ",
                                                                                     name=rule.get_rule_name() + ":\n")
                        error_string = error_string + rule.return_errors_for_cmlt()

        return error_string

    def return_rule_warning_state(self):
        """
        Loops through the self.yara_rules array and returns true if any of the rules are in a warning state
        :return:
        """
        import warnings
        warnings.warn(
            'YaraFileProcessor.return_rule_warning_state() is deprecated, '
            'use YaraFileProcessor.return_file_warning_state() instead',
            DeprecationWarning
        )
        warning_state = False
        for rule in self.yara_rules:
            if rule.rule_return:
                if rule.return_warning():
                    warning_state = True
                    break

        return warning_state

    def return_file_warning_state(self):
        """
        Loops through the self.yara_rules array and returns true if any of the rules are in a warning state
        :return:
        """
        warning_state = False
        for rule in self.yara_rules:
            if rule.rule_return:
                if rule.return_warning():
                    warning_state = True
                    break

        return warning_state

    def return_rule_warnings(self):
        """
        Loops throught the self.yara_rules array and returns a string for of warnings
        :return:
        """
        import warnings
        warnings.warn(
            'YaraFileProcessor.return_rule_warnings() is deprecated, '
            'use YaraFileProcessor.return_file_warnings() instead',
            DeprecationWarning
        )
        warning_string = ''

        for rule in self.yara_rules:
            if rule.rule_return:
                if rule.return_warning():
                    warning_string = warning_string + rule.return_warnings()

        return warning_string

    def return_file_warnings(self):
        """
        Loops throught the self.yara_rules array and returns a string for of warnings
        :return:
        """
        warning_string = ''

        for rule in self.yara_rules:
            if rule.rule_return:
                if rule.return_warning():
                    warning_string = warning_string + rule.return_warnings()

        return warning_string

    def return_rule_warnings_for_cmlt(self):
        """
        Loops throught the self.yara_rules array and returns a string for of warnings in cmlt format
        :return:
        """
        import warnings
        warnings.warn(
            'YaraFileProcessor.return_rule_warnings_for_cmlt() is deprecated, '
            'use YaraFileProcessor.return_file_warnings_for_cmlt() instead',
            DeprecationWarning
        )
        warning_string = ''

        for rule in self.yara_rules:
            if rule.rule_return:
                if rule.return_warning():
                    warning_string = warning_string + "{indent:>8} {name:10}".format(indent="- ",
                                                                                     name=rule.get_rule_name() + ":\n")
                    warning_string = warning_string + rule.return_warnings_for_cmlt()

        return warning_string

    def return_file_warnings_for_cmlt(self):
        """
        Loops throught the self.yara_rules array and returns a string for of warnings in cmlt format
        :return:
        """
        warning_string = ''

        for rule in self.yara_rules:
            if rule.rule_return:
                if rule.return_warning():
                    warning_string = warning_string + "{indent:>8} {name:10}".format(indent="- ",
                                                                                     name=rule.get_rule_name() + ":\n")
                    warning_string = warning_string + rule.return_warnings_for_cmlt()

        return warning_string

    def return_original_rule(self):
        """
        Returns the original rule string
        :return:
        """
        import warnings
        warnings.warn(
            'YaraFileProcessor.return_original_rule() is deprecated, '
            'use YaraFileProcessor.return_original_file() instead',
            DeprecationWarning
        )
        return self.original_rule_string

    def return_original_file(self):
        """
        Returns the original rule string
        :return:
        """
        return self.original_rule_string

    def return_edited_rule(self):
        """
        Returns the edited rule string
        :return:
        """
        import warnings
        warnings.warn(
            'YaraFileProcessor.return_original_rule() is deprecated, '
            'use YaraFileProcessor.return_original_file() instead',
            DeprecationWarning
        )
        return self.edited_rule_string

    def return_edited_file(self):
        """
        Returns the edited rule string
        :return:
        """
        return self.edited_rule_string



class YaraRule:
    """
    YaraRule objects contain a string representation of a rule, a plyara representation of the rule and the RuleReturn
        object
    """

    def __init__(self, rule_string, rule_plyara):
        self.rule_string = rule_string
        self.rule_plyara = rule_plyara
        self.rule_name = str(self.rule_plyara.get('rule_name'))
        self.rule_return = YaraReturn(rule_string)

    def add_rule_return(self, rule_return):
        self.rule_return = rule_return

    def return_error(self):
        return self.rule_return.error_state()

    def return_errors(self):
        error_string = ''

        if isinstance(self.rule_return, YaraReturn):
            if self.rule_return.error_state():
                error_string = self.rule_return.return_errors()
                if error_string:
                    error_string = error_string + '\n'
        else:
            if not self.rule_return.rule_validity:
                error_string = self.rule_return.return_errors()
                if error_string:
                    error_string = error_string + '\n'

        return error_string

    def return_errors_for_cmlt(self):
        error_string = ''

        if isinstance(self.rule_return, YaraReturn):
            if self.rule_return.error_state():
                error_string = self.rule_return.return_errors_for_cmlt()
                if error_string:
                    error_string = error_string + '\n'
        else:
            if not self.rule_return.rule_validity:
                error_string = self.rule_return.return_errors_for_cmlt()
                if error_string:
                    error_string = error_string + '\n'

        return error_string

    def return_warning(self):
        return self.rule_return.warning_state()

    def return_warnings(self):
        warning_string = ''
        if self.rule_return.warning_state():
            warning_string = self.rule_return.return_warnings()
            if warning_string:
                warning_string = warning_string + '\n'

        return warning_string

    def return_warnings_for_cmlt(self):
        warning_string = ''
        if self.rule_return.warning_state():
            warning_string = self.rule_return.return_warnings_for_cmlt()
            if warning_string:
                warning_string = warning_string + '\n'

        return warning_string

    def return_rule_return(self):
        return self.rule_return

    def get_rule_name(self):
        return self.rule_name

    def return_original_rule(self):
        return self.rule_return.return_original_rule()

    def return_edited_rule(self):
        return self.rule_return.edited_rule()


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
        # collection of all the errors
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

    def error_state(self):
        return self.rule_errors

    def return_errors(self):
        error_string = ''
        if self.rule_errors:
            error_string = self.__build_return_string(self.errors)

        return error_string

    def return_errors_for_cmlt(self):
        error_string = ''
        if self.rule_errors:
            error_string = self.__build_return_string_cmlt(self.errors)

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
        return self.original_rule

    def return_edited_rule(self):
        return self.edited_rule

    def set_edited_rule(self, edited_rule):
        self.edited_rule = edited_rule

    def return_validated_rule(self):
        """
        Created to duplicate functionality from original YaraValidatorReturn class
        :return: returns the self.edited_rule instead of the original self.validated_rule
        """
        return self.edited_rule

    def set_validated_rule(self, valid_rule):
        """
        Created to duplicate functionality from original YaraValidatorReturn class
        :param valid_rule:
        :return:
        """
        self.edited_rule = valid_rule

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

        yara_new_file = []
        if yara_original_meta_start != 0 and yara_original_meta_end != 0 and yara_edited_meta_start != 0 and yara_edited_meta_end != 0:
            yara_new_file = yara_original_lines[0:yara_original_meta_start] + \
                            yara_edited_lines[yara_edited_meta_start:yara_edited_meta_end] + \
                            yara_original_lines[yara_original_meta_end:]
            yara_new_file = '\n'.join(yara_new_file)

        if self.original_rule != yara_new_file:
            self.edited_rule = yara_new_file
