""" This class

"""

from stix2 import Filter
from datetime import datetime

# add the casefold to the supported filter operations
from stix2.datastore.filters import FILTER_OPS
FILTER_OPS.append('casefold')

class FilterCasefold(Filter):
    def _check_property(self, stix_obj_property):
        """
        creating a filter that uses the .casefold() function to remove case sensitivity
        :param stix_obj_property:
        :return:
        """
        '''Had to keep the following code so that '''
        # If filtering on a timestamp property and the filter value is a string,
        # try to convert the filter value to a datetime instance.
        if isinstance(stix_obj_property, datetime) and \
                isinstance(self.value, six.string_types):
            filter_value = stix2.utils.parse_into_datetime(self.value)
        else:
            filter_value = self.value

        if self.op == "casefold":
            return stix_obj_property.casefold() == filter_value.casefold()
        else:
            Filter._check_property(self, stix_obj_property)