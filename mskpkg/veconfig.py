#!/usr/bin/env python

"""This module loads the conf file for VE(s) and returns list
"""

import json


class loadveconfig(object):
    """
    Class to get the configuration and returns an Delphix authentication
    object
    """

    def __init__(self):
        self.dlpx_engines = {}

    def __getitem__(self, key):
        return self.dlpx_engines[key]

    def get_config(self, config_file_path='./dxtools.conf'):
        """
        This method reads in the dxtools.conf file

        config_file_path: path to the configuration file.
                          Default: ./dxtools.conf
        """

        # First test to see that the file is there and we can open it
        try:
            with open(config_file_path) as config_file:

                # Now parse the file contents as json and turn them into a
                # python dictionary, throw an error if it isn't proper json
                config = json.loads(config_file.read())

        except IOError:
            raise DlpxException('\nERROR: Was unable to open {}. Please '
                                'check the path and permissions, and try '
                                'again.\n'.format(config_file_path))

        except (ValueError, TypeError, AttributeError) as e:
            raise DlpxException('\nERROR: Was unable to read {} as json. '
                                'Please check if the file is in a json format'
                                ' and try again.\n {}'.format(config_file_path,
                                                              e))

        # Create a dictionary of engines (removing the data node from the
        # dxtools.json, for easier parsing)
        for each in config['data']:
            self.dlpx_engines[each['hostname']] = each
