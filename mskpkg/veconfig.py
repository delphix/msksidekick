#!/usr/bin/env python

"""This module loads the conf file for VE(s) and returns list
"""

import json
import os
import sys
from mskpkg.DlpxException import DlpxException


class loadveconfig(object):
    """
    Class to get the configuration and returns an Delphix authentication
    object
    """

    def __init__(self):
        self.dlpx_engines = {}

        if getattr(sys, 'frozen', False):
            # If the application is run as a bundle, the PyInstaller bootloader
            # extends the sys module by a flag frozen=True and sets the app
            # path into variable _MEIPASS'.
            # script_dir = sys._MEIPASS
            self.scriptdir = os.path.dirname(sys.executable)
        else:
            self.scriptdir = os.path.dirname(os.path.abspath(__file__))

    def __getitem__(self, key):
        return self.dlpx_engines[key]

    def get_config(self, config_file_path=None):
        """
        This method reads in the dxtools.conf file

        config_file_path: path to the configuration file.
                          Default: "{}/dxtools.conf".format(scriptdir)
        """
        config_file_path = "{}/dxtools.conf".format(self.scriptdir)
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
