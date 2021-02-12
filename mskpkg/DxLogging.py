"""
Package DxLogging
"""

import logging
import mskpkg.globals as globals

debug = None
VERSION = 'v.0.1'

def logging_est(logfile_path, debug=False):
    """
    Establish Logging

    logfile_path: path to the logfile. Default: current directory.
    debug: Set debug mode on (True) or off (False). Default: False
    """
    debug = globals.debug
    logging.basicConfig(filename=logfile_path,
                        format='%(levelname)s:%(asctime)s:%(message)s',
                        level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')

    logger = logging.getLogger()

    if debug is True:
        logger.setLevel(10)
        print_info('Debug Logging is enabled.')


def print_debug(print_obj, debug=False):
    """
    Call this function with a log message to prefix the message with DEBUG

    print_obj: Object to print to logfile and stdout
    debug: Flag to enable debug logging. Default: False
    :rtype: None
    """
    debug = globals.debug
    try:
        if debug is True:
            #print ('DEBUG: {}'.format(str('S----------------------------------------------------------------------------------------')))
            print ('DEBUG: {}'.format(str(print_obj)))
            #print ('DEBUG: {}'.format(str('E----------------------------------------------------------------------------------------')))
            logging.debug(str(print_obj))
    except:
        pass


def print_info(print_obj):
    """
    Call this function with a log message to prefix the message with INFO
    """
    print ('INFO: {}'.format(str(print_obj)))
    logging.info(str(print_obj))

def print_warning(print_obj):
    """
    Call this function with a log message to prefix the message with INFO
    """
    print ('WARN: %s' % (str(print_obj)))
    logging.warn(str(print_obj))

def print_exception(print_obj):
    """
    Call this function with a log message to prefix the message with EXCEPTION
    """
    print (str(print_obj))
    logging.exception('EXCEPTION: {}'.format(str(print_obj)))
