"""Read configuration from file
"""

import sys
import logging
import json
from json.decoder import JSONDecodeError


def read_config(config_path):
    """Read configuration from file.

    :param config_path: ``str``, The config file path.

    :returns: ``dict``, The configuration in a dict format.

    """
    try:
        with open(config_path) as json_file:
            data = json.load(json_file)
            return data
    except FileNotFoundError:
        logging.error('Please provide a valid path for config file.')
        sys.exit(1)
    except JSONDecodeError:
        logging.error('The configuration you provided is not a valid JSON.')
        sys.exit(1)
