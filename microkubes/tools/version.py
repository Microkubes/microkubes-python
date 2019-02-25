"""Version endpoint
"""

import json
import logging
import sys


def add_version_endpoint(app, config):
    """Adds Flask endpoint that returns the microservice version.

    :param app: ``Flask``, Flask app instance.
    :param config: ``dict``, The configuration in a dict format.

    """
    version = config.get('version')

    if version is None:
        logging.error('Field "version" does not exist in the configuration file.')
        sys.exit(1)

    def _version_endpoint():
        version_dict = {
            'version': version
        }
        return json.dumps(version_dict)

    app.route('/version')(_version_endpoint)
