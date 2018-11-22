"""API Gateway tools for Microkubes.
"""


from urllib.parse import urljoin
import requests


class RegistrationException(Exception):
    """RegistrationException represents an exception that occured during the process
    of self-registration on the API Gateway.
    """
    pass

class Registrator:
    """Registers service to an API Gateway.

    This is a base class intended to implement the general behaviour for registration
    a service on the API Gateway.

    :param gw_admin_url: ``str``, the API Gateway base url for admin REST actions. The
        default value is ``"http://gateway:8001"``.

    """
    def __init__(self, gw_admin_url='http://gateway:8001'):
        self.gw_admin_url = gw_admin_url

    def _get_url(self, path, params=None):
        url = self.gw_admin_url
        if path:
            url += '/' + path

        trail_slash = url[-1] == '/'
        url = urljoin(url + '/', '.')
        if not trail_slash:
            url = url[0:-1]

        if params:
            url += '?' + '&'.join(['%s=%s' % (k, v) for k, v in sorted(params.items())])

        return url

    def register(self, **kwargs):
        """Register a service with the API Gateway.

        :param name: ``str``, the name of the service. This is required.
        :param paths: ``list``, list of paths to match the request path agaisnt. If any match,
            the request will be routed to the registered API. This parameter is required.
        :param host: ``str``, the actual (LAN) hostname of the service. This parameter is requred.
        :param port: ``int``, service port. The incoming trafic for the service will be routed to
            this port on the service ``host``.

        """
        if not kwargs.get('name'):
            raise ValueError('service name must be provided')

        if not kwargs.get('paths'):
            raise ValueError('paths must be set with at least one path')

        if not kwargs.get('host'):
            raise ValueError('host (vhost) must be provided')

        svc_def = {
            'name': kwargs['name'],
            'port': int(kwargs.get('port', 8080)),
            'paths': kwargs['paths'],
            'host': kwargs['host'],
        }

        try:
            return self.register_service(svc_def)
        except Exception as e:
            raise RegistrationException from e

    def register_service(self, service_def):
        """Actual registration of the service with the specific gateway.

        This method is intended to be overriden in a subclass to actually register
        the service with the specific gateway.

        :param service_def: ``dict``, contains the validated service definition. The
            following properties are guaranteed:

            - ``name`` - service name
            - ``port`` - service actual port
            - ``host`` - service actual host
            - ``paths`` - list of path patterns to register the service with

        """
        pass


class KongGatewayRegistrator(Registrator):
    """Registrator for Kong API Gateway.

    Registers services with Kong Gateway using the Kong admin API.

    :param gw_admin_url: ``str``, Kong Admin API base URL.

    """
    def __init__(self, gw_admin_url):
        super(KongGatewayRegistrator, self).__init__(gw_admin_url=gw_admin_url)

    def _to_api_params(self, service_def):
        return {
            'name': service_def['name'],
            'uris': ','.join(service_def['paths']),
            'upstream_url': 'http://%s:%d' % (service_def['host'], service_def['port']),
            "preserve_host": true,
        }

    def _get_api_by_name(self, api_name):
        resp = requests.get(self._get_url('/apis/' + api_name))
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return None
        raise RegistrationException(resp.json().get('message'))

    def _add_api(self, api_def):
        resp = requests.post(self._get_url('/apis/'), json=api_def)
        if resp.status_code != 201:
            raise RegistrationException(resp.json().get('message'))
        return resp.json()

    def _update_api(self, registered_api, api_def):
        uris = registered_api['uris']
        upstream_url = registered_api['upstream_url']
        if api_def.get('uris'):
            uris = api_def['uris']
        if api_def.get('upstream_url'):
            upstream_url = api_def['upstream_url']

        data = {
            'name': registered_api['name'],
            'uris': uris,
            'upstream_url': upstream_url
        }

        resp = requests.patch(self._get_url('/apis/' + api_def['name']), json=data)
        if resp.status_code != 200:
            raise RegistrationException(resp.json().get('message'))
        return resp.json()

    def register_service(self, service_def):
        """Does an actual registration of the service with the Kong API Gateway.

        If the service already exists and is registered with the gateway, then the confguration
        is updated with the given ``service_def``. Otherwise, the service is added to the gateway
        registry.

        :returns: ``dict``, the JSON response from the gateway itself. Refer to the Kong
            documentation for the actual response schema.

        """
        api_def = self._to_api_params(service_def)

        reg_api = self._get_api_by_name(api_def['name'])

        if reg_api is None:
            return self._add_api(api_def)
        return self._update_api(reg_api, api_def)
