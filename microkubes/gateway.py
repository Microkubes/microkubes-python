"""API Gateway tools for Microkubes.
"""


from urllib.parse import urljoin
import requests


class RegistrationException(Exception):
    pass

class Registrator:

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
            url += '?' + '&'.join(['%s=%s' % (k, v) for k,v in sorted(params.items())])
        
        return url

    def register(self, **kwargs):
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
        pass


class KongGatewayRegistrator(Registrator):

    def __init__(self, gw_admin_url):
        super(KongGatewayRegistrator, self).__init__(gw_admin_url=gw_admin_url)
    
    def _to_api_params(self, service_def):
        return {}

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
        data = {}
        data.update(registered_api)
        data.update(api_def)
        resp = requests.patch(self._get_url('/apis/' + api_def['name']), json=data)
        if resp.status_code != 200:
            raise RegistrationException(resp.json().get('message'))
        return resp.json()

    def register_service(self, service_def):
        api_def = self._to_api_params(service_def)

        reg_api = self._get_api_by_name(api_def['name'])

        if reg_api is None:
            return self._add_api(api_def)
        return self._update_api(registered_api, api_def)