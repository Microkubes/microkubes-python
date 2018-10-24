from microkubes.gateway import Registrator, KongGatewayRegistrator
from unittest import mock
import pook


def test_get_url():
    r = Registrator(gw_admin_url='http://kong:8001')

    assert r._get_url('/apis') == 'http://kong:8001/apis'
    assert r._get_url('////apis') == 'http://kong:8001/apis' # normalize
    assert r._get_url('/apis', {'id': '10', 'num': 22.3, 'str': 'other-string'}) == 'http://kong:8001/apis?id=10&num=22.3&str=other-string'


@mock.patch.object(Registrator, 'register_service')
def test_registrator_register(register_service_mock):
    reg = Registrator(gw_admin_url='http://kong:8000')

    (reg.register(name='service_name', port=1001, host='the-host.lan', paths=['/match', '/match/again']))

    assert register_service_mock.called_once_with({
        'name': 'service_name',
        'port': 1001,
        'paths': ['/match', '/match/again'],
        'host': 'the-host.lan'
    })

@pook.on
def test_kong_gateway_add_api():
    pook.get('http://kong:8001/apis/test-api', reply=404, response_json={'message': 'Not Found'})
    (pook.post('http://kong:8001/apis/').json({
        'name': 'test-api',
        'uris': '/test,/api/test',
        'upstream_url': 'http://test.services.lan:8080'

    }).reply(201).json({
        'created_at': 1540213698704,
        'strip_uri': False,
        'id': '6af8aa24-b520-471a-bced-942e6cc023b6',
        'name': 'test-api',
        'http_if_terminated': True,
        'https_only': False,
        'upstream_url': 'http://test.services.lan:8080',
        'uris': [
            '/test',
            '/api/test'
        ],
        'preserve_host': False,
        'upstream_connect_timeout': 60000,
        'upstream_read_timeout': 60000,
        'upstream_send_timeout': 60000,
        'retries': 5
    }))

    reg = KongGatewayRegistrator(gw_admin_url='http://kong:8001')

    resp = reg.register(name='test-api', host='test.services.lan', port=8080, paths=['/test', '/api/test'])
    assert resp is not None


@pook.on
def test_kong_gateway_update_api():
    pook.get('http://kong:8001/apis/test-api', reply=200, response_json={
        'created_at': 1540213698704,
        'strip_uri': False,
        'id': '6af8aa24-b520-471a-bced-942e6cc023b6',
        'name': 'test-api',
        'http_if_terminated': True,
        'https_only': False,
        'upstream_url': 'http://test.services.lan:8080',
        'uris': [
            '/test',
            '/api/test'
        ],
        'preserve_host': False,
        'upstream_connect_timeout': 60000,
        'upstream_read_timeout': 60000,
        'upstream_send_timeout': 60000,
        'retries': 5
    })
    (pook.patch('http://kong:8001/apis/test-api').json({
        'name': 'test-api',
        'uris': '/new,/new/test',
        'upstream_url': 'http://new-test.services.lan:8089'

    }).reply(200).json({
        'created_at': 1540213698704,
        'strip_uri': False,
        'id': '6af8aa24-b520-471a-bced-942e6cc023b6',
        'name': 'test-api',
        'http_if_terminated': True,
        'https_only': False,
        'upstream_url': 'http://new-test.services.lan:8089',
        'uris': [
            '/new',
            '/new/test'
        ],
        'preserve_host': False,
        'upstream_connect_timeout': 60000,
        'upstream_read_timeout': 60000,
        'upstream_send_timeout': 60000,
        'retries': 5
    }))

    reg = KongGatewayRegistrator(gw_admin_url='http://kong:8001')

    resp = reg.register(name='test-api', host='new-test.services.lan', port=8089, paths=['/new', '/new/test'])
    assert resp is not None
    assert resp.get('uris') == ['/new', '/new/test']
    assert resp.get('upstream_url') == 'http://new-test.services.lan:8089'
