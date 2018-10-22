from microkubes.gateway import Registrator


def test_get_url():
    r = Registrator(gw_admin_url='http://kong:8001')

    assert r._get_url('/apis') == 'http://kong:8001/apis'
    assert r._get_url('////apis') == 'http://kong:8001/apis' # normalize
    assert r._get_url('/apis', {'id': '10', 'num': 22.3, 'str': 'other-string'}) == 'http://kong:8001/apis?id=10&num=22.3&str=other-string'