from collections import namedtuple
from unittest import mock

from microkubes.security.chain import (SecurityChain,
                                       SecurityException,
                                       Request,
                                       Response,
                                       BreakChain,
                                       is_authenticated_provider,
                                       public_routes_provider)
from microkubes.security.auth import ThreadLocalSecurityContext, SecurityContext


def test_request_wrapper():
    """Test the request wrapper
    """
    _Request = namedtuple('_Request', ['url', 'method', 'host', 'path', 'scheme',
                                       'query_string', 'data', 'json', 'headers',
                                       'get_data', 'get_json', 'get_form'])

    wrapped = _Request('http://example.com/path?a=b', 'POST', 'example.com', 
                       '/path', 'http', 'a=b', '{"a": "b"}', {"a": "b"}, 
                       {"Content-Type": "application/json"}, lambda: '{"a": "b"}',
                       lambda: {"a": "b"}, lambda: {"a": "b"})

    req = Request(wrapped)

    assert req.url == 'http://example.com/path?a=b'
    assert req.method == 'POST'
    assert req.host == 'example.com'
    assert req.path == '/path'
    assert req.scheme == 'http'
    assert req.query_string == 'a=b'
    assert req.data == '{"a": "b"}'
    assert req.json == {"a": "b"}
    assert req.headers == {"Content-Type": "application/json"}

    assert req.get_data() == '{"a": "b"}'
    assert req.get_form() == {"a": "b"}
    assert req.get_json() == {"a": "b"}

    assert req.get_header("Content-Type") == "application/json"


def test_response():
    """Test the Chain response.
    """
    resp = Response()

    resp.headers = {"Content-Type": "application/json"}

    assert resp.headers == {"Content-Type": "application/json"}
    assert resp.modified is True

    resp = Response()

    resp.status = "TEST"

    assert resp.status == "TEST"
    assert resp.modified is True

    resp = Response()

    resp.status_code = 201

    assert resp.status_code == 201
    assert resp.modified is True

    resp = Response()

    resp.write("DATA")

    assert resp.modified is True
    assert resp._buffer.getvalue() == "DATA"
    assert resp.get_response_body() == "DATA"

    resp = Response()

    resp.write_json({"a": "b"})

    assert resp.modified is True
    assert resp._buffer.getvalue() == '{"a": "b"}'
    assert resp.get_response_body() == '{"a": "b"}'
    assert resp.headers["Content-Type"] == "application/json"

    resp = Response()

    resp.end(code=203, status="TEST")

    assert resp.modified is True
    assert resp.ended is True
    assert resp.status_code == 203
    assert resp.status == "TEST"


def test_chain_execute():
    """Test Security chain - execute providers chain.
    """
    req = Request(None)
    resp = Response()
    context = ThreadLocalSecurityContext()


    providers_called = []

    def get_provider(provider_name):
        def _provider(_ctx, _req, _resp):
            assert _ctx == context
            assert _req == req
            assert _resp == resp
            providers_called.append(provider_name)

        return _provider


    chain = (SecurityChain().
             with_security_context(context).
             provider(get_provider("provider-1")).
             provider(get_provider("provider-2")).
             provider(get_provider("provider-3")))



    chain.execute(req, resp)

    assert providers_called == ["provider-1", "provider-2", "provider-3"]


def test_chain_execute_break_chain():
    """Test SecurityChain execution of providers - break the chain.
    """
    req = Request(None)
    resp = Response()
    context = ThreadLocalSecurityContext()


    providers_called = []

    def get_provider(provider_name):
        def _provider(_ctx, _req, _resp):
            assert _ctx == context
            assert _req == req
            assert _resp == resp
            providers_called.append(provider_name)

        return _provider

    def break_chain(_ctx, _req, _resp):
        assert _ctx == context
        assert _req == req
        assert _resp == resp
        raise BreakChain()


    chain = (SecurityChain().
             with_security_context(context).
             provider(get_provider("provider-1")).
             provider(get_provider("provider-2")).
             provider(break_chain).
             provider(get_provider("provider-3")))



    chain.execute(req, resp)

    assert providers_called == ["provider-1", "provider-2"]


@mock.patch.object(SecurityContext, "has_auth")
def test_is_authenticated_provider_pass(has_auth_mock):
    """Test is_authenticated provider - authenticated scenario.
    """
    has_auth_mock.return_value = True

    sc = SecurityContext(None)
    req = Request(None)
    resp = Response()

    is_authenticated_provider(sc, req, resp)

    assert has_auth_mock.call_count == 1


@mock.patch.object(SecurityContext, "has_auth")
def test_is_authenticated_provider_block(has_auth_mock):
    """Test is_authenticated provider - not authenticated scenario.
    """
    has_auth_mock.return_value = False

    sc = SecurityContext(None)
    req = Request(None)
    resp = Response()

    err = None
    try:
        is_authenticated_provider(sc, req, resp)
    except SecurityException as sec:
        err = sec

    assert has_auth_mock.call_count == 1
    assert err is not None
    assert err.status_code == 401
    assert str(err) == 'authentication required'


def test_public_routes_provider():
    """Test public routes provider.
    """
    def expect(exc, fn, *args):
        """Expect fn to throw an exception of the provided type.
        """
        try:
            fn(*args)
        except Exception as e:
            if not isinstance(e, exc):
                raise Exception('Expected error of type %s but got "%s" of type: %s' % (exc, e, type(e)))
            return
        raise Exception("Expected error of type %s but none was raised." % e)

    _R = namedtuple('_Request', ['path'])

    def request(path):
        """Create new request with this path.
        """
        return Request(_R(path))

    sc = SecurityContext(None)
    resp = Response()

    # test exact matches
    provider = public_routes_provider('/path', '/longer/path')

    expect(BreakChain, provider, sc, request('/path'), resp)
    expect(BreakChain, provider, sc, request('/longer/path'), resp)

    provider(sc, request('/not/matched'), resp)
    provider(sc, request('/longer/path/invalid'), resp)

    # test pattern

    provider = public_routes_provider('/path/.*', r'.*\.js')

    expect(BreakChain, provider, sc, request('/path/a'), resp)
    expect(BreakChain, provider, sc, request('/path/longer'), resp)
    expect(BreakChain, provider, sc, request('/resources/file.js'), resp)
    expect(BreakChain, provider, sc, request('file.js'), resp)

    provider(sc, request('/path'), resp)
    provider(sc, request('/api/v1/service'), resp)
    provider(sc, request('/api.js/v1'), resp)
