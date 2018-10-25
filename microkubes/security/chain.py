
import json
import re


_REGEX_TYPE = type(re.compile('_'))


class SecurityException(Exception):
    """Represents a security error. A security error is raised while
    executing the security chain for the current request.

    The security exception contains additional properties that relate
    to the HTTP response that will be generated and returned to the
    client later on.

    :param message: ``str``, the error message.
    :param status_code: ``int``, HTTP status code. For example - 401 if the 
        authorization is missing; 403 if an authorization was sent but the
        access is forbidden; 400 if some required parameter/header is missing
        or has wrong value.
    :param headers: ``dict``, additional headers to be added to the HTTP response.
    """
    def __init__(self, message, status_code=500, headers=None):
        super(SecurityException, self).__init__(message)
        self.status_code = status_code
        self.headers = headers or {}


class BreakChain(Exception):
    """Raised to stop the security chain at the current provider. If raised,
    then the chain will break after the provider that raised the error and
    will not execute the rest of the providers. The security chain must not
    re-raise this error, as this is considered regular way of terminating the
    chain execution.
    """
    pass


class Request:
    """Request wrapper, partly compatible with Flask Request.

    Wraps the original request to ensure trasparent access to most common properties
    of while evaluating the request for security authentication/authorization.

    This basic implementation will try to treat the wrapped (underlying) HTTP request
    to be Flask-type request object. Other implemenations can extend from this class
    and override or add other functinalities for accessing the request data.

    :param request: ``object``, the original request. This may be the original Flask Request
        or any other underlying implementation type request object.
    """
    def __init__(self, request):
        self.wrapped_request = request
    
    def _getattr(self, attr, default=None):
        return getattr(self.wrapped_request, attr, default)

    @property
    def url(self):
        """Request URL (full).
        """
        return self._getattr('url')
    
    @property
    def method(self):
        """HTTP method for this request.
        """
        return self._getattr('method')
    
    @property
    def host(self):
        """Host name, usually retrieved from the HTTP headers.
        """
        return self._getattr('host')

    @property
    def path(self):
        """HTTP request path.
        """
        return self._getattr('path')
    
    @property
    def scheme(self):
        """HTTP request scheme (``http`` or ``https``).
        """
        return self._getattr('scheme')
    
    @property
    def query_string(self):
        """HTTP request query string.
        """
        return self._getattr('query_string')
    
    @property
    def data(self):
        """HTTP request data. Usually raw data because it was not decoded as form params or json.
        """
        return self._getattr('data')
    
    @property
    def form(self):
        """Form data as dict.
        """
        return self._getattr('form')
    
    @property
    def json(self):
        """Dict containing the decoded JSON data.
        """
        return self._getattr('json')

    @property
    def headers(self):
        """HTTP Request headers dict.
        """
        return self._getattr('headers')

    def get_header(self, header):
        """Returns the value of the specified HTTP request header.

        :param header" ``str``, the header name.

        :returns: ``str`` the header value or ``None``.

        """
        return self._getattr('headers', {}).get(header)

    def get_data(self):
        """Get the raw HTTP request data.
        """
        if hasattr(self.wrapped_request, 'get_data'):
            return self.wrapped_request['get_data']()
        return None

    def get_json(self):
        """Get the decoded JSON data as dict.
        """
        if hasattr(self.wrapped_request, 'get_json'):
            return self.wrapped_request['get_json']()
        return None

    def get_form(self):
        """Get decoded form params as dict.
        """
        if hasattr(self.wrapped_request, 'get_form'):
            return self.wrapped_request['get_form']()
        return None



class Response:
    """HTTP response wrapper.
    """
    def __init__(self, response):
        self.wrapped_response = response
        self.ended = False
    
    def _getattr(self, name):
        return getattr(self.wrapped_response, name, None)
    
    def _call(self, fn_name, *args, **kwargs):
        fn = self._getattr(fn_name)
        if fn:
            return fn(*args, **kwargs)

    @property
    def headers(self):
        """Response headers dict.
        """
        return self._getattr('headers')
    
    @headers.setter
    def headers(self, hdrs=None):
        """Response headers setter.
        """
        if hdrs is None:
            self.wrapped_response.headers = hdrs

    def set_header(self, header, value):
        """Set HTTP response header.

        :param header: ``str``, the header name.
        :param value: ``str``, the header value.
        """
        hdrs = self._getattr('headers')
        if hdrs:
            hdrs[header] = value
    
    @property
    def status(self):
        """Response status message.
        """
        return self._getattr('status')
    
    @status.setter
    def status(self, status_message):
        """Response status message.
        """
        self.wrapped_response.status = status_message

    @property
    def status_code(self):
        """Response status code.
        """
        return self._getattr('status_code')
    
    @status_code.setter
    def status_code(self, code=None):
        """Response status code.
        """
        self.wrapped_response.code = code
    
    def write(self, data):
        """Write data to the HTTP response stream.

        :param data: ``str``, the data to be written to the response stream directly.
        """
        stream = self._getattr('stream')
        if stream:
            stream.write(data)
    
    def write_json(self, data):
        """Writes data to the response stream with ``application/json`` content type.

        :param data: ``any``, the data to be serialized (if necessary) as JSON and written to
            the HTTP response stream.
        """
        self.set_header('Content-Type', 'application/json')
        if isinstance(data, str):
            self.write(data)
        else:
            self.write(json.dumps(data))
    
    def end(self, code=None, status=None):
        """End this response.

        :param code: ``int``, HTTP response status code.
        :param status: ``str``, HTTP response status message.
        """
        if code is not None:
            self.status_code = code
        if status is not None:
            self.status = status
        self.ended = True


class SecurityChain:
    """SecurityProcessing chain. Executes the security providers with the HTTP Request and Response
    wrappers in order to process and create :class:`microkubes.security.Auth`.

    :params security_context: :class:`microkubes.security.SecurityContext`, the security context.
    :params providers: ``list``, list of security providers to execute for each request. A security
        provider is a function that processes the current HTTP request so it can check for existing
        auth or in order to create one from the request values. The security provider prototype is 
        as follows:

            .. code-block:: python

                def security_provider(security_context, req, resp):
                    pass

        where:

            * ``security_context`` is the current :class:`microkubes.security.SecurityContext`.
            * ``req`` is the current HTTP :class:`Request`.
            * ``resp`` is the current HTTP :class:`Response`.

    """
    def __init__(self, security_context=None, providers=None):
        self.security_context = security_context
        self.providers = providers or []

    def with_security_context(self, security_context):
        """Set the security context for this :class:`SecurityChain`.

        This is a builder method.

        :param security_context: :class:`microkubes.security.SecurityContext`

        :returns: reference to this instance of :class:`SecurityChain`

        """
        self.security_context = security_context
        return self
    
    def provider(self, security_provider):
        """Add a security provider to this chain.

        The provider is added to the end of the list of providers. The providers are executed
        sequentially in the same order as they are registered.

        :param security_provider: ``function``, a security provider function.

        :returns: reference to this instance of :class:`SecurityChain`

        """
        self.providers.append(security_provider)
        return self
    
    def execute(self, req, resp):
        """Execute this security chain with the given request and response.

        :param req: ``Request``, the current HTTP Request.
        :param resp: ``Response``, the current HTTP Response.

        :raises: :class:`SecurityException` if an exception happens during the chain
            execution of the security providers.
        """
        for provider in self.providers:
            try:
                provider(self.security_context, req, resp)
                if resp.ended:
                    break
            except BreakChain:
                break
            except SecurityException as e:
                raise e
            except Exception as e:
                raise SecurityException(str(e))


def is_authenticated_provider(sc, req, resp):
    """Security provider to check if the current request has been authenticated.

    You can add this provider to the end of the security chain to detect if the previous
    providers have been succesfull in creating authnetication for the request.

    Raises :class:`SecurityException` if the security context does not contain authentication.
    """
    if not sc.has_auth():
        raise SecurityException('not authenticated')


def public_routes_provider(*args):
    """Security provider to allow access to resources without auth.

    Takes a list of ``str`` patterns or regexp objects to match the ``Request.path`` against.
    If the request path matches, the chain is broken and the request is passed through.

    :returns: ``function`` the compiled security providers for the given public routes.

    Example usage:

        .. code-block:: python

            static_resources = public_routes_provider(r'.*.js', r'.*.css', r'.*.png')

            chain = (SecurityChain().
                        with_security_context(sc).
                        provider(static_resources).  # add it first in the chain so it cancels the rest of the providers if matches a publid resource
                        provider(jwt_provider).
                        provider(oauth2_provider).
                        provider(saml_provider).
                        provider(is_authenticated_provider)  # we add the is_authenticated_provider last to check if any of the previous have generated authentication.
                        )
    """
    if not len(args):
        raise ValueError('you must provide at least one route pattern')
    patterns = []
    for pattern in args:
        if isinstance(pattern, str):
            patterns.append(re.compile(pattern))
        elif isinstance(pattern, _REGEX_TYPE):
            patterns.append(pattern)
        else:
            raise ValueError('pattern must be str or regex Pattern object')
    
    def _check_public_route(sc, req, resp):
        for pattern in patterns:
            if pattern.match(req.path or ''):
                raise BreakChain()
    
    return _check_public_route
            