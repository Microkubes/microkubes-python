
class SecurityException(Exception):

    def __init__(self, message, status_code=500, headers=None):
        super(SecurityException, self).__init__(message)
        self.status_code = status_code
        self.headers = headers or {}


class BreakChain(Exception):
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
    
    def url(self):
        pass
    
    def method(self):
        pass


class Response:

    def __init__(self, response):
        self.wrapped_response = response
    
    
class SecurityChain:
    
    def __init__(self, security_context=None, providers=None):
        self.security_context = security_context
        self.providers = providers or []
    
    def with_security_context(self, security_context):
        self.security_context = security_context
        return self
    
    def provider(self, security_provider):
        self.providers.append(security_provider)
        return self
    
    def execute(self, req, resp):
        for provider in self.providers:
            try:
                provider(self.security_context, req, resp)
            except BreakChain:
                break
            except SecurityException as e:
                raise e
            except Exception as e:
                raise SecurityException(str(e))