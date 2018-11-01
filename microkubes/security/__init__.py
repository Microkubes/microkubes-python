"""Microkubes Security API.
"""


from microkubes.security.auth import (SecurityContext,
                                      Auth,
                                      ThreadLocalSecurityContext)

from microkubes.security.chain import (SecurityChain,
                                       SecurityException,
                                       is_authenticated_provider,
                                       public_routes_provider)
from microkubes.security.keys import (Key,
                                      KeyStore,
                                      KeyException)
from microkubes.security.jwt import JWTProvider
from microkubes.security.oauth2 import OAuth2Provider
from microkubes.security.acl import (Policy as ACLPolicy,
                                     ACLProvider)


try:
    # try using the ContextVar security context if python >= 3.7
    from contextvars import ContextVar as _ContextVar
    from microkubes.security.auth import ContextvarsSecurityContext
except ImportError:
    pass


_HAS_FLASK = False
try:
    import flask
    _HAS_FLASK = True
except ImportError:
    pass


# if flask is installed, import Flask integration components
if _HAS_FLASK:
    from microkubes.security.flask import (FlaskSecurity,
                                           FlaskSecurityContext,
                                           FlaskSecurityError)
