"""Microkubes Security API.
"""


from microkubes.security.auth import (SecurityContext,
                                      Auth)
from microkubes.security.chain import (SecurityChain,
                                       SecurityException)
from microkubes.security.keys import (Key,
                                      KeyStore,
                                      KeyException)
from microkubes.security.jwt import JWTProvider
from microkubes.security.oauth2 import OAuth2Provider
from microkubes.security.acl import (Policy as ACLPolicy,
                                     ACLProvider)


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
