""" SAML service provider"""

import jwt

from microkubes.security.jwt import JWTProvider
from microkubes.security.keys import KeyException

from logging import getLogger
log = getLogger(__name__)

class SAMLServiceProvider(JWTProvider):
    """Decodes SAML token from the request which is JWT token

    :param key_store: :class:`microkubes.security.keys.KeyStore`, the KeyStore to use with this provider.
    :param algs: ``list``, list of supported hash signing algorithms. Default is ``['HS256', 'HS512', 'RS256', 'RS512']``.

    """
    def __init__(self, key_store, algs=None, token_name='saml_token'):
        super(SAMLServiceProvider, self).__init__(key_store=key_store, algs=algs)
        self.token_name = token_name

    def execute(self, ctx, req, resp):
        """Execute the security chain provider.

        Checks for cookie with samk token which is JWT token. If found, the token is decoded and
        validated with the keys provided by the ``KeyStore``. If the token contains the optional
        key ID header (``kid``), then the decoding will be attempted with the specified key (if
        such key can be found with the registered ``KeyStore``).

        If the attempted decoding and validation of the SAML token is successful, then :class:`microkubes.security.auth.Auth`
        is created and set in the current security context.

        :param ctx: :class:`microkubes.security.auth.SecurityContext`, current ``SecurityContext``.
        :param req: :class:`microkubes.security.chain.Request`, wrapped HTTP Request.
        :param resp: :class:`microkubes.security.chain.Response`, wrapped HTTP Response.

        """
        token_value = req.get_cookie(self.token_name)
        if not token_value:
            return None

        keys = []
        try:
            keys = self._get_keys(token_value)
        except KeyException:
            return None

        if not keys:
            return None

        for key in keys:
            try:
                token = jwt.decode(token_value, key.load(), algorithms=self.algs)
                auth = self._get_auth(token)
                ctx.set_auth(auth)
            except Exception as e:
                log.debug("Failed to decode JWT: %s", e)
        return None


