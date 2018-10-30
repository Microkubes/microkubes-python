"""JWT security provider
"""
from logging import getLogger
import jwt
from microkubes.security.auth import Auth
from microkubes.security.keys import KeyException


log = getLogger(__name__)


class JWTProvider:
    """Implements JWT decoding and validation as a security chain provider.

    :param key_store: :class:`microkubes.security.keys.KeyStore`, the KeyStore to use with this provider.
    :param header: ``str``, the name of the security header. Default is ``Authorization``.
    :param auth_schema: ``str``, the format of the security header. The default schema is ``Bearer`` token.
    :param algs: ``list``, list of supported hash signing algorithms. Default is ``["HS256", "RS256"]``.

    """
    def __init__(self, key_store, header='Authorization', auth_schema='Bearer', algs=None):
        self.key_store = key_store
        self.header = header
        self.auth_schema = auth_schema
        self.algs = algs or ['HS256', 'RS256']

    def execute(self, ctx, req, resp):
        """Execute the security chain provider.

        Checks for security header containing JWT token. If found, the token is decoded and
        validated with the keys provided by the ``KeyStore``. If the token contains the optional
        key ID header (``kid``), then the decoding will be attempted with the specified key (if
        such key can be found with the registered ``KeyStore``).

        If the attempted decoding and validation of the JWT is successful, then :class:`microkubes.security.auth.Auth`
        is created and set in the current security context.

        :param ctx: :class:`microkubes.security.auth.SecurityContext`, current ``SecurityContext``.
        :param req: :class:`microkubes.security.chain.Request`, wrapped HTTP Request.
        :param resp: :class:`microkubes.security.chain.Response`, wrapped HTTP Response.

        """
        header_value = req.get_header(self.header)
        if not header_value:
            return None

        token_value = self._get_token(header_value)
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

    def _get_auth(self, token):
        user_id = token.get('userId')
        username = token.get('username')
        scope = token.get('scope')
        roles = token.get('roles', [])

        if not user_id:
            raise Exception('user_id is missing')
        if not username:
            raise Exception('username is missing')
        if not scope:
            raise Exception('scope not specified')

        if roles:
            roles = [role.strip() for role in roles.split(',')]

        organizations = token.get('organizations')
        if organizations:
            organizations = [org.strip() for org in organizations.split(',')]

        namespaces = token.get('namespaces')
        if namespaces:
            namespaces = [ns.strip() for ns in namespaces.split(',')]

        return Auth(user_id, username, roles=roles, organizations=organizations, namespaces=namespaces)

    def _get_keys(self, token_value):
        token_header = jwt.get_unverified_header(token_value)
        key_name = token_header.get('kid')
        if key_name:
            return [self.key_store.get_key(key_name)]
        # if JWT key id not set, then try all
        return [key for _, key in self.key_store.public_keys()]

    def _get_token(self, header_value):
        if not self.auth_schema:
            return header_value

        if header_value.startswith('%s ' % self.auth_schema):
            return header_value[len(self.auth_schema) + 1:]

        return None

    def __call__(self, ctx, req, resp):
        """Makes the instance of this class callable and thus available for use
        directly as a ``SecurityChain`` provider.
        """
        return self.execute(ctx, req, resp)
