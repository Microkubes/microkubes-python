"""OAuth2 security provider.
"""

from microkubes.security.jwt import JWTProvider


class OAuth2Provider(JWTProvider):
    """OAuth2 security chain provider.

    The OAuth2 authenticated requests MUST contain the OAuth2 token.
    Microkubes tokens are all JWTs and we prefer Authorization: Bearer schema.

    The OAuth2 provider is basically JWTProvider and re-uses the same decoding
    and validation flow.

    :param key_store: :class:`microkubes.security.keys.KeyStore`, the key store to be used
        with this security provider.
    :param algs: ``list``, list of supported key signing algorithms. By default ``RS256``
        and ``HS256`` are supported.

    """

    def __init__(self, key_store, algs=None):
        super(OAuth2Provider, self).__init__(key_store=key_store, header='Authorization',
                                             auth_schema='Bearer', algs=algs)
