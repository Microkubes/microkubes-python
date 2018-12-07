""" SAML service provider"""
import os
import requests

from flask import redirect
from urllib.parse import urlparse
from microkubes.security.auth import Auth
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from logging import getLogger

log = getLogger(__name__)

class SAMLServiceProvider():
    """Decodes SAML token from the request

    :param key_store: :class:`microkubes.security.keys.KeyStore`, the KeyStore to use with this provider.
    :param session_name: :string, the SAML session name
    """

    def __init__(self, saml_session=None, registration_url=''):
       self.session = saml_session
       self.registration_url = registration_url
       self._register_sp()

    def execute(self, ctx, req, resp):
        """Execute the security chain provider.

        Checks for cookie with SAML token. If found, the token is decoded.

        If the attempted decoding of the SAML token is successful, then :class:`microkubes.security.auth.Auth`
        is created and set in the current security context.

        :param ctx: :class:`microkubes.security.auth.SecurityContext`, current ``SecurityContext``.
        :param req: :class:`microkubes.security.chain.Request`, wrapped HTTP Request.
        :param resp: :class:`microkubes.security.chain.Response`, wrapped HTTP Response.

        """
        if 'samlUserdata' not in self.session:
            r = self._prepare_saml_request(req)
            auth = self._init_saml_auth(r)

            resp.redirect_url = auth.login()
        if len(self.session['samlUserdata']) > 0:
            user_attrs = self.session['samlUserdata']
            auth = self._get_auth(attributes=user_attrs)
            ctx.set_auth(auth)

        return None

    def _register_sp(self):
        auth = self._init_saml_auth(None)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) > 0:
            raise Exception('Invalid SP metadata: %s' % ', '.join(errors))

        try:
            headers = {'Content-Type': 'application/xml'}
            requests.post('http://localhost:8080/saml/idp/services', data=metadata, headers=headers)
        except Exception as e:
            log.debug('Failed to register SP on IDP: %s' % str(e))

    def _init_saml_auth(self, req):
        auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), '../examples/flask/saml'))
        return auth

    def _get_auth(self, attributes={}):
        """Create authentication object
        """

        user_id = attributes.get('urn:oid:0.9.2342.19200300.100.1.1', [])[0]
        email =  attributes.get('urn:oid:1.3.6.1.4.1.5923.1.1.1.6', [])[0]
        roles = attributes.get('urn:oid:1.3.6.1.4.1.5923.1.1.1.1', [])

        if not user_id:
            raise Exception('user_id is missing')
        if not email:
            raise Exception('email is missing')
        if not roles:
            raise Exception('roles not specified')

        # TODO: Add scopes, namespaces and organizations in session created from Microkubes Identity Provider
        # and user's fullname if possible
        return Auth(user_id, email, roles=roles)

    def _prepare_saml_request(self, req):
        """Prepare SAML request
        """

        url_data = urlparse(req.url)

        return {
            'https': 'on' if req.scheme == 'https' else 'off',
            'http_host': req.host,
            'server_port': url_data.port,
            'script_name': req.path,
            'get_data': req.args.copy(),
            'post_data': req.form.copy(),
        }

    def __call__(self, ctx, req, resp):
        """Makes the instance of this class callable and thus available for use
        directly as a ``SecurityChain`` provider.
        """
        return self.execute(ctx, req, resp)
