""" SAML service provider"""
import requests

from urllib.parse import urlparse
from microkubes.security.auth import Auth
from onelogin.saml2.auth import OneLogin_Saml2_Auth, OneLogin_Saml2_Utils, OneLogin_Saml2_Settings
from logging import getLogger

log = getLogger(__name__)

class SAMLServiceProvider():
    """Decodes SAML session from the request

    :param key_store: :class:`microkubes.security.keys.KeyStore`, the KeyStore to use with this provider.
    :param config: ``dict``, SAML config
    :param session: ``dict``, the HTTP request session
    """

    def __init__(self, key_store, config, saml_session={}):
        self.key_store = key_store
        self.config = config
        self.session = saml_session
        self._set_keys()
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
            r = SAMLSPUtils.prepare_saml_request(req)
            auth = SAMLSPUtils.init_saml_auth(r, self.config)

            resp.redirect_url = auth.login()
        if len(self.session.get('samlUserdata', {})) > 0:
            user_attrs = self.session['samlUserdata']
            auth = self._get_auth(attributes=user_attrs)
            ctx.set_auth(auth)

        return None

    def _set_keys(self):
        """Set private key and sertificate
        """
        self.config['sp']['x509cert'] = self.key_store.get_key(key_name=self.config.get('certName', None), public=False).load().decode('utf-8')
        self.config['idp']['x509cert'] = self.key_store.get_key(key_name=self.config.get('certName', None), public=False).load().decode('utf-8')
        self.config['sp']['privateKey'] = self.key_store.get_key(key_name=self.config.get('privateKeyName', None), public=False).load().decode('utf-8')

    def _register_sp(self):
        """ Sends SP metadata to the IDP
        """
        if not self.config.get('registration_url', None):
            raise Exception('registration_url is missing from config')

        metadata, errors = SAMLSPUtils.get_sp_metadata(self.config)

        if len(errors) > 0:
            raise Exception('Invalid SP metadata: %s' % ', '.join(errors))

        try:
            headers = {'Content-Type': 'application/xml'}
            requests.post(self.config.get('registration_url'), data=metadata, headers=headers)
        except Exception as e:
            log.debug('Failed to register SP on IDP: %s' % str(e))

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

    def __call__(self, ctx, req, resp):
        """Makes the instance of this class callable and thus available for use
        directly as a ``SecurityChain`` provider.
        """
        return self.execute(ctx, req, resp)


class SAMLSPUtils():
    """Auxiliary class that contains several utility methods
    """

    @staticmethod
    def prepare_saml_request(req):
        """Prepare SAML request

        :param req: :class:`microkubes.security.chain.Request`, wrapped HTTP Request.

        "returns: dict representing SAML request
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

    @staticmethod
    def init_saml_auth(req, config):
        """Prepare SAML request

        :param req: :class:`microkubes.security.chain.Request`, wrapped HTTP Request.

        :param config: ``dict``, SAML config

        :returns: an instance of OneLogin_Saml2_Auth
        """

        settingsSAML = OneLogin_Saml2_Settings(settings=config)
        auth = OneLogin_Saml2_Auth(req, old_settings=settingsSAML)
        return auth

    @staticmethod
    def get_sp_metadata(config):
        """Create and validate SP metadata

        :param config: ``dict``, SAML config

        :returns: metadata if no errors otherwise the errors
        """
        auth = SAMLSPUtils.init_saml_auth(None, config)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        return (metadata, errors)

    @staticmethod
    def serve_acs(request, session, config, redirect_to):
        """ Accept SAML response from the IDP for the purpose of establishing a session based on an assertion.

        :param request: :object: instance of HTTP Request.

        :param session: :object: session object from the HTTP request

        :param config: ``dict``, SAML config

        :param redirect_to: ``func``, function that accept URL to redirect to it

        :returns: redirect user to the desire resource
        """
        req = SAMLSPUtils.prepare_saml_request(request)
        auth = SAMLSPUtils.init_saml_auth(req, config)
        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if len(errors) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect_to(auth.redirect_to(request.form['RelayState']))
