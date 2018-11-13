"""Flask decorators and helpers to set up Microkubes security for Flask apps.
"""
from json import dumps

from flask import request, make_response, g

from microkubes.security.jwt import JWTProvider
from microkubes.security.oauth2 import OAuth2Provider
from microkubes.security.auth import SecurityContext
from microkubes.security.chain import (Request,
                                       Response,
                                       SecurityException,
                                       SecurityChain,
                                       is_authenticated_provider,
                                       public_routes_provider)
from microkubes.security.keys import KeyStore


class FlaskSecurityError(Exception):
    """Error during security setup for Flask apps.
    """
    pass


class FlaskSecurityContext(SecurityContext):
    """SecurityContext that wraps Flask's ``g`` object. Request Scoped.
    """
    def __init__(self):
        super(FlaskSecurityContext, self).__init__(g)


class Security:
    """Main security object.

    Contains the configured :class:`microkubes.security.chain.SecurityChain` and
    executes it for every secured action.

    A secured action is an action decorated with :func:`Security.secured`.

    Given that we have configured a SecurityChain, we can protect/secure Flask actions like this:

        .. code-block:: python

            sec = Security(security_chain=chain, context=FlaskSecurityContext())

            @app.route('/')
            @sec.secured
            def my_action():
                return 'My secured action.'

    """
    def __init__(self, security_chain, context, json_response=True):
        self.security_chain = security_chain
        self.context = context
        self.json_response = json_response

    def check(self):
        """Perform the check for the given Request in the current SecurityContext.

        :returns: ``tuple``: ``(allowed, flask_response)``, where:
            * ``allowed`` is ``bool`` indicating whether the request is allowed to proceed.
            * ``flask_response`` - :class:`Response` the Flask response. May be ``None``.
        """
        req = Request(request)
        resp = Response()
        try:
            self.security_chain.execute(req, resp)
        except SecurityException as security_error:
            if self.json_response:
                flask_response = make_response(dumps({
                    'code': security_error.status_code,
                    'message': str(security_error),
                }), security_error.status_code)
            else:
                flask_response = make_response(str(security_error), security_error.status_code)
            if security_error.headers:
                flask_response.headers.update(security_error.headers)
            return (False, flask_response)

        if resp.modified or resp.ended:
            flask_response = make_response(resp.get_response_body(), resp.status_code)
            flask_response.status = resp.status
            if resp.headers:
                flask_response.headers.update(resp.headers)
            return (True, flask_response)
        return (True, None)

    def secured(self, decorated):
        """Decorator for security check.

        When decorated with ``@security.secured``, the decorated method will not be called
        unless the security check passes.

        :param decorated: ``function``, the decorated method.

        :returns: ``function``, the security decorator for the given method or function..
        """
        def _secured_method(*args, **kwargs):
            allowed, flask_resp = self.check()
            if not allowed:
                if flask_resp:
                    return flask_resp
                return make_response("Request denied", 403)
            if flask_resp:
                return flask_resp
            return decorated(*args, **kwargs)

        return _secured_method


_SECURITY_CONTEXT = FlaskSecurityContext()  # Default g-based security context.


class FlaskSecurity:
    """Flask security builder.

    Builds new Microkubes enabled security for Flask applications.
    In the background it generates a ``SecurityChain`` and :class:`Security` that can be
    used to secure the Flask's endpoints.

    Example setup:

        .. code-block:: python

            from flask import Flask
            from microkubes.security import FlaskSecurity

            app = Flask(__name__)

            sec = (FlaskSecurity().  # new security with default secuity context
                    keys_dir('./keys').  # the RSA keys are in this directory
                    static_files(r'.*\\.js', r'.*\\.css', r'.*\\.png', r'.*\\.jpg', r'.*\\.jpeg'). # ignore these
                    public_route('/public/.*').  # ignore this too
                    jwt().  # Support JWT
                    oauth2().  # Support OAuth2
                    build())  # Finally, build the security

            @app.route("/")
            @sec.secured
            def hello_world():
                return 'hello world'

    :param context: :class:`microkubes.security.auth.SecurityContext` - the security context to be used.
        By default :class:`FlaskSecurityContext` is used.
    :param key_store: :class:`microkubes.security.keys.KeyStore`, ``KeyStore`` instance.

    """
    def __init__(self, context=None, key_store=None):
        self.key_store = key_store
        context = context or _SECURITY_CONTEXT
        self._context = context
        self._chain = SecurityChain(security_context=context)
        self._public_routes = []
        self._jwt_provider = None
        self._oauth_provider = None
        self._other_providers = []
        self._prefer_json_respose = True

    def keys_dir(self, path):
        """Load the keys for the ``KeyStore`` from this directory.

        :param path: ``str``, keys directory path.

        :returns: :class:`FlaskSecurity`.
        """
        if self.key_store:
            raise FlaskSecurityError("KeyStore is already defined.")
        self.key_store = KeyStore(dir_path=path)
        return self

    def use_key(self, key_name, key_file):
        """Add mapped key to the ``KeyStore``.

        :param key_name: ``str``, the name (id) of the key.
        :param key_file: ``str``, path to the key file.

        :returns: :class:`FlaskSecurity`.
        """
        if not self.key_store:
            self.key_store = KeyStore()
        self.key_store.add_key(key_name, key_file)
        return self

    def jwt(self, header='Authorization', schema='Bearer', algs=None):
        """Setup JWT security provider.

        This provider tries to decode and create auth from a JWT in the HTTP request.

        :param header: ``str``, the name of the HTTP auth header. Default is ``Authorization``.
        :param schema: ``str``, the auth schema used for the auth HTTP header. By default this is ``Bearer`` token.
        :param algs: ``list``, list of accepted signing algorithms. If not specified assumes ``HS256`` and ``RS256``.

        :returns: :class:`FlaskSecurity`.
        """
        if not self.key_store:
            raise FlaskSecurityError('KeyStore must be defined before setting up the JWT provider.')
        self._jwt_provider = JWTProvider(self.key_store, header=header, auth_schema=schema, algs=algs)
        return self

    def oauth2(self, algs=None):
        """Setup OAuth2 security provider.

        This provider will try to decode and validate an OAuth2 token. All tokens with Microkubes are
        self-contained and are JWTs.

        :param algs: ``list``, list of accepted signing algorithms. If not specified assumes ``HS256`` and ``RS256``.

        :returns: :class:`FlaskSecurity`.
        """
        if not self.key_store:
            raise FlaskSecurityError('KeyStore must be defined before setting up the OAuth2 provider.')
        self._oauth_provider = OAuth2Provider(key_store=self.key_store, algs=algs)
        return self

    def public_route(self, *args):
        """Add public routes that will be ignored and not checked by the security.

        A public route is a HTTP request path that is publicly accessible and does not need authorization
        for access.

        :param args: variadic args, ``list`` of exact routes or regexp patterns to match against. All routes
            are treated as regular expression pattern, so:

                * ``/public/resource`` matches exactly this pattern
                * ``/public/.*`` matches both ``/public/a`` and ``/public/file.js`` but not ``/protected/file``
                * ``.*\\.js`` matches all js files - both ``/public/file.js`` and ``/protected/file.js``

        :returns: :class:`FlaskSecurity`.
        """
        self._public_routes.append(public_routes_provider(*args))
        return self

    def static_files(self, *args):
        """Alias for ``public_routes`` method.

        The only difference is a semantic one, to allow more readablity in the code.
        """
        return self.public_route(*args)

    def add_provider(self, provider, position='last'):
        """Add custom security provider to the security chain.

        The chain executes multiple providers, in order, when processing a request.
        This method adds new provider to the security chain's providers list.

        Because there are some defult providers that are set up in a certain order, you can provide
        a ``position`` and place the custom provider anuwhere in the chain.
        If not given, the provider is appended near the end of the list (the provider that checks if
        the request is authenticated is always last).

        In general, these are the available positions, and corresponding placement for the providers:

        +-----+--------------------------+------------------------------+
        | seq | POSITION                 | PROVIDERS                    |
        +-----+--------------------------+------------------------------+
        | 1   | first                    | custom providers             |
        +-----+--------------------------+------------------------------+
        | 2   | N/A                      | public_routes                |
        +-----+--------------------------+------------------------------+
        | 3   | before_jwt, after_public | custom providers             |
        +-----+--------------------------+------------------------------+
        | 4   | N/A                      | jwt_provider                 |
        +-----+--------------------------+------------------------------+
        | 5   | after_jwt, before_oauth2 | custom providers             |
        +-----+--------------------------+------------------------------+
        | 6   | N/A                      | oauth2_provider              |
        +-----+--------------------------+------------------------------+
        | 7   | last                     | custom providers             |
        +-----+--------------------------+------------------------------+
        | 8   | N/A                      | is_authenticated_provider    |
        +-----+--------------------------+------------------------------+
        | 9   | final                    | custom providers             |
        +-----+--------------------------+------------------------------+

        :param provider: ``function``, the security provider to add
        :param position: ``str``, at which position in the chain to add the provider. One of ``first``,
            ``before_jwt``, ``after_public``, ``after_jwt``, ``before_oauth2``, ``last`` and ``final`` is allowed. 
            Default is ``last``.

        :returns: :class:`FlaskSecurity`.
        """
        position = position or 'last'
        self._other_providers.append((provider, position))
        return self

    def _merge_providers(self):
        providers = []

        for provider, position in self._other_providers:
            if position == 'first':
                providers.append(provider)

        for provider in self._public_routes:
            providers.append(provider)

        for provider, position in self._other_providers:
            if position in ['before_jwt', 'after_public']:
                providers.append(provider)

        if self._jwt_provider:
            providers.append(self._jwt_provider)

        for provider, position in self._other_providers:
            if position in ['after_jwt', 'before_oauth', 'before_oauth2']:
                providers.append(provider)
                
        if self._oauth_provider:
            providers.append(self._oauth_provider)

        for provider, position in self._other_providers:
            if position in ['after_oauth', 'after_oauth2', 'last']:
                providers.append(provider)

        providers.append(is_authenticated_provider)


        for provider, position in self._other_providers:
            if position == 'final':
                providers.append(provider)

        return providers

    def build_chain(self):
        """Build a :class:`microkubes.security.chain.SecurityChain` from the configured values.

        :returns: the :class:`microkubes.security.chain.SecurityChain`
        """
        if not self.key_store:
            raise FlaskSecurityError('Please define a KeyStore.')

        for provider in self._merge_providers():
            self._chain.provider(provider)

        return self._chain

    def build(self):
        """Build a ``Security`` from the configured values.

        It builds a security chain and configures a new security to be used in flask apps.

        :returns: :class:`Security`.
        """
        chain = self.build_chain()
        security = Security(security_chain=chain, context=self._context, json_response=self._prefer_json_respose)
        return security
