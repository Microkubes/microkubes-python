"""Security Auth model and SecurityContext API.
"""


from threading import local as thread_local

has_contextvars = False
try:
    from contextvars import ContextVar
    has_contextvars = True
except ImportError:
    pass


class Auth:

    def __init__(self, user_id, username, roles=None, organizations=None, namespaces=None, scope=None):
        self.user_id = user_id
        self.username = username
        self.roles = roles or []
        self.organizations = organizations or []
        self.namespaces = namespaces or []
        self.scope = scope


def get_auth(local_context):
    auth = getattr(local_context, 'microkubes_auth', None)
    if auth is not None and isinstance(auth, Auth):
        return auth
    return None


def set_auth(local_context, auth):
    local_context.microkubes_auth = auth


def has_auth(local_context):
    return get_auth(local_context) is not None


class SecurityContext:

    def __init__(self, local_context):
        self.local_context = local_context

    def get_auth(self):
        return get_auth(self.local_context)

    def set_auth(self, auth):
        return set_auth(self.local_context, auth)

    def has_auth(self):
        return has_auth(self.local_context)


class ThreadLocalSecurityContext(SecurityContext):

    def __init__(self):
        super(ThreadLocalSecurityContext, self).__init__(thread_local())


if has_contextvars:
    ctxvar_local_context = ContextVar("local_context", {})

    class _local_context_proxy:

        def __getattr__(self, name):
            return ctxvar_local_context.get().get(name)

        def __setattr__(self, name, value):
            ctxvar_local_context.get()[name] = value

    _local_context = _local_context_proxy()

    class ContextvarsSecurityContext(SecurityContext):

        def __init__(self):
            super(ContextvarsSecurityContext, self).__init__(_local_context)
