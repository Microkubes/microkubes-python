"""Security Auth model and SecurityContext API.
"""


from threading import local as thread_local

_HAS_CONTEXTVARS = False
try:
    from contextvars import ContextVar
    _HAS_CONTEXTVARS = True
except ImportError:
    pass


class Auth:
    """Auth is the main Security Authorization model.

    :class:`Auth` holds the authorization for a particular user.

    :param user_id: ``str``, the User ID.
    :param username: ``str``, username. Usually in Microkubes this is the user email,
    :param roles: ``list``, list of roles that the user has. May be empty or ``None``.
    :param organizations: ``list``, list of organization to which this user belongs to.
    :param namespaces: ``list``: list of namespaces to which this user belongs to.
    :param scope: ``str``, scope to which this Auth is limited to.
    """
    def __init__(self, user_id, username, roles=None, organizations=None, namespaces=None, scope=None):
        self.user_id = user_id
        self.username = username
        self.roles = roles or []
        self.organizations = organizations or []
        self.namespaces = namespaces or []
        self.scope = scope

    def __repr__(self):
        return 'Auth<%s (%s) roles=[%s], orgs=[%s], ns=[%s], scope=%s>' % (self.user_id,
                                                                           self.username,
                                                                           ','.join(self.roles or []),
                                                                           ','.join(self.organizations or []),
                                                                           ','.join(self.namespaces or []),
                                                                           self.scope or 'None')
    def __str__(self):
        return self.__repr__()

    def __eq__(self, o):
        if o is None or not isinstance(o, Auth):
            return False

        return (self.user_id == o.user_id and
                self.username == o.username and
                self.scope == o.scope and
                set(self.roles or []) == set(o.roles or []) and
                set(self.organizations or []) == set(o.organizations or []) and
                set(self.namespaces or []) == set(o.namespaces or []))

    def __hash__(self):
        return self.__str__().__hash__()
    

def get_auth(local_context):
    """Get current :class:`Auth` from the given local context.

    :param local_context: the current local context. This is either ThreadLocal object or ContextVars
        context. See https://docs.python.org/3/library/threading.html#thread-local-data for thread-based
        local context or https://docs.python.org/3/library/contextvars.html for contextvars based
        local context.

    :returns: :class:`Auth` if the current local context contains Auth. Otherwise ``None``.
    """
    auth = getattr(local_context, 'microkubes_auth', None)
    if auth is not None and isinstance(auth, Auth):
        return auth
    return None


def set_auth(local_context, auth):
    """Set the :class:`Auth` in the current local context.

    :param local_context: the current local context. This is either ThreadLocal object or ContextVars
        context. See https://docs.python.org/3/library/threading.html#thread-local-data for thread-based
        local context or https://docs.python.org/3/library/contextvars.html for contextvars based
        local context.
    :param auth: :class:`Auth`, the auth to set in the context.

    """
    local_context.microkubes_auth = auth


def has_auth(local_context):
    """Checks whether there was an :class:`Auth` set for this local context.

    :param local_context: the current local context. This is either ThreadLocal object or ContextVars
        context. See https://docs.python.org/3/library/threading.html#thread-local-data for thread-based
        local context or https://docs.python.org/3/library/contextvars.html for contextvars based
        local context.

    """
    return get_auth(local_context) is not None


def clear_auth(local_context):
    """Clears the current :class:`Auth` in the goven local context.

    :param local_context: the current local context. This is either ThreadLocal object or ContextVars
        context. See https://docs.python.org/3/library/threading.html#thread-local-data for thread-based
        local context or https://docs.python.org/3/library/contextvars.html for contextvars based
        local context.

    """
    if has_auth(local_context):
        local_context.microkubes_auth = None


class SecurityContext:
    """Context object that holds security data.

    The instaces of this class are intended to be shared between requests, threads and/or corouthines.

    The auth object is kept in a local context - usually a proxy to a Thread-local or contextvar based
    local context.

    :param local_context: the local context object used for storing the Auth objects. The auth object will be
        visible only to the request/coroutine that has set it.
    """
    def __init__(self, local_context):
        self.local_context = local_context

    def get_auth(self):
        """Return the current :class:`Auth`, if set.

        :returns: :class:`Auth` or ``None``.
        """
        return get_auth(self.local_context)

    def set_auth(self, auth):
        """Set the given :class:`Auth` in the current context.

        If already set, this :class:`Auth` overrides the existing one.

        :param auth: :class:`Auth`, the auth object to set in the security context.

        """
        return set_auth(self.local_context, auth)

    def has_auth(self):
        """Check if there is an :class:`Auth` set in this security context.

        :returns: ``True`` if there is an auth set, otherwise ``False``.
        """
        return has_auth(self.local_context)

    def clear_auth(self):
        """Clear the current :class:`Auth` from this context.
        """
        return clear_auth(self.local_context)


class ThreadLocalSecurityContext(SecurityContext):
    """Thread-local based implementation of the :class:`SecurtyContext`.

    See https://docs.python.org/3/library/threading.html#thread-local-data.
    """
    def __init__(self):
        super(ThreadLocalSecurityContext, self).__init__(thread_local())


if _HAS_CONTEXTVARS:
    _CTXVAR_LOCAL_CONTEXT = ContextVar("local_context", {})

    class _LocalContextProxy:

        def __getattr__(self, name):
            return _CTXVAR_LOCAL_CONTEXT.get().get(name)

        def __setattr__(self, name, value):
            _CTXVAR_LOCAL_CONTEXT.get()[name] = value

    _LOCAL_CONTEXT = _LocalContextProxy()

    class ContextvarsSecurityContext(SecurityContext):
        """contextvars base implementation of :class:`SecurityContext`.

        See https://docs.python.org/3/library/contextvars.html.
        """
        def __init__(self):
            super(ContextvarsSecurityContext, self).__init__(_LOCAL_CONTEXT)
