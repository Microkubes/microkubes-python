"""Security Auth module unit tests.
"""
from threading import local
from microkubes.security.auth import Auth, get_auth, set_auth, has_auth, clear_auth, SecurityContext


def test_auth_eq():
    """Test Auth equality override.
    """
    a1 = Auth(user_id="a1", username="a1@example.com")
    a2 = Auth(user_id="a1", username="a1@example.com")

    assert a1 == a2
    assert a2 == a1

    a1 = Auth(user_id="a1", username="a1@example.com", roles=["user"])
    a2 = Auth(user_id="a1", username="a1@example.com")

    assert a1 != a2
    assert a2 != a1

    a1 = Auth(user_id="a1", username="a1@example.com", roles=["user"], organizations=["o1", "o2"],
              namespaces=["ns1", "ns2"], scope="test-scope")
    a2 = Auth(user_id="a1", username="a1@example.com", roles=["user"], organizations=["o1", "o2"],
              namespaces=["ns1", "ns2"], scope="test-scope")

    assert a1 == a2

    # mix up the names in the lists
    a1 = Auth(user_id="a1", username="a1@example.com", roles=["user", "r2"], organizations=["o1", "o2"],
              namespaces=["ns1", "ns2"], scope="test-scope")
    a2 = Auth(user_id="a1", username="a1@example.com", roles=["r2", "user"], organizations=["o2", "o1"],
              namespaces=["ns2", "ns1"], scope="test-scope")

    assert a1 == a2

    # mix, but should not be equal
    a1 = Auth(user_id="a1", username="a1@example.com", roles=["user", "r2"], organizations=["o1", "o2"],
              namespaces=["ns1", "ns2", "ns3"], scope="test-scope")
    a2 = Auth(user_id="a1", username="a1@example.com", roles=["r2", "user"], organizations=["o2", "o1"],
              namespaces=["ns2", "ns1"], scope="test-scope")

    assert a1 != a2


def test_get_auth():
    """Test get auth from thread-local based context.
    """
    ctx = local()
    auth = Auth(user_id="test-001", username="user@example.com")
    ctx.microkubes_auth = auth

    result = get_auth(ctx)
    assert result is not None
    assert auth == result


def test_set_auth():
    """Test set_auth to a thread-local based context.
    """
    ctx = local()
    auth = Auth(user_id="test-001", username="user@example.com")

    set_auth(ctx, auth)

    assert ctx.microkubes_auth is not None
    assert ctx.microkubes_auth == auth


def test_has_auth():
    """Test has_auth with thread-local based context.
    """
    ctx = local()
    auth = Auth(user_id="test-001", username="user@example.com")

    assert has_auth(ctx) is False

    ctx.microkubes_auth = auth

    assert has_auth(ctx)


def test_clear_auth():
    """Test clear_auth to a thread-local based context.
    """
    ctx = local()
    auth = Auth(user_id="test-001", username="user@example.com")

    ctx.microkubes_auth = auth

    assert has_auth(ctx)

    clear_auth(ctx)

    assert has_auth(ctx) is False


def test_security_context():
    """Test SecurityContext with thread-local based context.
    """
    local_context = local()
    sc = SecurityContext(local_context)

    assert sc.has_auth() is False

    auth = Auth(user_id="test", username="test@example.com")

    sc.set_auth(auth)

    assert local_context.microkubes_auth is not None
    assert sc.has_auth() is True

    result = sc.get_auth()
    assert result is not None
    assert result == auth

    sc.clear_auth()

    assert local_context.microkubes_auth is None

    assert sc.has_auth() is False
    assert sc.get_auth() is None
