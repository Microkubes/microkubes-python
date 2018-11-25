"""JWT Security provider test.
"""
from os.path import join as path_join
from tempfile import TemporaryDirectory
from threading import local

from unittest import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import jwt

from microkubes.security.keys import KeyStore
from microkubes.security.jwt import JWTProvider
from microkubes.security.chain import Request, Response
from microkubes.security.auth import SecurityContext


def generate_RSA_keypair():
    """Generate RSA key pair.
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                    backend=default_backend())


def serialize_private_pem(key):
    """Serialize the private key as PEM in PKCS8 format.
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def serialize_public_pem(key):
    """Serialize the public key as PEM.
    """
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def get_jwt(key_store, claims):
    """Generate signed JWT with custom claims using the "system" key from the KeyStore.
    """
    return jwt.encode(claims, key_store.get_private_key('system').load(), algorithm='RS256').decode('utf-8')


@mock.patch.object(Request, 'get_header')
def test_jwt_pass(get_header_mock):
    """Test the JWT provider in a successful vanila scenario.
    """
    with TemporaryDirectory() as tmpdir:
        rsa_key = generate_RSA_keypair()

        priv_key = serialize_private_pem(rsa_key)
        pub_key = serialize_public_pem(rsa_key)

        with open(path_join(tmpdir, 'system'), 'wb') as keyfile:
            keyfile.write(priv_key)

        with open(path_join(tmpdir, 'system.pub'), 'wb') as keyfile:
            keyfile.write(pub_key)

        key_store = KeyStore(dir_path=tmpdir)

        header_token = get_jwt(key_store, {
            'userId': 'test-user',
            'username': 'user@example.com',
            'scopes': 'api:read',
            'roles': 'user,test',
            'organizations': 'org1,org2',
            'namespaces': 'microkubes,special1'
        })

        get_header_mock.return_value = 'Bearer %s' % header_token

        jwt_provider = JWTProvider(key_store=key_store)

        local_context = local() # Thread-Local underlying local context

        context = SecurityContext(local_context=local_context)

        req_object = local()
        request = Request(req_object)

        response = Response()

        jwt_provider(context, request, response)

        assert context.has_auth()
        auth = context.get_auth()

        assert auth is not None
        assert auth.user_id == 'test-user'
        assert auth.username == 'user@example.com'
        assert auth.scopes == ['api:read']
        assert auth.roles == ['user', 'test']
        assert auth.organizations == ['org1', 'org2']
        assert auth.namespaces == ['microkubes', 'special1']
