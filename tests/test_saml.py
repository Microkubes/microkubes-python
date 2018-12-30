"""SAML service provier test
"""

from threading import local
from unittest import mock
from os.path import join as path_join
from tempfile import TemporaryDirectory

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from onelogin.saml2.auth import OneLogin_Saml2_Auth

from microkubes.security import SAMLServiceProvider, SAMLSPUtils
from microkubes.security.chain import Request, Response
from microkubes.security.keys import KeyStore
from microkubes.security.auth import SecurityContext

configSAML = {
    "strict": True,
    "debug": False,
    "sp": {
        "entityId": "http://localhost:5000/metadata",
        "assertionConsumerService": {
            "url": "http://localhost:5000/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "x509cert": "",
        "privateKey": ""
    },
    "idp": {
        "entityId": "http://localhost:8080/saml/idp/metadata",
        "singleSignOnService": {
            "url": "http://localhost:8080/saml/idp/sso",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": ""
    },
    "security": {
        "nameIdEncrypted": False,
        "authnRequestsSigned": False,
        "signMetadata": False,
        "wantMessagesSigned": False,
        "wantAssertionsSigned": False,
        "wantNameId": False,
        "wantNameIdEncrypted": False,
        "wantAssertionsEncrypted": False,
    },
    "registration_url":"http://localhost:8080/saml/idp/services",
    "privateKeyName":"service.key",
    "certName": "service.cert"
}

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


@mock.patch.object(Request, 'args')
@mock.patch.object(Request, 'form')
def test_prepare_saml_request(args_mock, form_mock):
    """Prepare SAML request
    """
    req_object = local()
    request = Request(req_object)

    args_mock.return_value = ['arg1']
    form_mock.return_value = {'RelayState': 'dsd67atdas6dad67ad67a'}

    saml_req = SAMLSPUtils.prepare_saml_request(request)

    assert isinstance(saml_req, dict)
    assert len(saml_req) == 6

def test_get_sp_metadata():
    """ Return the SP metadata
    """
    metadata = SAMLSPUtils.get_sp_metadata(configSAML)

    assert isinstance(metadata, tuple)

def test_init_saml_auth():
    """ Initialize SAML auth object
    """
    req_object = local()
    request = Request(req_object)

    auth = SAMLSPUtils.init_saml_auth(request, configSAML)

    assert isinstance(auth, OneLogin_Saml2_Auth)

@mock.patch.object(SAMLServiceProvider, '_register_sp')
@mock.patch.object(Request, 'args')
@mock.patch.object(Request, 'form')
@mock.patch.object(Request, 'host')
def test_saml_sp(host_mock, form_mock, args_mock, register_sp_mock):
    """ Test SAML SP middleware
    """
    register_sp_mock.return_value = 'OK'
    args_mock.return_value = ['arg1']
    form_mock.return_value = {'RelayState': 'dsd67atdas6dad67ad67a'}
    host_mock = 'localhost:5000'

    with TemporaryDirectory() as tmpdir:
        rsa_key = generate_RSA_keypair()

        priv_key = serialize_private_pem(rsa_key)
        pub_key = serialize_public_pem(rsa_key)

        with open(path_join(tmpdir, 'service.key'), 'wb') as keyfile:
            keyfile.write(priv_key)

        with open(path_join(tmpdir, 'service.cert'), 'wb') as keyfile:
            keyfile.write(pub_key)

        key_store = KeyStore(dir_path=tmpdir)

        local_context = local() # Thread-Local underlying local context
        context = SecurityContext(local_context=local_context)

        req_object = local()
        request = Request(req_object)

        response = Response()

        sp = SAMLServiceProvider(key_store, configSAML)
        sp(context, request, response)

        assert response.redirect_url.startswith('http://localhost:8080/saml/idp/sso')

        saml_session = {
            'samlUserdata': {
                'urn:oid:0.9.2342.19200300.100.1.1': ['test-user'],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.6': ['test@example.com'],
                'urn:oid:1.3.6.1.4.1.5923.1.1.1.1': ['user']
            }
        }
        sp = SAMLServiceProvider(key_store, configSAML, saml_session=saml_session)
        sp(context, request, response)

        auth = context.get_auth()
        assert context.has_auth()
        assert auth.user_id == 'test-user'
        assert auth.roles == ['user']
        assert auth.username == 'test@example.com'
