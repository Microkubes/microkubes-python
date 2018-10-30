"""Test microkubes.security.keys module.
"""

from os.path import join as path_join
from tempfile import NamedTemporaryFile, TemporaryDirectory
from microkubes.security.keys import Key, KeyStore


def test_load_key():
    """Test loading key from temporary file.
    """
    with NamedTemporaryFile() as tmpf:
        tmpf.write(b"THIS IS THE KEY CONTENT")
        tmpf.flush()

        key = Key(key_file=tmpf.name)

        cnt = key.load()

        assert cnt == b"THIS IS THE KEY CONTENT"


def test_key_store_load_from_dir():
    """Test KeyStore loading keys from a directory.
    """
    with TemporaryDirectory() as tmpdir:

        with open(path_join(tmpdir, 'system'), 'wb') as kf:
            kf.write(b'SYSTEM PRIVATE KEY')

        with open(path_join(tmpdir, 'system.pub'), 'wb') as kf:
            kf.write(b'SYSTEM PUBLIC KEY')

        with open(path_join(tmpdir, 'ignored.crt'), 'wb') as kf:
            kf.write(b'this must be ignored')

        with open(path_join(tmpdir, 'default.pub'), 'wb') as kf:
            kf.write(b'DEFAULT PUBLIC KEY')


        ks = KeyStore(dir_path=tmpdir)

        assert ks.keys.get('ignored') is None
        assert ks.keys.get('ignored.pub') is None
        assert ks.keys.get('ignored.crt') is None

        syskey = ks.get_key('system')
        assert syskey is not None
        assert syskey.public is True
        assert syskey.load() == b'SYSTEM PUBLIC KEY'

        syskey = ks.get_private_key('system')
        assert syskey is not None
        assert syskey.public is False
        assert syskey.load() == b'SYSTEM PRIVATE KEY'

        default = ks.get_key()
        assert default is not None

        public_keys = ks.public_keys()

        assert len(public_keys) == 2
        assert public_keys.get('system') is not None
        assert public_keys.get('default') is not None


def test_key_store_load_keys_map():
    """Test KeyStore loading keys from a given keys map.
    """
    with TemporaryDirectory() as tmpdir:

        with open(path_join(tmpdir, 'system'), 'wb') as kf:
            kf.write(b'SYSTEM PRIVATE KEY')

        with open(path_join(tmpdir, 'default.pub'), 'wb') as kf:
            kf.write(b'DEFAULT PUBLIC KEY')

        with open(path_join(tmpdir, 'system.pub'), 'wb') as kf:
            kf.write(b'SYSTEM PUBLIC KEY')

        ks = KeyStore(keys={
            'default': path_join(tmpdir, 'default.pub'),
            'system': path_join(tmpdir, 'system'),
        })

        syskey = ks.get_private_key('system')
        assert syskey is not None
        assert syskey.public is False
        assert syskey.load() == b'SYSTEM PRIVATE KEY'

        default = ks.get_key()
        assert default is not None

        ks.add_key('system', path_join(tmpdir, 'system.pub'))

        assert ks.get_key('system') is not None
        assert ks.get_private_key('system') is not None
        assert ks.get_key('system') != ks.get_private_key('system')
        assert ks.get_key('system').load() != ks.get_private_key('system').load()
