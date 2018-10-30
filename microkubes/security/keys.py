
"""Tools and helpers for manipulating key files.

Defines a wrapper around a key file and a store for keys retrieval.
"""


from os import listdir, sep as path_sep
from os.path import isdir, isfile, abspath, basename


class KeyError(Exception):
    """Represents an error that occurs during loading or specifying a key.
    """
    pass


class Key:
    """Key holds the path to the actual key file and a flag whether the key is public or private (if applicable).

    :param key_file: ``str``, the path to the key file.
    :param public: ``bool``, flag indicating whether this key is public.

    :raises: :class:`KeyError` if the key file does not exist or is not a file.
    """
    def __init__(self, key_file, public=False):
        self.public = public
        self.key_file = key_file
        if not isfile(self.key_file):
            raise KeyError('File %s does not exist or is not a file.' % self.key_file)
    
    def load(self):
        """Tries to load a key from the given file.

        Returns the content of the key as bytes.

        :raises: :class:`KeyError` if an error occurs during loading.
        """
        try:
            with open(self.key_file, 'rb') as kf:
                return kf.read()
        except Exception as read_err:
            raise KeyError from read_err


class KeyStore:
    """Loads keys from a given directory or a key map (key_name => key_file).

    The store is being used to quickly fetch/load a key from a map of known keys.

    When loading the keys, the store guesses whether the key is public or not based on
    the file name:

        * If the file name ends in ".pub" the key is flagged as public key.
        * If the file name ends in ".pem" or does not have an extension, then the key is flagged as private.
        * If the file ends with other extension, it is ignored and not loaded.

    :param dir_path: ``str``, the directory to load keys from. Optional.
    :param keys: ``dict``, keys map in the form key_name => key_file. Whether the key is public/private is guessed
        based on the file name.

    """
    def __init__(self, dir_path=None, keys=None):
        self.keys = {}
        if dir_path is not None:
            self._load_keys_from_dir(dir_path)
        if keys is not None:
            self._load_keys_from_map(keys)
    

    def get_key(self, key_name=None):
        """Retrieves a :class:`Key` by name.

        :param key_name: ``str``, the name of the key to retrieve. If not given, the default value is ``default``.

        :returns: :class:`Key` if the key is found; otherwise raises :class:`KeyError`.

        """
        if key_name is None:
            key_name = 'default'
        key = self.keys.get(key_name)
        if not key:
            raise KeyError('No such key: %s' % key_name)
        return key
    
    def get_private_key(self, key_name):
        """Retrieves a key flagged as private by its name.

        If the name is not given, then will attempt to retrieve the private key with name ``default``.

        :param key_name: ``str``, the name of the key to retrieve. If not given, the default value is ``default``.

        :returns: :class:`Key` if the key is found; otherwise raises :class:`KeyError`.

        """
        key = self.get_key(key_name=key_name)
        if key.public:
            raise KeyError('No such private key: %s' % key_name)
        return key
    
    def public_keys(self):
        """Retrieves all of the public keys as a dict key_name => :class:`Key`.
        """
        return {key_name: key for key in self.keys if key.public}
    
    def add_key(self, key_name, key_file):
        """Add a key to this :class:`KeyStore`.

        :param key_name: ``str``, the name of the key.
        :param key_file: ``str``, key file path.

        """
        self._load_keys_from_map({key_name: key_file})
    
    def _load_keys_from_dir(self, dir_path):
        if not isdir(dir_path):
            raise KeyError('Path %s is not a directory.' % dir_path)
        
        for file_name in listdir(dir_path):
            abs_file_name = abspath(dir_path + path_sep + file_name)
            if isfile(abs_file_name):
                key_name = basename(abs_file_name)
                lwr_name = key_name.lower()
                if lwr_name.endswith('.pub'):
                    self.keys[key_name[:-4]] = Key(abs_file_name, public=True)
                elif lwr_name.endswith('.pem') or '.' not in lwr_name:
                    self.keys[key_name.split('.')[0]] = Key(abs_file_name, public=False)
    
    def _load_keys_from_map(self, keys):
        for key_name, key_file in keys.items():
            if not isfile(key_file):
                raise KeyError('Key file %s does not exist or it is not a file.' % key_file)
            abs_key_file = abspath(key_file)
            base_name = basename(abs_key_file)
            priv_key = True
            if base_name.lower().endswith('.pub'):
                priv_key=False
            
            self.keys[key_name] = Key(abs_key_file, public=not priv_key)