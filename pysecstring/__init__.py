__version__ = '0.1.0'


import platform

if platform.system() != 'Windows':
    raise ImportError("secstring module only meant to run on Windows!")

from .main import encrypt, decrypt, set_credentials, get_credentials, Blob
