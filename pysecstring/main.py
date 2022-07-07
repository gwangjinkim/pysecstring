# Copyright 2015, Nashwan Azhari.
# Licensed under the GPLv2, see LICENSE file for details.

"""
Basic Blob structure used for data manipulation.
"""

from ctypes import c_char
from ctypes import create_string_buffer
from ctypes import POINTER
from ctypes import Structure
from ctypes import cdll
from ctypes import windll
from ctypes.wintypes import DWORD

# correctly set windll.kernel32.LocalFree for 64bit 

import ctypes
import ctypes.wintypes


import subprocess

'''
win32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
win32.LocalAlloc.argtypes = [ctypes.c_ulong, ctypes.c_size_t]
win32.LocalAlloc.restype = ctypes.wintypes.HLOCAL
h=win32.LocalAlloc(0, 10)
## h ## 2348093371568
win32.LocalFree.argtypes = ctypes.wintypes.HLOCAL,
win32.LocalFree.restype = ctypes.wintypes.HLOCAL
## win32.LocalFree(h) # None is returned for a NULL pointer   # now win32.LocalFree is set correctly!

# source was: https://stackoverflow.com/questions/62538206/using-ctypes-with-dll-receiving-incorrect-return-values
'''

# with the source
# https://stackoverflow.com/questions/23522055/error-when-unload-a-64bit-dll-using-ctypes-windll

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]

memcpy = cdll.msvcrt.memcpy
localfree = windll.kernel32.LocalFree

class Blob(Structure):
    """Basic Structure used for data manipulation.
    It is structurally identical to the native CRYPT_INTEGER_BLOB structure.
    Composed of a field holding the length of the data and a
    pointer to the start of it.
    """
    _fields_ = [("length", DWORD), ("data", POINTER(c_char))]

    def get_data(self):
        """Fetches the data from the Blob."""
        fetched = create_string_buffer(self.length)

        memcpy(fetched, self.data, self.length)

        return fetched.raw

    def free_blob(self):
        """Frees the memory allocated for the Blob's data."""
        localfree(self.data)



"""
A pure Python implementation of the functionality of the ConvertTo-SecureString
and ConvertFrom-SecureString PoweShell commandlets.
Usage example:
from securestring import encrypt, decrypt
if __name__ == "__main__":
    str = "My horse is amazing"
    # encryption:
    try:
        enc = encrypt(str)
        print("The encryption of %s is: %s" % (str, enc))
    except Exception as e:
        print(e)
    # decryption:
    try:
        dec = decrypt(enc)
        print("The decryption of the above is: %s" % dec)
    except Exception as e:
        print(e)
    # checking of operation symmetry:
    print("Encryption and decryption are symmetrical: %r", dec == str)
    # decrypting powershell input:
    psenc = "<your output of ConvertFrom-SecureString>"
    try:
        dec = decrypt(psenc)
        print("Decryption from ConvertFrom-SecureString's input: %s" % dec)
    except Exception as e:
        print(e)
"""

from codecs import encode
from codecs import decode

# from blob import Blob

from ctypes import byref
# from ctypes import create_string_buffer
# from ctypes import windll

protect_data = windll.crypt32.CryptProtectData
unprotect_data = windll.crypt32.CryptUnprotectData


def encrypt(input):
    """Encrypts the given string following the same syscalls as done by
    ConvertFrom-SecureString.
    Arguments:
    input -- an input string.
    Returns:
    output -- string containing the output of the encryption in hexadecimal.
    """
    # CryptProtectData takes UTF-16; so we must convert the data here:
    encoded = input.encode("utf-16")
    data = create_string_buffer(encoded, len(encoded))

    # create our various Blobs:
    input_blob = Blob(len(encoded), data)
    output_blob = Blob()
    flag = 0x01

    # call CryptProtectData:
    res = protect_data(byref(input_blob), u"", byref(Blob()), None,
                       None, flag, byref(output_blob))
    # input_blob.free_blob()
    del input_blob

    # check return code:
    if res == 0:
        output_blob.free_blob()
        raise Exception("Failed to encrypt: %s" % input)
    else:
        raw = output_blob.get_data()
        # output_blob.free_blob()
        del output_blob

        # encode the resulting bytes into hexadecimal before returning:
        hex = encode(raw, "hex")
        return decode(hex, "utf-8").upper()


def decrypt(input, binary=False):
    """Decrypts the given hexadecimally-encoded string in conformity
    with CryptUnprotectData.
    Arguments:
    input -- the encrypted input string in hexadecimal format.
    Returns:
    output -- string containing the output of decryption.
    """
    # de-hex the input:
    if binary:
        rawinput = input
    else:
        rawinput = decode(input, "hex")
    data = create_string_buffer(rawinput, len(rawinput))

    # create out various Blobs:
    input_blob = Blob(len(rawinput), data)
    output_blob = Blob()
    dwflags = 0x01

    # call CryptUnprotectData:
    res = unprotect_data(byref(input_blob), u"", byref(Blob()), None,
                         None, dwflags, byref(output_blob))
    # input_blob.free_blob() # this created an error - probably segdefault?
    del input_blob # this corrects it!

    # check return code:
    if res == 0:
        output_blob.free_blob()
        raise Exception("Failed to decrypt: %s" + input)
    else:
        raw = output_blob.get_data()
        # output_blob.free_blob()
        del output_blob

        # decode the resulting data from UTF-16:
        return decode(raw, "utf-16")



class CredentialGenerator:
    
    @classmethod
    def cmd(cls, cmd):
        return subprocess.run(["powershell.exe", "-Command", cmd], capture_output=True)
    
    @classmethod
    def generate(cls, username_file, pass_file):
        # asks for username and password to save it in encrypted forms
        res = cls.cmd( f"ConvertFrom-SecureString $(Read-Host -Prompt 'Enter the username' -AsSecureString) | Out-File {username_file}")
        res1 = cls.cmd(f"ConvertFrom-SecureString $(Read-Host -Prompt 'Enter the password' -AsSecureString) | Out-File {pass_file}")
        return (res, res1)            

# for nicer interface of the module:
def set_credentials(username_file, pass_file):
    return CredentialGenerator.generate(username_file, pass_file)

class CredentialObject:
    
    def __init__(self, user_file, pass_file):
        self.user_file = user_file
        self.pass_file = pass_file
    
    def read_in(self, path):
        with open(path, 'rb') as fin:
            return fin.read()
    
    @property
    def password(self):
        return self.decrypt(self.pass_file)
    
    @property
    def username(self):
        return self.decrypt(self.user_file)
    
    def decrypt(self, path):
        encrypted_binary = self.read_in(path)
        encrypted = decode(encrypted_binary, 'utf-16').strip() # Out-File adds a '\r\x00\n\x00' at the end! therefore `.strip()`
        return pss.decrypt(encrypted)

# for nicer interface of the module:
def get_credentials(user_file, pass_file):
    return CredentialObject(user_file, pass_file)

'''
# usage - CredentialGenerate
CredentialGenerator.generate(r'.\.user', r'.\.pass')

# usage:
co = CredentialObject(r'.\.user', r'.\.pass')
co.password
co.username
'''



