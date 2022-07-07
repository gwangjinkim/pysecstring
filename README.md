This package serves as a mean to save passwords securely in Windows 10 machines.
It uses PowerShell's `SecureString` function and objects.

# Installation

You install this package simply from PyPI.org by:

```
pip install pysecstring
```

You could pip install directly from this github repository - which is the development repository.

Also, you could install it by git cloning this repository and `poetry install` it.

```
git clone https://github.com/gwangjinkim/pysecstring.git

cd pysecstring
poetry install
```

# Usage

The functions `encrypt()` and `decrypt()` serve as pure Python equivalents of the `ConvertTo-SecureString` (or `Read-Host -AsSecureString`) and the `ConvertFrom-SecureString` functions in PowerShell.

`set_credentials()` asks you for entering your username and password (starred input), which will store your credentials in two separate files in form of `SecureStrings`
(hexed binary - with a seed generated inside your computer).

`get_credentials()` reads these stored files and packs the credentials into a `CredentialObject` also known from PowerShell (but a Python equivalent version of it).
When probing for `.password` and `.username` properties from this credential, property-methods decrypt them immediately into plain text (but they are nowhere stored in plain text form - to enhance safety).

At any time point and place in your script, username and password are stored only in their encrypted form.

`set_credentials()` and `get_credentials()` work only when run on the same machine. Because different machines use different salts for encryption and decryption.

```
# save your credentials in the files `.\.user` and `.\.pass` in your machine:
username_file = '.\.user'
pass_file = '.\.pass'
set_credentials(username_file, pass_file)
# then PowerShell asks you for input of username and pass
# and these are stored in the username and pass files in an encrypted form - SecureString

# reads-in the SecureStrings and return them as one credential object
co = get_credentials(username_file, pass_file) 


# these credential object you can probe using property methods to get the decrypted plain text forms on the fly
co.username # returns decrypted username
co.password # returns decrypted password
# the decryption happens when the properties are called (property objects)
```

This repository started as a fork of `aznashwan/py-securestring`.
