# ADB Tools

Tools for hacking ADB Epicentro routers. Python dependencies can be installed
using `pip3 install -r requirements.txt`. No Python 2 support. Do not replicate
any of the cryptographic practices shown here as they are all completely
braindead unless marked otherwise.

## overflow.py

Uses a buffer overflow in the login page to make the default user admin. Takes
the login page as an argument. Credit to Alain Mowat (@plopz0r) for the
exploit. Was patched in October 2015.

Example:

    python3 overflow.py 'http://10.0.0.138/ui/login'

## pkcrypt

Tool used for encrypting the config backups from the webinterface. Uses an RSA
public key for AES encryption. Sounds really stupid at first, but gets even
worse when you look at how they implemented it. Has a Python and C++ version
that both do exactly the same. Only works with configs created with version
E_3.4.0 or later (May 2017) as older ones tried to use asymmetric encryption
without a private key, which makes the configs impossible to decrypt, even for
the devices themselves. Key can be found at `/etc/certs/download.pem` in the
firmware image.

Example:

    python3 pkcrypt.py sym_decrypt download.pem config.bin config.xml

Compiling the C++ version (not necessary if you use the Python version):

    g++ pkcrypt.cpp -lcryptopp -o pkcrypt

## YAPL file structure

Yapl files are used as the CGI templates. This is just documentation that I
didn't know where else to put.

    0x00 - 0x03: Header "Yapl"
    0x04 - 0x07: Padding
    0x08 - 0x0B: Number of strings
    0x0C - 0x0F: Padding
    0x10 - ....: Zero separated strings
    .... - ....: Instructions that somehow reference the strings
