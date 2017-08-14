#!/usr/bin/env python3

import sys
from Crypto.Cipher import AES # requires pycrypto

if len(sys.argv) < 5:
    print("Usage: pkcrypt.py sym_encrypt|sym_decrypt <key> <in> <out>")
    exit(1)

task = sys.argv[1]
if task not in ("sym_encrypt", "sym_decrypt"):
    print("Error: First argument must be sym_encrypt or sym_decrypt.")
    exit(1)

key_filename = sys.argv[2]
in_filename = sys.argv[3]
out_filename = sys.argv[4]

with open(key_filename, "rb") as f:
    pem_data = f.read()
with open(in_filename, "rb") as f:
    data_in = f.read()

# Going for the popular choice...
IV = b"\x00" * AES.block_size

# Just take a random chunk out of the file and use it as our key
key = pem_data[0x20:0x30]
cipher = AES.new(key, AES.MODE_CBC, IV)

if task == "sym_encrypt":
    padding_length = AES.block_size - (len(data_in) % AES.block_size)
    if padding_length != AES.block_size:
        padding_byte = padding_length.to_bytes(1, "big")
        data_in += padding_byte * padding_length
    data_out = cipher.encrypt(data_in)
elif task == "sym_decrypt":
    data_out = cipher.decrypt(data_in)
    # Padding is a badly implemented PKCS#7 where 16 bytes padding is ignored,
    # so we have to check all previous bytes to see if it is valid.
    padding_length = data_out[-1]
    if (padding_length < AES.block_size) && (padding_length < len(data_out)):
        for i in range(0, padding_length):
            if data_out[-1 - i] != padding_length:
                break
        else:
            data_out = data_out[:-padding_length]
else:
    raise NotImplementedError("Operation not supported")

with open(out_filename, "wb") as f:
    f.write(data_out)
