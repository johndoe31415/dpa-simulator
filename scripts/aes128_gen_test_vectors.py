#!/usr/bin/python3
#
#

import os
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.primitives.ciphers.modes
import cryptography.hazmat.primitives.ciphers.algorithms

def aes128_ecb_enc(plaintext, key):
	backend = default_backend()
	ecb = cryptography.hazmat.primitives.ciphers.modes.ECB()
	encryptor = cryptography.hazmat.primitives.ciphers.Cipher(cryptography.hazmat.primitives.ciphers.algorithms.AES(key = key), ecb, backend = backend).encryptor()
	ciphertext = encryptor.update(plaintext) + encryptor.finalize()
	return ciphertext


print(aes128_ecb_enc(bytes(16),bytes(16)).hex())
for i in range(16):
	k = os.urandom(16)
	p = os.urandom(16)
	c = aes128_ecb_enc(plaintext = p, key = k)
	print("{ .key = \"%s\", .plaintext = \"%s\", .ciphertext = \"%s\" }," % (k.hex(), p.hex(), c.hex()))
