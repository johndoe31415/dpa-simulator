#	dpa-simulator - Create simulated traces for demonstrating basic DPA/CPA.
#	Copyright (C) 2022-2022 Johannes Bauer
#
#	This file is part of dpa-simulator.
#
#	dpa-simulator is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	dpa-simulator is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with dpa-simulator; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import re
import json
import base64
import random
import struct
from cryptography.hazmat.backends import default_backend
import cryptography.hazmat.primitives.ciphers.modes
import cryptography.hazmat.primitives.ciphers.algorithms

class Tracefile():
	def __init__(self, filename):
		with open(filename) as f:
			self._tracefile = json.load(f)
		if "key" in self._tracefile["meta"]:
			self._tracefile["meta"]["key"] = base64.b64decode(self._tracefile["meta"]["key"])
		for trace in self._tracefile["traces"]:
			trace["ciphertext"] = base64.b64decode(trace["ciphertext"])
			trace["plaintext"] = base64.b64decode(trace["plaintext"])
			trace["data"] = self._interpret_samples(base64.b64decode(trace["data"]))

	def _interpret_samples(self, samples):
		if self.format == "uint8_t":
			# Return them verbatin as values from 0..255
			return samples
		elif self.format == "float":
			fmt = "<%df" % (len(samples) // 4)
			return struct.unpack(fmt, samples)
		else:
			raise NotImplementedError(self.format)

	@property
	def correct_key(self):
		return self._tracefile["meta"].get("key")

	@property
	def format(self):
		return self._tracefile["meta"].get("format", "uint8_t")

	@correct_key.setter
	def correct_key(self, value):
		self.validate_key(value)
		self._tracefile["meta"]["key"] = value

	def randomize(self):
		random.shuffle(self._tracefile["traces"])

	@property
	def total_trace_count(self):
		return len(self._tracefile["traces"])

	@staticmethod
	def _aes128_enc(plaintext, key):
		backend = default_backend()
		ecb = cryptography.hazmat.primitives.ciphers.modes.ECB()
		encryptor = cryptography.hazmat.primitives.ciphers.Cipher(cryptography.hazmat.primitives.ciphers.algorithms.AES(key = key), ecb, backend = backend).encryptor()
		ciphertext = encryptor.update(plaintext) + encryptor.finalize()
		return ciphertext

	def validate_key(self, key):
		if (self._tracefile["meta"]["algorithm"] == "AES-128") and (self._tracefile["meta"]["mode"] == "encrypt"):
			for trace in self:
				c = self._aes128_enc(trace["plaintext"], key)
				if c != trace["ciphertext"]:
					raise Exception("Invalid key and/or corrput data. K = %s, P = %s would expect C = %s but tracefile contains C = %s" % (key.hex(), trace["plaintext"].hex(), c.hex(), trace["ciphertext"].hex()))
		else:
			raise Exception("Cannot validate unknown key type.")

	def __iter__(self):
		return iter(self._tracefile["traces"])


if __name__ == "__main__":
	tf = Tracefile("aes128_encrypt.json")
	print(tf)
	tf.validate_key(bytes.fromhex("ab eb d2 3e 6e ee c2 c2 f2 64 8c 47 9b ca 6e ba"))


