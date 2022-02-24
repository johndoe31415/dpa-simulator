#!/usr/bin/python3
import sys
import zlib
import base64
import json
import datetime
import os
import re

tracefile = {
	"meta": {
		"algorithm":	"AES-128",
		"mode":			"encrypt",
		"created":		datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
	},
	"traces": [ ],
}

input_dirname = sys.argv[1]
output_json_filename = sys.argv[2]

regex = re.compile(r"AES128_enc_P_(?P<plaintext>[0-9a-f]{32})_C_(?P<ciphertext>[0-9a-f]{32})\.bin")
for filename in os.listdir(input_dirname):
	match = regex.fullmatch(filename)
	if match:
		match = match.groupdict()
		full_filename = input_dirname + "/" + filename
		with open(full_filename, "rb") as f:
			trace_data = f.read()
		ciphertext = bytes.fromhex(match["ciphertext"])
		plaintext = bytes.fromhex(match["plaintext"])

		trace = {
			"plaintext": base64.b64encode(plaintext).decode("ascii"),
			"ciphertext": base64.b64encode(ciphertext).decode("ascii"),
			"data": base64.b64encode(trace_data).decode("ascii"),
		}
		tracefile["traces"].append(trace)

with open(output_json_filename, "w") as f:
	json.dump(tracefile, f)
