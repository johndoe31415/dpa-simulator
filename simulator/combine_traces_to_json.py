#!/usr/bin/python3
import sys
import base64
import json
import datetime
import os
import re
from FriendlyArgumentParser import FriendlyArgumentParser

parser = FriendlyArgumentParser(description = "Combine lots of simulated DPA traces into one JSON file.")
parser.add_argument("-k", "--correct-key", metavar = "hex", type = bytes.fromhex, help = "Use this is the known correct key. Must be given in hex notation. Will be embedded into the JSON file and will be used for validation.")
parser.add_argument("-m", "--mode", choices = [ "aes128enc" ], default = "aes128enc", help = "Specifies the mode; by default this is %(default)s. Can be one of %(choices)s.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("input_directory", help = "Directory in which the tracefiles resides which the simulator generated ")
parser.add_argument("output_json", help = "Output JSON file")
args = parser.parse_args(sys.argv[1:])

tracefile = {
	"meta": {
		"created":		datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
	},
	"traces": [ ],
}

if args.mode == "aes128enc":
	tracefile["meta"]["algorithm"] = "AES-128"
	tracefile["meta"]["mode"] = "encrypt"

if args.correct_key is not None:
	tracefile["meta"]["key"] = base64.b64encode(args.correct_key).decode("ascii")

regex = re.compile(r"trace_P_(?P<plaintext>[0-9a-f]{32})_C_(?P<ciphertext>[0-9a-f]{32})\.bin")
for filename in os.listdir(args.input_directory):
	match = regex.fullmatch(filename)
	if match:
		match = match.groupdict()
		full_filename = args.input_directory + "/" + filename
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

with open(args.output_json, "w") as f:
	json.dump(tracefile, f)
