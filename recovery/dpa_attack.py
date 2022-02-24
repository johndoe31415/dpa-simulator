#!/usr/bin/python3
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

import sys
import subprocess
from FriendlyArgumentParser import FriendlyArgumentParser
from Tracefile import Tracefile

class DPAAttack():
	_AES_SBOX = [
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
	]

	def __init__(self, args):
		self._args = args
		self._tracefile = Tracefile(self._args.tracefile)
		self._key = bytearray(16)

	@property
	def key(self):
		return self._key

	@staticmethod
	def _hweight(x):
		weight = 0
		while x > 0:
			if (x & 1) == 1:
				weight += 1
			x >>= 1
		return weight

	@staticmethod
	def _avg_trace(traces):
		trace_count = len(traces)
		trace_length = len(traces[0])
		result_values = [ 0 ] * trace_length
		for trace in traces:
			for (index, value) in enumerate(trace):
				result_values[index] += value
		for index in range(len(result_values)):
			result_values[index] /= trace_count
		return result_values

	@staticmethod
	def _diff_trace(trace1, trace2):
		return [ x - y for (x, y) in zip(trace1, trace2) ]


	def _attack_keybyte_with_guess(self, i, K):
		low_traces = [ ]
		high_traces = [ ]

		used_trace_count = 0
		for (traceno, trace) in enumerate(self._tracefile):
			if (self._args.max_traces is not None) and (traceno == self._args.max_traces):
				break

			used_trace_count += 1
			P = trace["plaintext"][i]
			C = trace["ciphertext"][i]

			# This is what happens for every byte with the first roundkey (which is the AES key):
			#
			#    Q = (P XOR K)			// add_round_key
			#    Q = AES_SBOX[Q]		// sub_bytes
			#
			# We attack the second instruction by estimating the hamming
			# distance of Q and Q' (after the S-box substitution) and only
			# choose those traces for the grouping which have the most
			# pronounced change in Hamming weight.

			Q = P ^ K
			Qpost = self._AES_SBOX[Q]
			flips = self._hweight(Q ^ Qpost)

			if flips <= 1:
				# Low flip candidate
				low_traces.append(trace["data"])
			elif flips >= 7:
				# High flip candidate
				high_traces.append(trace["data"])

		if (len(low_traces) == 0) or (len(high_traces) == 0):
			print("Attacking keybyte %d with guess K = %02x failed: %3d low and %3d high candidates -- cannot compute differential trace; retry with more traces if the attack fails" % (i, K, len(low_traces), len(high_traces)))
		else:

			avg_low = self._avg_trace(low_traces)
			avg_high = self._avg_trace(high_traces)
			diff = self._diff_trace(avg_high, avg_low)
			metric = max(diff)
			if self._best_guess is None:
				self._best_guess = (K, metric)
			elif metric > self._best_guess[1]:
				self._best_guess = (K, metric)
			print("Attacking keybyte %d with guess K = %02x: %3d low and %3d high candidates; used %d traces of %d available (%.0f%%), grouped %d of those (%.0f%%); max diff %6.3f (best %02x %6.3f)" % (i, K, len(low_traces), len(high_traces), used_trace_count, self._tracefile.total_trace_count, used_trace_count / self._tracefile.total_trace_count * 100, len(low_traces) + len(high_traces), (len(low_traces) + len(high_traces)) / used_trace_count * 100, metric, self._best_guess[0], self._best_guess[1]))

			if self._args.create_plots:
				plotfile = "plots/K_%02d_%02x.txt" % (i, K)
				with open(plotfile, "w") as f:
					for value in diff:
						print(value, file = f)

				subprocess.check_output([ "gnuplot" ], input = ("""
					set terminal pngcairo size 1920,1080 enhanced
					set yrange [ -8 : 8 ]
					set output '%s.png'
					plot '%s' with lines
				""" % (plotfile, plotfile)).encode())

			self._key[i] = self._best_guess[0]


	def _attack_keybyte(self, i):
		self._best_guess = None
		for K in range(256):
			self._attack_keybyte_with_guess(i, K)

	def attack(self):
		if self._args.randomize:
			self._tracefile.randomize()
		if len(self._args.keybyte) == 0:
			for i in range(16):
				self._attack_keybyte(i)
		else:
			for i in self._args.keybyte:
				self._attack_keybyte(i)
		print("Recovered key after attack: %s" % (" ".join("%02x" % (x) for x in self._key)))


parser = FriendlyArgumentParser(description = "Educational tool to demonstrate differential power analysis.")
parser.add_argument("-r", "--randomize", action = "store_true", help = "Randomly shuffle traces before starting.")
parser.add_argument("-p", "--create-plots", action = "store_true", help = "Create gnuplot plots for each diffential trace.")
parser.add_argument("-n", "--max-traces", metavar = "count", type = int, help = "Use this number of traces at maximum for each keykyte estimation. By default, all traces in the tracefile are used.")
parser.add_argument("-i", "--keybyte", metavar = "index", type = int, action = "append", default = [ ], help = "Attack keybyte at index i. Can be specified multiple times. By default, all keybytes are tried.")
parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increases verbosity. Can be specified multiple times to increase.")
parser.add_argument("tracefile", metavar = "tracefile_json", help = "The JSON source file which contains all collected/simulated traces")
args = parser.parse_args(sys.argv[1:])

dpa = DPAAttack(args)
dpa.attack()
