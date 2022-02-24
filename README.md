# dpa-simulator
dpa-simulator is an educational tool to demonstrate how differential power
analysis works. It emulates code (Cortex-M code using
[libthumb2sim](https://github.com/johndoe31415/libthumb2sim)) and generates
"artificial" traces based on a simple Hamming distance model of flipped bits in
both register set and SRAM. This means that for experimentation, no hardware is
needed whatsoever.

To make explaining the concept of key recovery simpler, DPA was also chosen as
the attack mode instead of CPA.

## Prerequisites
You need to have [libthumb2sim](https://github.com/johndoe31415/libthumb2sim)
installed on your system to run the simulator. For the recovery, you need
Python3 and the "cryptography" module (it plausibilizes keys). If you want to
build your own embedded firmware to test attacks, you also need an ARM
compiler. By default, a vulnerable AES-128 encryption library is also shipped
in binary form.

## Usage
If you want to create traces, first build the simulator in the simulator/
subdirectory. Then just start it and give it an AES-128 key:

```
$ ./trace_simulator -k a617db75310a5f1cc7241bfcd9cb93e0 /tmp/my_traces
```

This generates lots of binary files in the `/tmp/my_traces` subdirectory. You
can also parallelize this manually. For example on a 24-CPU system if you want
2000 traces in total, that gives around 83 traces for each CPU. Simply do:

```
$ for i in `seq 24`; do ./trace_simulator -n 83 -k a617db75310a5f1cc7241bfcd9cb93e0 /tmp/my_traces >/dev/null 2>&1 & done
```

After emulation, to easier handle the trace files from Python, you can convert
them into a unified JSON file:

```
$ ./combine_traces_to_json.py /tmp/my_traces my_traces.json
```

By default, this file does not contain the correct key. However, you can also
specify it so that it beomes known:

```
$ ./combine_traces_to_json.py -k a617db75310a5f1cc7241bfcd9cb93e0 /tmp/my_traces my_traces.json
```

Then, you can attempt recovery. Switch to the `recovery/` subdirectory and have at it:

```
$ ./dpa_attack.py my_traces.json
Attacking keybyte 0 with guess K = 00:  84 low and  56 high candidates; used 2010 traces of 2010 available (100%), grouped 140 of those (7%); max diff  2.137 (best 00  2.137)
Attacking keybyte 0 with guess K = 01: 115 low and  62 high candidates; used 2010 traces of 2010 available (100%), grouped 177 of those (9%); max diff  1.082 (best 00  2.137)
Attacking keybyte 0 with guess K = 02:  92 low and  51 high candidates; used 2010 traces of 2010 available (100%), grouped 143 of those (7%); max diff  1.400 (best 00  2.137)
Attacking keybyte 0 with guess K = 03:  96 low and  61 high candidates; used 2010 traces of 2010 available (100%), grouped 157 of those (8%); max diff  0.971 (best 00  2.137)
Attacking keybyte 0 with guess K = 04: 117 low and  42 high candidates; used 2010 traces of 2010 available (100%), grouped 159 of those (8%); max diff  1.572 (best 00  2.137)
Attacking keybyte 0 with guess K = 05:  74 low and  68 high candidates; used 2010 traces of 2010 available (100%), grouped 142 of those (7%); max diff  1.071 (best 00  2.137)
Attacking keybyte 0 with guess K = 06: 101 low and  61 high candidates; used 2010 traces of 2010 available (100%), grouped 162 of those (8%); max diff  1.607 (best 00  2.137)
Attacking keybyte 0 with guess K = 07:  75 low and  52 high candidates; used 2010 traces of 2010 available (100%), grouped 127 of those (6%); max diff  1.116 (best 00  2.137)
Attacking keybyte 0 with guess K = 08: 112 low and  48 high candidates; used 2010 traces of 2010 available (100%), grouped 160 of those (8%); max diff  1.512 (best 00  2.137)
Attacking keybyte 0 with guess K = 09:  85 low and  63 high candidates; used 2010 traces of 2010 available (100%), grouped 148 of those (7%); max diff  1.231 (best 00  2.137)
Attacking keybyte 0 with guess K = 0a:  99 low and  61 high candidates; used 2010 traces of 2010 available (100%), grouped 160 of those (8%); max diff  1.222 (best 00  2.137)
Attacking keybyte 0 with guess K = 0b:  81 low and  54 high candidates; used 2010 traces of 2010 available (100%), grouped 135 of those (7%); max diff  1.099 (best 00  2.137)
Attacking keybyte 0 with guess K = 0c:  83 low and  52 high candidates; used 2010 traces of 2010 available (100%), grouped 135 of those (7%); max diff  1.263 (best 00  2.137)
Attacking keybyte 0 with guess K = 0d:  98 low and  57 high candidates; used 2010 traces of 2010 available (100%), grouped 155 of those (8%); max diff  1.206 (best 00  2.137)
[...]
```

The attack is deliberately simple: It makes, based on plaintext and keyguess,
an estimate about the Hamming weight change of the S-box substitution. It only
considers those traces that have either 1 or 7 bits flipped and groups them to
build the differential average trace. Then it looks for a peak in that trace.

## Notes
This attack is quite simple and simulation is not intended to replace actual
target analysis. The goal of this piece of code is to allow people easy access
and simple alogorithmic recovery that they can fully understand before turning
to actual tools like the [ChipWhisperer](https://www.newae.com/chipwhisperer).

In general, if you're looking for a comprehensive explanation of how this is
actually done in practice by a professional, take a look at the [excellent
videos of Colyn O'Flynn](https://www.youtube.com/watch?v=OlX-p4AGhWs), who just
so happens to also be the inventor of the the ChipWhisperer.

## License
GNU GPL-3.
