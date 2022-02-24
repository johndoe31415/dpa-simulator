import argparse
parser = argparse.ArgumentParser(prog = "trace_simulator", description = "Emulates embedded code and simulates power traces.", add_help = False)
parser.add_argument("-f", "--firmware", metavar = "filename", default = "aes128_rom.bin", help = "The firmware file to emulate. Defaults to %(default)s.")
parser.add_argument("-n", "--tracecnt", metavar = "count", type = int, default = 1000, help = "An integer that specifies the amount of traces to generate by default. Defaults to %(default)d.")
parser.add_argument("-k", "--key", metavar = "key", help = "Gives the key to feed the implementation. By default the key is entirely zeros.")
parser.add_argument("output_directory", metavar = "path", help = "Output directory to write tracefiles into.")
