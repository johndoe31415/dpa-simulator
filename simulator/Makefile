.PHONY: all clean test

CFLAGS := $(CFLAGS) -std=c11
CFLAGS += -Wall -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Werror=format -Wimplicit-fallthrough -Wshadow
CFLAGS += -O3 -g3

LDFLAGS := -lthumb2sim

TARGETS := trace_simulator
OBJS := argparse.o

all: $(TARGETS)

clean:
	rm -f $(OBJS) $(TARGETS)

test: trace_simulator
	./trace_simulator

trace_simulator: $(OBJS) trace_simulator.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<
