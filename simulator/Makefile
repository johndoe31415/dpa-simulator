.PHONY: all clean test

CFLAGS := $(CFLAGS) -std=c11
CFLAGS += -Wall -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Werror=format -Wimplicit-fallthrough -Wshadow
CFLAGS += -Os -g3

LDFLAGS := -lthumb2sim

TARGETS := simulator
OBJS :=

all: $(TARGETS)

clean:
	rm -f $(OBJS) $(TARGETS)

test: simulator
	./simulator

simulator: $(OBJS) simulator.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<
