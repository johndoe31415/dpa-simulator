.PHONY: all clean test

CFLAGS := $(CFLAGS) -std=c11
CFLAGS += -Wall -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Werror=format -Wimplicit-fallthrough -Wshadow
CFLAGS += -Os -g3

TARGETS := aes128_test
OBJS := aes128.o

all: $(TARGETS)

clean:
	rm -f $(OBJS) $(TARGETS)

test: aes128_test
	./aes128_test

aes128_test: $(OBJS) aes128_test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<
