.PHONY: all 

CC := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
CFLAGS := -O3 -std=c11 -I.. -I/usr/local/include -Wall -Wmissing-prototypes -Wstrict-prototypes -Werror=implicit-function-declaration -Wshadow
CFLAGS += -g -D_XOPEN_SOURCE=500

LDFLAGS := -Tstm32f407.ld

OBJS := ivt.o emu_syscall.o boilerplate.o ../aes128.o
TARGETS := aes128_rom.bin

all: $(TARGETS)

clean:
	rm -f $(OBJS) $(TARGETS)
	rm -f aes128_rom

aes128_rom: $(OBJS) aes128_rom.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

aes128_rom.bin: aes128_rom
	$(OBJCOPY) -O binary $< $@

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

.s.o:
	$(CC) $(CFLAGS) -c -o $@ $<
