#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <thumb2sim/thumb2sim.h>
#include "argparse.h"

static struct pgmopts_t {
	const char *output_directory;
	const char *firmware_filename;
	unsigned int trace_count;
	uint8_t key[64];
} pgmopts = {
	.firmware_filename = ARGPARSE_DEFAULT_FIRMWARE,
	.trace_count = ARGPARSE_DEFAULT_TRACECNT,
};

#define MAX_TRACE_LENGTH		(32 * 1024)
#define RAM_SIZE_KB				128

struct user_ctx_t {
	bool end_emulation;
	int readstate;
	uint8_t key[16];
	uint8_t plaintext[16];
	uint8_t ciphertext[16];
	unsigned int trace_length;
	uint8_t trace[MAX_TRACE_LENGTH];
	struct cm3_cpu_state_t prev_regs;
	uint8_t prev_ram[RAM_SIZE_KB * 1024];
};

#define READSTATE_READ_KEY			1
#define READSTATE_READ_PLAINTEXT	2
#define READSTATE_WRITE_KEY			3
#define READSTATE_WRITE_PLAINTEXT	4
#define READSTATE_WRITE_CIPHERTEXT	5

#define BREAKPOINT_START_AES		1
#define BREAKPOINT_END_AES			2

static unsigned int hweight(uint32_t x) {
	unsigned int weight = 0;
	while (x) {
		if (x & 1) {
			weight++;
		}
		x >>= 1;
	}
	return weight;
}

static void post_step_callback(struct emu_ctx_t *emu_ctx) {
	struct user_ctx_t *usr = (struct user_ctx_t*)emu_ctx->user;


	unsigned int bits_flipped_regs = 0;
	for (int i = 0; i < 16; i++) {
		int w = hweight(emu_ctx->cpu.reg[i] ^ usr->prev_regs.reg[i]);
		bits_flipped_regs += w;
	}

	const uint32_t *prev_ram = (uint32_t*)usr->prev_ram;
	const uint32_t *now_ram = (uint32_t*)emu_ctx->addr_space.slices[1].data;
	for (int i = 0; i < RAM_SIZE_KB * 1024 / 4; i++) {
		int w = hweight(prev_ram[i] ^ now_ram[i]);
		bits_flipped_regs += w;
	}
	memcpy(&usr->prev_regs, &emu_ctx->cpu, sizeof(struct cm3_cpu_state_t));
	memcpy(usr->prev_ram, now_ram, RAM_SIZE_KB * 1024);

	if (bits_flipped_regs > 255) {
		fprintf(stderr, "Register hamming weight clipped from %d\n", bits_flipped_regs);
		bits_flipped_regs = 255;
	}

	if (usr->trace_length < MAX_TRACE_LENGTH) {
		usr->trace[usr->trace_length] = bits_flipped_regs;
		usr->trace_length++;
	} else {
		fprintf(stderr, "Trace truncated!\n");
	}
}

static void bkpt_callback(struct emu_ctx_t *emu_ctx, uint8_t bkpt_number) {
	struct user_ctx_t *usr = (struct user_ctx_t*)emu_ctx->user;
	if (bkpt_number == BREAKPOINT_START_AES) {
		emu_ctx->post_step_callback = post_step_callback;
		memcpy(&usr->prev_regs, &emu_ctx->cpu, sizeof(struct cm3_cpu_state_t));
		memcpy(usr->prev_ram, emu_ctx->addr_space.slices[1].data, RAM_SIZE_KB * 1024);
	} else if (bkpt_number == BREAKPOINT_END_AES) {
		emu_ctx->post_step_callback = NULL;
	} else if (bkpt_number != 255) {
		fprintf(stderr, "Unexpected breakpoint %d.\n", bkpt_number);
	}
}

static uint32_t syscall_read(struct emu_ctx_t *emu_ctx, void *data, uint32_t max_length) {
	struct user_ctx_t *usr = (struct user_ctx_t*)emu_ctx->user;
	usr->readstate++;

	if (usr->readstate == READSTATE_READ_KEY) {
		uint8_t *key = (uint8_t*)data;
		memcpy(key, usr->key, 16);
	} else if (usr->readstate == READSTATE_READ_PLAINTEXT) {
		uint8_t *plaintext = (uint8_t*)data;
		memcpy(plaintext, usr->plaintext, 16);
	} else {
		fprintf(stderr, "Unexpected read %d\n", usr->readstate);
	}
	return max_length;
}

static bool end_emulation_callback(struct emu_ctx_t *emu_ctx) {
	struct user_ctx_t *usr = (struct user_ctx_t*)emu_ctx->user;
	return usr->end_emulation;
}

static void syscall_write(struct emu_ctx_t *emu_ctx, const void *data, uint32_t length) {
	struct user_ctx_t *usr = (struct user_ctx_t*)emu_ctx->user;
	usr->readstate++;
	if (usr->readstate == READSTATE_WRITE_CIPHERTEXT) {
		uint8_t *ciphertext = (uint8_t*)data;
		memcpy(usr->ciphertext, ciphertext, 16);
	}
}

static void syscall_exit(struct emu_ctx_t *emu_ctx, uint32_t status) {
	struct user_ctx_t *usr = (struct user_ctx_t*)emu_ctx->user;
	usr->end_emulation = true;
}

static bool parse_hex(uint8_t *dest, const char *src, unsigned int max_length, argparse_errmsg_callback_t errmsg_callback) {
	int sl = strlen(src);
	if ((sl % 2) != 0) {
		errmsg_callback("Could not parse \"%s\" as a hex string: length not divisible by 2.", src);
		return false;
	}

	if ((sl / 2) > max_length) {
		errmsg_callback("Could not parse \"%s\" as a hex string: too long, can only handle up to %d bytes.", src, max_length);
		return false;
	}

	for (int i = 0; i < sl; i += 2) {
		char digit[3];
		digit[0] = src[i + 0];
		digit[1] = src[i + 1];
		digit[2] = 0;

		char *end;
		uint8_t value = strtoul(digit, &end, 16);
		if (*end != 0) {
			errmsg_callback("Could not parse \"%s\" as a hex string: digit at offset %d invalid.", src, i);
			return false;
		}

		dest[i / 2] = value;
	}

	return true;
}

static bool argument_callback(enum argparse_option_t option, const char *value, argparse_errmsg_callback_t errmsg_callback) {
	switch (option) {
		case ARG_FIRMWARE:
			pgmopts.firmware_filename = value;
			break;

		case ARG_TRACECNT:
			pgmopts.trace_count = atoi(value);
			break;

		case ARG_OUTPUT_DIRECTORY:
			pgmopts.output_directory = value;
			break;

		case ARG_KEY:
			if (!parse_hex(pgmopts.key, value, sizeof(pgmopts.key), errmsg_callback)) {
				return false;
			}
			break;
	}
	return true;
}

static bool plausibilization_callback(argparse_errmsg_option_callback_t errmsg_callback) {
	return true;
}

int main(int argc, char **argv) {
	argparse_parse_or_quit(argc, argv, argument_callback, plausibilization_callback);



	const char *rom_image_filename = "aes128_rom.bin";
	const struct hardware_params_t cpu_parameters = {
		.rom_size_bytes = 1024 * 1024,
		.ram_size_bytes = RAM_SIZE_KB * 1024,
		.ivt_base_address = 0x08000000,
		.rom_base_address = 0x08000000,
		.ram_base_address = 0x20000000,
		.rom_image_filename = rom_image_filename,
		.ram_image_filename = NULL,
	};

	struct emu_ctx_t *emu_ctx = init_cortexm(&cpu_parameters);
	emu_ctx->bkpt_callback = bkpt_callback;
	emu_ctx->end_emulation_callback = end_emulation_callback;
	emu_ctx->emulator_syscall_read = syscall_read;
	emu_ctx->emulator_syscall_write = syscall_write;
	emu_ctx->emulator_syscall_exit = syscall_exit;

	FILE *f = fopen("/dev/urandom", "r");
	if (!f) {
		perror("/dev/urandom");
		exit(1);
	}

	for (unsigned int trace_no = 0; trace_no < pgmopts.trace_count; trace_no++) {
		struct user_ctx_t user = {
			.end_emulation = false,
			.readstate = 0,
		};
		memcpy(user.key, pgmopts.key, 16);
		emu_ctx->user = &user;
		if (fread(user.plaintext, 16, 1, f) != 1) {
			perror("fread");
			exit(1);
		}

		cpu_reset(emu_ctx);
		cpu_run(emu_ctx);

		mkdir(pgmopts.output_directory, 0755);

		/* Yes, this sprintf/strlen cascade is neither efficient nor secure
		 * (buffer overflow). Send a PR if you care. */
		char output_filename[256];
		output_filename[0] = 0;
		sprintf(output_filename + strlen(output_filename), "%s/trace_P_", pgmopts.output_directory);
		for (int i = 0; i < 16; i++) {
			sprintf(output_filename + strlen(output_filename), "%02x", user.plaintext[i]);
		}
		sprintf(output_filename + strlen(output_filename), "_C_");
		for (int i = 0; i < 16; i++) {
			sprintf(output_filename + strlen(output_filename), "%02x", user.ciphertext[i]);
		}
		sprintf(output_filename + strlen(output_filename), ".bin");
		printf("%s\n", output_filename);

		FILE *j = fopen(output_filename, "w");
		if (!j) {
			perror(output_filename);
			exit(1);
		}
		if (fwrite(user.trace, user.trace_length, 1, j) != 1) {
			perror("fwrite");
			exit(1);
		}
		fclose(j);
	}

	return 0;
}
