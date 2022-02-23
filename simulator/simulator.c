#include <stdio.h>
#include <string.h>
#include <thumb2sim/thumb2sim.h>

struct user_ctx_t {
	bool end_emulation;
	int readstate;
	uint8_t key[16];
	uint8_t plaintext[16];
	uint8_t ciphertext[16];
	struct cm3_cpu_state_t prev_regs;
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
	for (int i = 0; i < 32; i++) {
		int w = hweight(emu_ctx->cpu.reg[i] ^ usr->prev_regs.reg[i]);
		printf("X %d\n", w);
		bits_flipped_regs += w;
	}
	memcpy(&usr->prev_regs, &emu_ctx->cpu, sizeof(struct cm3_cpu_state_t));
	printf("%d\n", bits_flipped_regs);
}

static void bkpt_callback(struct emu_ctx_t *emu_ctx, uint8_t bkpt_number) {
	struct user_ctx_t *usr = (struct user_ctx_t*)emu_ctx->user;
	if (bkpt_number == BREAKPOINT_START_AES) {
		emu_ctx->post_step_callback = post_step_callback;
		memcpy(&usr->prev_regs, &emu_ctx->cpu, sizeof(struct cm3_cpu_state_t));
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

int main(int argc, char **argv) {
	const char *rom_image_filename = "aes128_rom.bin";
	const struct hardware_params_t cpu_parameters = {
		.rom_size_bytes = 1024 * 1024,
		.ram_size_bytes = 128 * 1024,
		.ivt_base_address = 0x08000000,
		.rom_base_address = 0x08000000,
		.ram_base_address = 0x20000000,
		.rom_image_filename = rom_image_filename,
		.ram_image_filename = NULL,
	};

	struct user_ctx_t user = {
		.end_emulation = false,
		.readstate = 0,
	};
	struct emu_ctx_t *emu_ctx = init_cortexm(&cpu_parameters);
	emu_ctx->bkpt_callback = bkpt_callback;
	emu_ctx->end_emulation_callback = end_emulation_callback;
	emu_ctx->emulator_syscall_read = syscall_read;
	emu_ctx->emulator_syscall_write = syscall_write;
	emu_ctx->emulator_syscall_exit = syscall_exit;
	emu_ctx->user = &user;

	cpu_run(emu_ctx);



	return 0;
}
