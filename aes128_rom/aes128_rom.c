/*
	libthumb2sim - Emulator for the Thumb-2 ISA (Cortex-M)
	Copyright (C) 2019-2019 Johannes Bauer

	This file is part of libthumb2sim.

	libthumb2sim is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	libthumb2sim is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with libthumb2sim; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/

#include <stdbool.h>
#include <thumb2sim/thumb2simguest.h>
#include "aes128.h"

int main(void) {
	uint8_t key[16] = { 0 };
	uint8_t plaintext[16] = { 0 };
	uint8_t ciphertext[16];

	thumb2sim_read(key, 16);
	thumb2sim_read(plaintext, 16);

	__asm__ __volatile__("bkpt #1");
	struct aes128_ctx_t aes;
	aes128_init(&aes, key);
	aes128_encrypt_block(&aes, plaintext, ciphertext);
	__asm__ __volatile__("bkpt #2");

	thumb2sim_write(key, 16);
	thumb2sim_write(plaintext, 16);
	thumb2sim_write(ciphertext, 16);

	thumb2sim_exit(0);
	return 0;
}
