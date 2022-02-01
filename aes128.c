/**
 *	dpa-simulator - Create simulated traces for demonstrating basic DPA/CPA.
 *	Copyright (C) 2022-2022 Johannes Bauer
 *
 *	This file is part of dpa-simulator.
 *
 *	dpa-simulator is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; this program is ONLY licensed under
 *	version 3 of the License, later versions are explicitly excluded.
 *
 *	dpa-simulator is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with dpa-simulator; if not, write to the Free Software
 *	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *	Johannes Bauer <JohannesBauer@gmx.de>
**/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "aes128.h"

static const uint8_t sbox[256] = {
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
};

static const uint8_t Rcon[AES_ROUNDS] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void aes_xor_bytes(void *vdest, const void *vsrc, unsigned int length) {
	/* length must be an even multiple of 4 */
	uint32_t *dest = (uint32_t*)vdest;
	const uint32_t *src = (const uint32_t*)vsrc;
	for (int i = 0; i < length / 4; i++) {
		dest[i] ^= src[i];
	}
}

#ifdef DEBUG
static void aes_dump_data(const void *data, unsigned int len, char *name) {
	if (name) {
		printf("%s = ", name);
	}
	for (unsigned int i = 0; i < len; i++) {
		printf("%02x ", ((const uint8_t*)data)[i]);
	}
	if (name) {
		printf("\n");
	}
}
#endif

static void aes_sub_bytes(uint8_t block[static 16]) {
	for (unsigned int i = 0; i < 16; i++) {
		block[i] = sbox[block[i]];
	}
}

static void aes_shift_rows(uint8_t block[static 16]) {
	uint8_t tmp;

	tmp = block[1];
	block[1] = block[5];
	block[5] = block[9];
	block[9] = block[13];
	block[13] = tmp;

	tmp = block[2];
	block[2] = block[10];
	block[10] = tmp;

	tmp = block[3];
	block[3] = block[15];
	block[15] = block[11];
	block[11] = block[7];
	block[7] = tmp;

	tmp = block[6];
	block[6] = block[14];
	block[14] = tmp;
}

static uint8_t gf2_8_mul2(uint8_t element) {
	bool msb = element & 0x80;
	element <<= 1;
	if (msb) {
		element ^= 0x1b;
	}
	return element;
}

/* Input: Coefficients b3, b2, b1, b0 of b(x) b3 x^3 + b2 x^2 + b1 x + b0 */
/* Output: b(x) * 3x^3 + x^2 + x + 2 mod x^4 + 1
 * Result is 3*b3*x^6 + (3*b2 + b3)*x^5 + (3*b1 + b2 + b3)*x^4 + (3*b0 + b1 + b2 + 2*b3)*x^3 + (b0 + b1 + 2*b2)*x^2 + (b0 + 2*b1)*x + 2*b0
 * but modular reduction yields x^j == x^(j mod 4), therefore
 * (3*b0 + b1 + b2 + 2*b3)*x^3 + (b0 + b1 + 2*b2 + 3*b3)*x^2 + (b0 + 2*b1 + 3*b2 + b3)*x + 2*b0 + 3*b1 + b2 + b3
 */
static void aes_mix_column(uint8_t elements[static 4]) {
	/* Rename elements to be in sync with equations */
	const uint8_t b3 = elements[3];
	const uint8_t b2 = elements[2];
	const uint8_t b1 = elements[1];
	const uint8_t b0 = elements[0];

	/* Multiply coefficients with 2 in GF(2^8) */
	const uint8_t b3x2 = gf2_8_mul2(b3);
	const uint8_t b2x2 = gf2_8_mul2(b2);
	const uint8_t b1x2 = gf2_8_mul2(b1);
	const uint8_t b0x2 = gf2_8_mul2(b0);

	elements[3] = b0 ^ b0x2 ^ b1 ^ b2 ^ b3x2;
	elements[2] = b0 ^ b1 ^ b2x2 ^ b3 ^ b3x2;
	elements[1] = b0 ^ b1x2 ^ b2x2 ^ b2 ^ b3;
	elements[0] = b0x2 ^ b1x2 ^ b1 ^ b2 ^ b3;
}

static void aes_mix_columns(uint8_t block[static 16]) {
	for (int col = 0; col < 4; col++) {
		aes_mix_column(block + 4 * col);
	}
}

void aes128_encrypt_block(struct aes128_ctx_t *ctx, const uint8_t plaintext[static 16], uint8_t ciphertext[static 16]) {
	memcpy(ciphertext, plaintext, 16);
	for (unsigned int rnd = 0; rnd < AES_ROUNDS - 1; rnd++) {
		/* Add round key */
		aes_xor_bytes(ciphertext, &ctx->round_key[rnd], 16);

		aes_sub_bytes(ciphertext);
		aes_shift_rows(ciphertext);
		if (rnd != AES_ROUNDS - 2) {
			aes_mix_columns(ciphertext);
		}
	}
	aes_xor_bytes(ciphertext, &ctx->round_key[AES_ROUNDS - 1], 16);
}

static void aes_rot_word(uint8_t word[static 4]) {
	uint8_t tmp = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = tmp;
}

static void aes_sub_word(uint8_t word[static 4]) {
	for (unsigned int i = 0; i < 4; i++) {
		word[i] = sbox[word[i]];
	}
}

static void aes128_key_schedule(struct aes128_ctx_t *ctx, const uint8_t key[static 16]) {
	/* First round key is just the AES key */
	memcpy(ctx->round_key[0], key, 16);

	uint8_t prev_word[4];
	memcpy(prev_word, &ctx->round_key[0][12], 4);

	for (int rnd = 1; rnd < AES_ROUNDS; rnd++) {
		/* Copy previous round key */
		memcpy(&ctx->round_key[rnd], &ctx->round_key[rnd - 1], 16);

		/* Then mangle and XOR round key word-wise */
		for (int subround = 0; subround < 4; subround++) {
			uint8_t *word = &ctx->round_key[rnd][4 * subround];

			if (subround == 0) {
				aes_rot_word(prev_word);
				aes_sub_word(prev_word);
				prev_word[0] ^= Rcon[rnd];
			}

			aes_xor_bytes(word, prev_word, 4);
			memcpy(prev_word, word, 4);
		}
	}
}

#ifdef DEBUG
void aes128_dump(const struct aes128_ctx_t *ctx) {
	for (unsigned int rnd = 0; rnd < AES_ROUNDS; rnd++) {
		printf("Round %2d: ", rnd);
		aes_dump_data(&ctx->round_key[rnd], 16, NULL);
		printf("\n");
	}
}
#endif

void aes128_init(struct aes128_ctx_t *ctx, const uint8_t key[static 16]) {
	aes128_key_schedule(ctx, key);
}
