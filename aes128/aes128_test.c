#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes128.h"

struct testcase_t {
	const char *key, *plaintext, *ciphertext;
};

static void parse_block(const char *hexdata, uint8_t block[static 16]) {
	if (strlen(hexdata) != 32) {
		abort();
	}
	for (int i = 0; i < 16; i++) {
		char hex[3];
		hex[0] = hexdata[(2 * i) + 0];
		hex[1] = hexdata[(2 * i) + 1];
		hex[2] = 0;
		block[i] = strtol(hex, NULL, 16);
	}
}

static void dump_block(const uint8_t block[static 16]) {
	for (unsigned int i = 0; i < 16; i++) {
		printf("%02x", block[i]);
	}
}

int main(int argc, char **argv) {
	struct testcase_t testcases[] = {
//		{ .key = "2b7e151628aed2a6abf7158809cf4f3c", .plaintext = "6bc0bce12a459991e134741a7f9e1925", .ciphertext = "00000000000000000000000000000000" },
		{ .key = "00000000000000000000000000000000", .plaintext = "00000000000000000000000000000000", .ciphertext = "66e94bd4ef8a2c3b884cfa59ca342b2e" },
		{ .key = "2136d17d62680a95b5f3facd615a76e1", .plaintext = "7507b47404e07900ad676892ccdd1a14", .ciphertext = "ee3926758f9ff0d0d6393fc64dc886cd" },
		{ .key = "61061a275f47f2319dbc6cd9231e8cd7", .plaintext = "971c7d762a4c7459fda3b96fa3aba29c", .ciphertext = "f287371107989ba0775af501035399df" },
		{ .key = "4a851208a2c83b4977b9fe3919c2dd42", .plaintext = "e232b27cc7dd974eb2e9345b6de0a24e", .ciphertext = "d9c2199256cbece5bed22b6aa1b35723" },
		{ .key = "f2b617fadcdf6aa8b9eb4d81dc5885ee", .plaintext = "b6626494867364f69eceb088a787011e", .ciphertext = "34d43c4542e783fb59a1ddedd3dadf24" },
		{ .key = "c7473962276bc8bb2369107f2ce40562", .plaintext = "c70c6c840c1ae3d7c6ce2630f55c12ec", .ciphertext = "6d595ae8749dfa414fdf092a17eb1ec0" },
		{ .key = "232567890b6ad9b2db7ce8769ef805f9", .plaintext = "764cb04c0b041fdf3e79f34a99433634", .ciphertext = "cad92f81683a7f537137890c2ac305ad" },
		{ .key = "2573dc25ccf112da3a0ab1d023d06309", .plaintext = "623b2db2dcd1ad3640c90da0dd3f11f9", .ciphertext = "6e9af4e63d5148aa0ad6feb752afa476" },
		{ .key = "d1d12e13886d83286b48bc24c53dd97f", .plaintext = "04c64748fae9063246efb8595e2f2538", .ciphertext = "74183c5a79b50a147ca35de08177f424" },
		{ .key = "4da123e8df0f7579ca76085aa8b6c0fd", .plaintext = "79dac2f7948584f2cae26b08cf8591f0", .ciphertext = "a95ef49b489bc2d371b1dadfbf9ac583" },
		{ .key = "9db84751bdf1167220efb71ac7313b1c", .plaintext = "e6b0d9163e82acb800f772aeb2499871", .ciphertext = "423780067115d0083e997778fd241c13" },
		{ .key = "99624dc30b1e95682f6a4a12679225e5", .plaintext = "fa79fa89c03a6dbde0d66844628a815b", .ciphertext = "eca50648e64c6edc5949609e0a636597" },
		{ .key = "ccab54a365acc86cac8ed66357a88c91", .plaintext = "eb466d5116dcf0f67e1fffd9916e4175", .ciphertext = "2d72ee83a03d7ed94b70f5a86d2fc73a" },
		{ .key = "e74894079981a54be5ab4f8aeb8f6398", .plaintext = "253993e78b770eb8796215cb37dfb8aa", .ciphertext = "3b2c86ca481d0136c106e3242329c34a" },
		{ .key = "2d3c11f1a7565814d6cc26010cd33d10", .plaintext = "ae52c12ca03ec7de0e7d104fc68ae5e8", .ciphertext = "36dc92a5e836444d881b40588f8c1bf1" },
		{ .key = "5ba37df472be72403ed81f7b161a6bd7", .plaintext = "f31fe752ac55b197f328438bb916590c", .ciphertext = "eac06e961ed74ad93f581f686ba8bd73" },
		{ .key = "cf4e28ad42e3f667fd67aa89d47d7825", .plaintext = "01873bce493332491d1ba9fc791e0787", .ciphertext = "a76569639e7455d8ef234ecdae575228" },
	};

	for (unsigned int i = 0; i < sizeof(testcases) / sizeof(testcases[0]); i++) {
		uint8_t key[16];
		uint8_t plaintext[16];
		uint8_t expected_ciphertext[16];
		uint8_t ciphertext[16];

		parse_block(testcases[i].key, key);
		parse_block(testcases[i].plaintext, plaintext);
		parse_block(testcases[i].ciphertext, expected_ciphertext);

		struct aes128_ctx_t aes;
		aes128_init(&aes, key);
		//aes128_dump(&aes);
		aes128_encrypt_block(&aes, plaintext, ciphertext);

		printf("TC %d: K = ", i);
		dump_block(key);
		printf(" P = ");
		dump_block(plaintext);
		printf(" C = ");
		dump_block(expected_ciphertext);
		if (!memcmp(expected_ciphertext, ciphertext, 16)) {
			printf(" PASS");
		} else {
			printf(" but computed C = ");
			dump_block(ciphertext);
			printf(" FAIL");
		}
		printf("\n");
	}

	return 0;
}
