#ifndef __AES128_H__
#define __AES128_H__

#include <stdint.h>

#define AES_ROUNDS		11

struct aes128_ctx_t {
	uint8_t round_key[AES_ROUNDS][16];
};

/*************** AUTO GENERATED SECTION FOLLOWS ***************/
void aes128_encrypt_block(struct aes128_ctx_t *ctx, const uint8_t plaintext[static 16], uint8_t ciphertext[static 16]);
void aes128_dump(const struct aes128_ctx_t *ctx);
void aes128_init(struct aes128_ctx_t *ctx, const uint8_t key[static 16]);
/***************  AUTO GENERATED SECTION ENDS   ***************/

#endif
