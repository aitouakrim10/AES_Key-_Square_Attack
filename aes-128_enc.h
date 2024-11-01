#include <stdint.h>
#include "utiles.h"
#define AES_BLOCK_SIZE 16
#define AES_128_KEY_SIZE 16

#ifndef __AES_128_ENC__H__
#define __AES_128_ENC__H__

extern int SWITCH;
/*
 * Encrypt @block with @key over @nrounds. If @lastfull is true, the last round includes MixColumn, otherwise it doesn't.
 * @nrounds <= 10
 */
void aes128_enc(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_128_KEY_SIZE], unsigned nrounds, int lastfull);

/*
 * Compute the @round-th round key in @prev_key, given the @(round + 1)-th key in @next_key 
 * @round in {0...9}
 * The ``master decryption key'' is the 10-th round key (for a full AES-128)
 */
void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round);
void next_aes128_round_key(const uint8_t prev_key[16], uint8_t next_key[16], int round);



#endif // __AES-128_ENC__H__
