#include "EnclaveDecrypt.h"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "Constants.h"

#include <memory>

void ecall_decrypt_aes_ctr(uint8_t * unsealedKey, uint8_t *  counterIv,
						   uint8_t * cryptMessage, size_t crypt_len,
						   char * plainMessage, size_t plain_len)
{
	uint8_t p_dst[BUFLEN] = { 0 };
	sgx_aes_ctr_decrypt(
		(sgx_aes_ctr_128bit_key_t *)unsealedKey,	// p_key			128-bit key
		cryptMessage,								// p_src			input data stream
		crypt_len,									// src_len			length of p_src
		counterIv,									// p_ctr			init vector (counter)
		COUNTER_BLOCK_INC,							// ctr_inc_bits		bits to increment in counter
		p_dst										// p_dst			output data stream
	);
	memcpy(plainMessage, p_dst, plain_len);
}
