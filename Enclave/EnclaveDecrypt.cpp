#include "EnclaveDecrypt.h"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

#include "Constants.h"

#include <memory>

void ecall_decrypt_aes_ctr(uint8_t * unsealed_key, uint8_t * counter_iv,
						   uint8_t * crypt_message, size_t crypt_len,
						   char * plain_message, size_t plain_len)
{
	sgx_aes_ctr_decrypt(
		(sgx_aes_ctr_128bit_key_t *)unsealed_key,	// p_key			128-bit key
		crypt_message,								// p_src			input data stream
		crypt_len,									// src_len			length of p_src
		counter_iv,									// p_ctr			init vector (counter)
		COUNTER_BLOCK_INC,							// ctr_inc_bits		bits to increment in counter
		(uint8_t *)plain_message					// p_dst			output data stream
	);
}
