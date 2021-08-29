#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "EnclaveDecrypt.h"
#include "Constants.h"

#include <assert.h>
#include <memory>
#include <stdlib.h>


static uint8_t unsealedKey[SGX_AESCTR_KEY_SIZE] = { 0 };
static uint8_t counterIv[COUNTER_BLOCK_SIZE] = { 0 };

void ecall_get_seal_size(size_t orig, size_t * seal)
{
	*seal = sgx_calc_sealed_data_size(0, orig);
}

void ecall_gen_key(uint8_t * key, size_t seal_len)
{
	assert(SGX_AESCTR_KEY_SIZE + sizeof(sgx_sealed_data_t) == seal_len);
	uint8_t p_key[SGX_AESCTR_KEY_SIZE];
	sgx_read_rand(p_key, SGX_AESCTR_KEY_SIZE);
	auto seal_status = sgx_seal_data(0, NULL, SGX_AESCTR_KEY_SIZE, p_key, seal_len, (sgx_sealed_data_t *)key);
	assert(seal_status == SGX_SUCCESS);
}

void ecall_gen_ctr(uint8_t * ctr, size_t len)
{
	assert(COUNTER_BLOCK_SIZE == len);
	uint8_t p_ctr[COUNTER_BLOCK_SIZE];
	sgx_read_rand(p_ctr, len);
	memcpy(ctr, p_ctr, len);
}

void ecall_encrypt(uint8_t * seal_key, size_t seal_len,
				   const char * path,
				   uint8_t * ctr, size_t ctr_len)
{
	assert(SGX_AESCTR_KEY_SIZE + sizeof(sgx_sealed_data_t) == seal_len);
	assert(COUNTER_BLOCK_SIZE == ctr_len);

	uint32_t keyLen = SGX_AESCTR_KEY_SIZE;
	auto seal_status = sgx_unseal_data((sgx_sealed_data_t *)seal_key, NULL, NULL, unsealedKey, &keyLen);
	assert(seal_status == SGX_SUCCESS);

	memcpy(counterIv, ctr, COUNTER_BLOCK_SIZE);

	ocall_encrypt_file(path);

	memset(unsealedKey, 0, SGX_AESCTR_KEY_SIZE);
	memset(counterIv, 0, COUNTER_BLOCK_SIZE);
}

void ecall_encrypt_aes_ctr(char * plainMessage, size_t plain_len,
						   uint8_t * cryptMessage, size_t crypt_len)
{
	uint8_t p_dst[BUFLEN];
	sgx_aes_ctr_encrypt(
		(sgx_aes_ctr_128bit_key_t *)unsealedKey,	// p_key			128-bit key
		(uint8_t *)plainMessage,					// p_src			input data stream
		plain_len,									// src_len			length of p_src
		counterIv,									// p_ctr			init vector (counter)
		COUNTER_BLOCK_INC,							// ctr_inc_bits		bits to increment in counter
		p_dst										// p_dst			output data stream
	);
	memcpy(cryptMessage, p_dst, crypt_len);
}
