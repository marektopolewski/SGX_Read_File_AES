#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define BUFLEN 2048
#define COUNTER_BLOCK_SIZE 16
#define COUNTER_BLOCK_INC 8


void ecall_get_seal_size(size_t orig, size_t * seal)
{
	*seal = sgx_calc_sealed_data_size(0, orig);
}

void ecall_gen_key(uint8_t * key, size_t sealLen)
{
	assert(SGX_AESCTR_KEY_SIZE + sizeof(sgx_sealed_data_t) == sealLen);
	uint8_t p_key[SGX_AESCTR_KEY_SIZE];
	sgx_read_rand(p_key, SGX_AESCTR_KEY_SIZE);
	auto seal_status = sgx_seal_data(0, NULL, SGX_AESCTR_KEY_SIZE, p_key, sealLen, (sgx_sealed_data_t *)key);
	assert(seal_status == SGX_SUCCESS);
}

void ecall_gen_ctr(uint8_t * ctr, size_t len)
{
	assert(COUNTER_BLOCK_SIZE == len);
	uint8_t p_ctr[COUNTER_BLOCK_SIZE];
	sgx_read_rand(p_ctr, len);
	memcpy(ctr, p_ctr, len);
}

void ecall_encrypt(uint8_t * sealKey, size_t sealLen,
				   const char * path,
				   uint8_t * ctr, size_t ctrLen)
{
	assert(SGX_AESCTR_KEY_SIZE + sizeof(sgx_sealed_data_t) == sealLen);
	assert(COUNTER_BLOCK_SIZE == ctrLen);
	ocall_encrypt_file(sealKey, sealLen, path, ctr, ctrLen);
}

void ecall_decrypt(uint8_t * sealKey, size_t sealLen,
		           const char * path,
				   uint8_t * ctr, size_t ctrLen)
{
	assert(SGX_AESCTR_KEY_SIZE + sizeof(sgx_sealed_data_t) == sealLen);
	assert(COUNTER_BLOCK_SIZE == ctrLen);
	ocall_decrypt_file(sealKey, sealLen, path, ctr, ctrLen);
}

void ecall_encrypt_aes_ctr(uint8_t * sealKey, size_t sealLen,
	char * plainMessage, size_t lenPlain,
	uint8_t * counterBlock, size_t lenCounter,
	uint8_t * cryptMessage, size_t lenCrypt)
{
	// Unseal key
	uint32_t keyLen = SGX_AESCTR_KEY_SIZE;
	uint8_t key[SGX_AESCTR_KEY_SIZE];
	auto seal_status = sgx_unseal_data((sgx_sealed_data_t *)sealKey, NULL, NULL, key, &keyLen);
	assert(seal_status == SGX_SUCCESS);

	// Encrypt
	uint8_t p_dst[BUFLEN];
	sgx_aes_ctr_encrypt(
		(sgx_aes_ctr_128bit_key_t *)key,	// p_key			128-bit key
		(uint8_t *)plainMessage,			// p_src			input data stream
		lenPlain,							// src_len			length of p_src
		counterBlock,						// p_ctr			init vector (counter)
		COUNTER_BLOCK_INC,					// ctr_inc_bits		bits to increment in counter
		p_dst								// p_dst			output data stream
	);
	memcpy(cryptMessage, p_dst, lenCrypt);
}

void ecall_decrypt_aes_ctr(uint8_t * sealKey, size_t sealLen,
	uint8_t * cryptMessage, size_t lenCrypt,
	uint8_t * counterBlock, size_t lenCounter,
	char * plainMessage, size_t lenPlain)
{
	// Unseal key
	uint32_t keyLen = SGX_AESCTR_KEY_SIZE;
	uint8_t key[SGX_AESCTR_KEY_SIZE];
	auto seal_status = sgx_unseal_data((sgx_sealed_data_t *)sealKey, NULL, NULL, key, &keyLen);
	assert(seal_status == SGX_SUCCESS);

	// Decrypt
	uint8_t p_dst[BUFLEN] = { 0 };
	sgx_aes_ctr_decrypt(
		(sgx_aes_ctr_128bit_key_t *)key,	// p_key			128-bit key
		cryptMessage,						// p_src			input data stream
		lenCrypt,							// src_len			length of p_src
		counterBlock,						// p_ctr			init vector (counter)
		COUNTER_BLOCK_INC,					// ctr_inc_bits		bits to increment in counter
		p_dst								// p_dst			output data stream
	);
	memcpy(plainMessage, p_dst, lenPlain);
}

