#include "App.h"
#include "Constants.h"
#include "ErrorSignal.h"

#include "Enclave_u.h"
#include "sgx_urts.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

sgx_enclave_id_t global_eid = 0;

int initialize_enclave()
{
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		return -1;
	}
	return 0;
}

int destroy_enclave()
{
	sgx_destroy_enclave(global_eid);
	return 0;
}

int SGX_CDECL main(int argc, char *argv[])
{
	if (initialize_enclave() < 0) {
		printf("Enter a character before exit ...\n");
		getchar();
		return -1;
	}
	printf("Enclave started.\n");

	printf("Sealing encryption key... ");
	size_t sealLen;
	ecall_get_seal_size(global_eid, SGX_AESCTR_KEY_SIZE, &sealLen);
	uint8_t * key = (uint8_t *)malloc(sealLen);
	ecall_gen_key(global_eid, key, sealLen);
	printf("done.\n");

	printf("Generating initialisation vector (AES coutner)... ");
	uint8_t iv[SGX_AESCTR_CTR_SIZE];
	uint8_t iv_copy[SGX_AESCTR_CTR_SIZE];
	ecall_gen_ctr(global_eid, iv, SGX_AESCTR_CTR_SIZE);
	memcpy(iv_copy, iv, SGX_AESCTR_CTR_SIZE);
	printf("done.\n");

	printf("Encrypting... ");
	ecall_encrypt(global_eid, key, sealLen, FILE_RAW_PATH, iv, SGX_AESCTR_CTR_SIZE);
	printf("done.\n");

	printf("Decrypting...\n");
	ecall_decrypt(global_eid, key, sealLen, FILE_ENC_PATH, iv_copy, SGX_AESCTR_CTR_SIZE);
	printf("done.\n");

	destroy_enclave();
	printf("Enclave stopped.\n");

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
