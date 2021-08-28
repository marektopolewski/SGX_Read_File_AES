#include "App.h"
#include "Constants.h"
#include "ErrorSignal.h"
#include "Server.h"

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_uswitchless.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <exception>

sgx_enclave_id_t global_eid = 0;

int initialize_enclave()
{
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
	us_config.num_uworkers = 2;
	us_config.num_tworkers = 2;
	const void* enclave_ex_p[32] = { 0 };
	enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void *)&us_config;

	ret = sgx_create_enclave_ex(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
		&global_eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
	// ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
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

Results test(Parameters params) 
{
	if (initialize_enclave() < 0) {
		printf("Enter a character before exit ...\n");
		getchar();
		throw std::exception("Could not init enclave");
	}
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	printf("Enclave started.\n");

	printf("Sealing encryption key...");
	size_t sealLen;
	ret = ecall_get_seal_size(global_eid, SGX_AESCTR_KEY_SIZE, &sealLen);
	uint8_t * key = (uint8_t *)malloc(sealLen);
	ecall_gen_key(global_eid, key, sealLen);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		getchar();
		throw std::exception("Could not seal AES key");
	}
	printf("done.\n");

	printf("Generating initialisation vector (AES coutner)... ");
	uint8_t iv[SGX_AESCTR_CTR_SIZE];
	uint8_t iv_copy[SGX_AESCTR_CTR_SIZE];
	ret = ecall_gen_ctr(global_eid, iv, SGX_AESCTR_CTR_SIZE);
	memcpy(iv_copy, iv, SGX_AESCTR_CTR_SIZE);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		getchar();
		throw std::exception("Could not generate AES counter");
	}
	printf("done.\n");

	printf("Encrypting file(s)...\n");
	for (const auto & file : params.listOfFiles) {
		printf("\tEncrpyting %s ... ", file.c_str());
		ret = ecall_encrypt(global_eid, key, sealLen, file.c_str(), iv, SGX_AESCTR_CTR_SIZE);
		if (ret != SGX_SUCCESS) {
			ErrorSignal::print_error_message(ret);
			getchar();
			throw std::exception("Could not encrypt data");
		}
		printf("done.\n");
	}
	printf("done.\n");

	printf("Decrypting and analysing file(s)...\n");
	for (const auto & file : params.listOfFiles) {
		auto encFile = file + ".enc";
		ret = ecall_decrypt(global_eid, key, sealLen, encFile.c_str(), iv_copy, SGX_AESCTR_CTR_SIZE);
		if (ret != SGX_SUCCESS) {
			ErrorSignal::print_error_message(ret);
			getchar();
			throw std::exception("Could not decrypt data");
		}
	}
	printf("done.\n");

	destroy_enclave();
	printf("Enclave stopped.\n");

	return {
		"success",
		{{ "rj123456", 0.77 }, { "gh987654", 0.21 }}
	};
}

int SGX_CDECL main(int argc, char *argv[])
{
	try {
		GwasServer server(&test);
		server.open().wait();
		printf("Press any key to exit\n");
		getchar();
		server.close().wait();
	}
	catch (const std::exception & e) {
		printf("Error occurred in the main loop: %s", e.what());
	}
	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
