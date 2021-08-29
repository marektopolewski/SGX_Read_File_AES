#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include "sgx_eid.h"

#include <string>
#include <tchar.h>

#define TOKEN_FILENAME   _T("Enclave.token")
#define ENCLAVE_FILENAME _T("Enclave.signed.dll")

#define SGX_AESCTR_KEY_SIZE 16 // 128-bit key
#define SGX_AESCTR_CTR_SIZE 16

#define READ_BUFFER_SIZE 25
#define READ_BATCH_SIZE 50

#define STRINGIFY(x) #x
#define EXPAND(x) STRINGIFY(x)

static std::string GET_DIRECTORY() {
	std::string dir_str = EXPAND(PROJECT_DIRECTORY);
	dir_str.erase(0, 1);
	dir_str.erase(dir_str.size() - 2);
	return dir_str;
}

extern sgx_enclave_id_t global_eid;

#endif // CONSTANTS_H_
