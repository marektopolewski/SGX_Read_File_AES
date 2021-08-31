#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include "sgx_eid.h"

#include <string>
#include <tchar.h>

/* SGX CONSTANTS */
#define TOKEN_FILENAME   _T("Enclave.token")
#define ENCLAVE_FILENAME _T("Enclave.signed.dll")

#define SGX_AESCTR_KEY_SIZE 16 // 128-bit key
#define SGX_AESCTR_CTR_SIZE 16

extern sgx_enclave_id_t global_eid;

/* MISC */
#define STRINGIFY(x) #x
#define EXPAND(x) STRINGIFY(x)

static std::string GET_DATA_DIR() {
	std::string dir_str = EXPAND(PROJECT_DIRECTORY);
	dir_str.erase(0, 1);
	dir_str.erase(dir_str.size() - 2);
	return dir_str + "data/";
}

static std::string MAKE_SUB_PATH(const char * sam_path, const char * sub)
{
	return sub + std::string(sam_path).substr(strlen(sub),
		strlen(sam_path) - strlen(sub) * 2) + sub;
}

/* SAM and FASTA CONSTANTS */
#define SEQ_READ_SIZE 82
#define WILDCARD_NUCLEOTIDE 'N'

/* VCF CONSTANTS */
#define MAX_BUFFER_SIZE 31
#define READ_BUFFER_SIZE_L 400
#define READ_BUFFER_SIZE_S 45
#define READ_BATCH_SIZE 50

#endif // CONSTANTS_H_
