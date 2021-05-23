#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_get_seal_size_t {
	size_t ms_orig;
	size_t* ms_seal;
} ms_ecall_get_seal_size_t;

typedef struct ms_ecall_gen_key_t {
	uint8_t* ms_key;
	size_t ms_len;
} ms_ecall_gen_key_t;

typedef struct ms_ecall_gen_ctr_t {
	uint8_t* ms_ctr;
	size_t ms_len;
} ms_ecall_gen_ctr_t;

typedef struct ms_ecall_encrypt_t {
	uint8_t* ms_sealKey;
	size_t ms_sealLen;
	const char* ms_path;
	size_t ms_path_len;
	uint8_t* ms_ctr;
	size_t ms_ctrLen;
} ms_ecall_encrypt_t;

typedef struct ms_ecall_decrypt_t {
	uint8_t* ms_sealKey;
	size_t ms_sealLen;
	const char* ms_path;
	size_t ms_path_len;
	uint8_t* ms_ctr;
	size_t ms_ctrLen;
} ms_ecall_decrypt_t;

typedef struct ms_ecall_encrypt_aes_ctr_t {
	char* ms_plain;
	size_t ms_lenPlain;
	uint8_t* ms_count;
	size_t ms_lenCount;
	uint8_t* ms_crypt;
	size_t ms_lenCrypt;
} ms_ecall_encrypt_aes_ctr_t;

typedef struct ms_ecall_decrypt_aes_ctr_t {
	uint8_t* ms_crypt;
	size_t ms_lenCrypt;
	uint8_t* ms_count;
	size_t ms_lenCount;
	char* ms_plain;
	size_t ms_lenPlain;
} ms_ecall_decrypt_aes_ctr_t;

typedef struct ms_ocall_encrypt_file_t {
	const char* ms_path;
	uint8_t* ms_ctr;
	size_t ms_ctrLen;
} ms_ocall_encrypt_file_t;

typedef struct ms_ocall_decrypt_file_t {
	const char* ms_path;
	uint8_t* ms_ctr;
	size_t ms_ctrLen;
} ms_ocall_decrypt_file_t;

typedef struct ms_ocall_printf_t {
	const char* ms_str;
} ms_ocall_printf_t;

typedef struct ms_ocall_printf_num_t {
	long int ms_num;
} ms_ocall_printf_num_t;

typedef struct ms_ocall_printf_hex_t {
	const uint8_t* ms_num;
	size_t ms_len;
} ms_ocall_printf_hex_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime64_t {
	void* ms_timeptr;
	uint32_t ms_timeb64Len;
} ms_u_sgxssl_ftime64_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_ecall_get_seal_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_seal_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_seal_size_t* ms = SGX_CAST(ms_ecall_get_seal_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	size_t* _tmp_seal = ms->ms_seal;
	size_t _len_seal = sizeof(size_t);
	size_t* _in_seal = NULL;

	CHECK_UNIQUE_POINTER(_tmp_seal, _len_seal);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_seal != NULL && _len_seal != 0) {
		if ( _len_seal % sizeof(*_tmp_seal) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_seal = (size_t*)malloc(_len_seal)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_seal, 0, _len_seal);
	}

	ecall_get_seal_size(ms->ms_orig, _in_seal);
	if (_in_seal) {
		if (memcpy_s(_tmp_seal, _len_seal, _in_seal, _len_seal)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_seal) free(_in_seal);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_gen_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_gen_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_gen_key_t* ms = SGX_CAST(ms_ecall_gen_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _tmp_len = ms->ms_len;
	size_t _len_key = _tmp_len;
	uint8_t* _in_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_key = (uint8_t*)malloc(_len_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_key, 0, _len_key);
	}

	ecall_gen_key(_in_key, _tmp_len);
	if (_in_key) {
		if (memcpy_s(_tmp_key, _len_key, _in_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_key) free(_in_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_gen_ctr(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_gen_ctr_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_gen_ctr_t* ms = SGX_CAST(ms_ecall_gen_ctr_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_ctr = ms->ms_ctr;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ctr = _tmp_len;
	uint8_t* _in_ctr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ctr, _len_ctr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ctr != NULL && _len_ctr != 0) {
		if ( _len_ctr % sizeof(*_tmp_ctr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ctr = (uint8_t*)malloc(_len_ctr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ctr, 0, _len_ctr);
	}

	ecall_gen_ctr(_in_ctr, _tmp_len);
	if (_in_ctr) {
		if (memcpy_s(_tmp_ctr, _len_ctr, _in_ctr, _len_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_ctr) free(_in_ctr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_t* ms = SGX_CAST(ms_ecall_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealKey = ms->ms_sealKey;
	size_t _tmp_sealLen = ms->ms_sealLen;
	size_t _len_sealKey = _tmp_sealLen;
	uint8_t* _in_sealKey = NULL;
	const char* _tmp_path = ms->ms_path;
	size_t _len_path = ms->ms_path_len ;
	char* _in_path = NULL;
	uint8_t* _tmp_ctr = ms->ms_ctr;
	size_t _tmp_ctrLen = ms->ms_ctrLen;
	size_t _len_ctr = _tmp_ctrLen;
	uint8_t* _in_ctr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealKey, _len_sealKey);
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_ctr, _len_ctr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealKey != NULL && _len_sealKey != 0) {
		if ( _len_sealKey % sizeof(*_tmp_sealKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealKey = (uint8_t*)malloc(_len_sealKey);
		if (_in_sealKey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealKey, _len_sealKey, _tmp_sealKey, _len_sealKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_path != NULL && _len_path != 0) {
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_path, _len_path, _tmp_path, _len_path)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_path[_len_path - 1] = '\0';
		if (_len_path != strlen(_in_path) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ctr != NULL && _len_ctr != 0) {
		if ( _len_ctr % sizeof(*_tmp_ctr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ctr = (uint8_t*)malloc(_len_ctr);
		if (_in_ctr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ctr, _len_ctr, _tmp_ctr, _len_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_encrypt(_in_sealKey, _tmp_sealLen, (const char*)_in_path, _in_ctr, _tmp_ctrLen);
	if (_in_ctr) {
		if (memcpy_s(_tmp_ctr, _len_ctr, _in_ctr, _len_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealKey) free(_in_sealKey);
	if (_in_path) free(_in_path);
	if (_in_ctr) free(_in_ctr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decrypt_t* ms = SGX_CAST(ms_ecall_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealKey = ms->ms_sealKey;
	size_t _tmp_sealLen = ms->ms_sealLen;
	size_t _len_sealKey = _tmp_sealLen;
	uint8_t* _in_sealKey = NULL;
	const char* _tmp_path = ms->ms_path;
	size_t _len_path = ms->ms_path_len ;
	char* _in_path = NULL;
	uint8_t* _tmp_ctr = ms->ms_ctr;
	size_t _tmp_ctrLen = ms->ms_ctrLen;
	size_t _len_ctr = _tmp_ctrLen;
	uint8_t* _in_ctr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealKey, _len_sealKey);
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_ctr, _len_ctr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealKey != NULL && _len_sealKey != 0) {
		if ( _len_sealKey % sizeof(*_tmp_sealKey) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_sealKey = (uint8_t*)malloc(_len_sealKey);
		if (_in_sealKey == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealKey, _len_sealKey, _tmp_sealKey, _len_sealKey)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_path != NULL && _len_path != 0) {
		_in_path = (char*)malloc(_len_path);
		if (_in_path == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_path, _len_path, _tmp_path, _len_path)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_path[_len_path - 1] = '\0';
		if (_len_path != strlen(_in_path) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ctr != NULL && _len_ctr != 0) {
		if ( _len_ctr % sizeof(*_tmp_ctr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ctr = (uint8_t*)malloc(_len_ctr);
		if (_in_ctr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ctr, _len_ctr, _tmp_ctr, _len_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_decrypt(_in_sealKey, _tmp_sealLen, (const char*)_in_path, _in_ctr, _tmp_ctrLen);
	if (_in_ctr) {
		if (memcpy_s(_tmp_ctr, _len_ctr, _in_ctr, _len_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealKey) free(_in_sealKey);
	if (_in_path) free(_in_path);
	if (_in_ctr) free(_in_ctr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encrypt_aes_ctr(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_aes_ctr_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_aes_ctr_t* ms = SGX_CAST(ms_ecall_encrypt_aes_ctr_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_plain = ms->ms_plain;
	size_t _tmp_lenPlain = ms->ms_lenPlain;
	size_t _len_plain = _tmp_lenPlain;
	char* _in_plain = NULL;
	uint8_t* _tmp_count = ms->ms_count;
	size_t _tmp_lenCount = ms->ms_lenCount;
	size_t _len_count = _tmp_lenCount;
	uint8_t* _in_count = NULL;
	uint8_t* _tmp_crypt = ms->ms_crypt;
	size_t _tmp_lenCrypt = ms->ms_lenCrypt;
	size_t _len_crypt = _tmp_lenCrypt;
	uint8_t* _in_crypt = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plain, _len_plain);
	CHECK_UNIQUE_POINTER(_tmp_count, _len_count);
	CHECK_UNIQUE_POINTER(_tmp_crypt, _len_crypt);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_plain != NULL && _len_plain != 0) {
		if ( _len_plain % sizeof(*_tmp_plain) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_plain = (char*)malloc(_len_plain);
		if (_in_plain == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_plain, _len_plain, _tmp_plain, _len_plain)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_count != NULL && _len_count != 0) {
		if ( _len_count % sizeof(*_tmp_count) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_count = (uint8_t*)malloc(_len_count);
		if (_in_count == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_count, _len_count, _tmp_count, _len_count)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_crypt != NULL && _len_crypt != 0) {
		if ( _len_crypt % sizeof(*_tmp_crypt) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_crypt = (uint8_t*)malloc(_len_crypt)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_crypt, 0, _len_crypt);
	}

	ecall_encrypt_aes_ctr(_in_plain, _tmp_lenPlain, _in_count, _tmp_lenCount, _in_crypt, _tmp_lenCrypt);
	if (_in_count) {
		if (memcpy_s(_tmp_count, _len_count, _in_count, _len_count)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_crypt) {
		if (memcpy_s(_tmp_crypt, _len_crypt, _in_crypt, _len_crypt)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plain) free(_in_plain);
	if (_in_count) free(_in_count);
	if (_in_crypt) free(_in_crypt);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decrypt_aes_ctr(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decrypt_aes_ctr_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decrypt_aes_ctr_t* ms = SGX_CAST(ms_ecall_decrypt_aes_ctr_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_crypt = ms->ms_crypt;
	size_t _tmp_lenCrypt = ms->ms_lenCrypt;
	size_t _len_crypt = _tmp_lenCrypt;
	uint8_t* _in_crypt = NULL;
	uint8_t* _tmp_count = ms->ms_count;
	size_t _tmp_lenCount = ms->ms_lenCount;
	size_t _len_count = _tmp_lenCount;
	uint8_t* _in_count = NULL;
	char* _tmp_plain = ms->ms_plain;
	size_t _tmp_lenPlain = ms->ms_lenPlain;
	size_t _len_plain = _tmp_lenPlain;
	char* _in_plain = NULL;

	CHECK_UNIQUE_POINTER(_tmp_crypt, _len_crypt);
	CHECK_UNIQUE_POINTER(_tmp_count, _len_count);
	CHECK_UNIQUE_POINTER(_tmp_plain, _len_plain);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_crypt != NULL && _len_crypt != 0) {
		if ( _len_crypt % sizeof(*_tmp_crypt) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_crypt = (uint8_t*)malloc(_len_crypt);
		if (_in_crypt == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_crypt, _len_crypt, _tmp_crypt, _len_crypt)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_count != NULL && _len_count != 0) {
		if ( _len_count % sizeof(*_tmp_count) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_count = (uint8_t*)malloc(_len_count);
		if (_in_count == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_count, _len_count, _tmp_count, _len_count)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_plain != NULL && _len_plain != 0) {
		if ( _len_plain % sizeof(*_tmp_plain) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_plain = (char*)malloc(_len_plain)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_plain, 0, _len_plain);
	}

	ecall_decrypt_aes_ctr(_in_crypt, _tmp_lenCrypt, _in_count, _tmp_lenCount, _in_plain, _tmp_lenPlain);
	if (_in_count) {
		if (memcpy_s(_tmp_count, _len_count, _in_count, _len_count)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_plain) {
		if (memcpy_s(_tmp_plain, _len_plain, _in_plain, _len_plain)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_crypt) free(_in_crypt);
	if (_in_count) free(_in_count);
	if (_in_plain) free(_in_plain);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[7];
} g_ecall_table = {
	7,
	{
		{(void*)(uintptr_t)sgx_ecall_get_seal_size, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_gen_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_gen_ctr, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_decrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt_aes_ctr, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_decrypt_aes_ctr, 1, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[11][7];
} g_dyn_entry_table = {
	11,
	{
		{0, 0, 0, 0, 0, 1, 0, },
		{0, 0, 0, 0, 0, 0, 1, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_encrypt_file(const char* path, uint8_t* ctr, size_t ctrLen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_ctr = ctrLen;

	ms_ocall_encrypt_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_encrypt_file_t);
	void *__tmp = NULL;

	void *__tmp_ctr = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(ctr, _len_ctr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctr != NULL) ? _len_ctr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_encrypt_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_encrypt_file_t));
	ocalloc_size -= sizeof(ms_ocall_encrypt_file_t);

	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	if (ctr != NULL) {
		ms->ms_ctr = (uint8_t*)__tmp;
		__tmp_ctr = __tmp;
		if (_len_ctr % sizeof(*ctr) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, ctr, _len_ctr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctr);
		ocalloc_size -= _len_ctr;
	} else {
		ms->ms_ctr = NULL;
	}
	
	ms->ms_ctrLen = ctrLen;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (ctr) {
			if (memcpy_s((void*)ctr, _len_ctr, __tmp_ctr, _len_ctr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_decrypt_file(const char* path, uint8_t* ctr, size_t ctrLen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_ctr = ctrLen;

	ms_ocall_decrypt_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_decrypt_file_t);
	void *__tmp = NULL;

	void *__tmp_ctr = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(ctr, _len_ctr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ctr != NULL) ? _len_ctr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_decrypt_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_decrypt_file_t));
	ocalloc_size -= sizeof(ms_ocall_decrypt_file_t);

	if (path != NULL) {
		ms->ms_path = (const char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	if (ctr != NULL) {
		ms->ms_ctr = (uint8_t*)__tmp;
		__tmp_ctr = __tmp;
		if (_len_ctr % sizeof(*ctr) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, ctr, _len_ctr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ctr);
		ocalloc_size -= _len_ctr;
	} else {
		ms->ms_ctr = NULL;
	}
	
	ms->ms_ctrLen = ctrLen;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (ctr) {
			if (memcpy_s((void*)ctr, _len_ctr, __tmp_ctr, _len_ctr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_printf(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_printf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_printf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_printf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_printf_t));
	ocalloc_size -= sizeof(ms_ocall_printf_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_printf_num(long int num)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_printf_num_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_printf_num_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_printf_num_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_printf_num_t));
	ocalloc_size -= sizeof(ms_ocall_printf_num_t);

	ms->ms_num = num;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_printf_hex(const uint8_t* num, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_num = len;

	ms_ocall_printf_hex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_printf_hex_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(num, _len_num);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (num != NULL) ? _len_num : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_printf_hex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_printf_hex_t));
	ocalloc_size -= sizeof(ms_ocall_printf_hex_t);

	if (num != NULL) {
		ms->ms_num = (const uint8_t*)__tmp;
		if (_len_num % sizeof(*num) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, num, _len_num)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_num);
		ocalloc_size -= _len_num;
	} else {
		ms->ms_num = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_ftime64(void* timeptr, uint32_t timeb64Len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb64Len;

	ms_u_sgxssl_ftime64_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime64_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime64_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime64_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime64_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb64Len = timeb64Len;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
