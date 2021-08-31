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
	uint8_t* ms_seal_key;
	size_t ms_seal_len;
	const char* ms_path;
	size_t ms_path_len;
	uint8_t* ms_ctr;
	size_t ms_ctr_len;
} ms_ecall_encrypt_t;

typedef struct ms_ecall_encrypt_aes_ctr_t {
	char* ms_plain;
	size_t ms_plain_len;
	uint8_t* ms_crypt;
	size_t ms_crypt_len;
} ms_ecall_encrypt_aes_ctr_t;

typedef struct ms_ecall_varcall_load_metadata_t {
	uint8_t* ms_in_seal_key;
	size_t ms_in_seal_len;
	uint8_t* ms_in_ctr;
	size_t ms_in_ctr_len;
	uint8_t* ms_out_seal_key;
	size_t ms_out_seal_len;
	uint8_t* ms_out_ctr;
	size_t ms_out_ctr_len;
} ms_ecall_varcall_load_metadata_t;

typedef struct ms_ecall_varcall_get_pos_t {
	uint8_t* ms_crypt;
	size_t ms_crypt_len;
	int* ms_mapq;
	int* ms_pos;
	int* ms_ignore;
} ms_ecall_varcall_get_pos_t;

typedef struct ms_ecall_varcall_find_mutations_t {
	const char* ms_prefix;
	size_t ms_prefix_len;
	const char* ms_ref_seq;
	size_t ms_ref_seq_len;
} ms_ecall_varcall_find_mutations_t;

typedef struct ms_ecall_varcall_flush_output_t {
	int* ms_flush_all;
} ms_ecall_varcall_flush_output_t;

typedef struct ms_ecall_analysis_set_params_t {
	int* ms_roi_begin;
	int* ms_roi_end;
} ms_ecall_analysis_set_params_t;

typedef struct ms_ecall_analysis_add_file_t {
	uint8_t* ms_seal_key;
	size_t ms_seal_len;
	const char* ms_path;
	size_t ms_path_len;
	uint8_t* ms_ctr;
	size_t ms_ctr_len;
} ms_ecall_analysis_add_file_t;

typedef struct ms_ecall_analysis_flush_output_t {
	int* ms_flush_all;
} ms_ecall_analysis_flush_output_t;

typedef struct ms_ecall_analysis_read_line_t {
	int* ms_id;
	uint8_t* ms_crypt;
	size_t ms_len_crypt;
	int* ms_pause;
} ms_ecall_analysis_read_line_t;

typedef struct ms_sl_init_switchless_t {
	sgx_status_t ms_retval;
	void* ms_sl_data;
} ms_sl_init_switchless_t;

typedef struct ms_sl_run_switchless_tworker_t {
	sgx_status_t ms_retval;
} ms_sl_run_switchless_tworker_t;

typedef struct ms_ocall_encrypt_file_t {
	const char* ms_path;
} ms_ocall_encrypt_file_t;

typedef struct ms_ocall_varcall_call_sam_file_t {
	const char* ms_path;
	int* ms_mapq;
} ms_ocall_varcall_call_sam_file_t;

typedef struct ms_ocall_varcall_flush_output_t {
	const char* ms_output;
	size_t ms_out_size;
} ms_ocall_varcall_flush_output_t;

typedef struct ms_ocall_analysis_add_file_t {
	const char* ms_path;
	int* ms_success;
} ms_ocall_analysis_add_file_t;

typedef struct ms_ocall_analysis_flush_output_t {
	const char* ms_output;
} ms_ocall_analysis_flush_output_t;

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
	uint8_t* _tmp_seal_key = ms->ms_seal_key;
	size_t _tmp_seal_len = ms->ms_seal_len;
	size_t _len_seal_key = _tmp_seal_len;
	uint8_t* _in_seal_key = NULL;
	const char* _tmp_path = ms->ms_path;
	size_t _len_path = ms->ms_path_len ;
	char* _in_path = NULL;
	uint8_t* _tmp_ctr = ms->ms_ctr;
	size_t _tmp_ctr_len = ms->ms_ctr_len;
	size_t _len_ctr = _tmp_ctr_len;
	uint8_t* _in_ctr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_seal_key, _len_seal_key);
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_ctr, _len_ctr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_seal_key != NULL && _len_seal_key != 0) {
		if ( _len_seal_key % sizeof(*_tmp_seal_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_seal_key = (uint8_t*)malloc(_len_seal_key);
		if (_in_seal_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_seal_key, _len_seal_key, _tmp_seal_key, _len_seal_key)) {
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

	ecall_encrypt(_in_seal_key, _tmp_seal_len, (const char*)_in_path, _in_ctr, _tmp_ctr_len);
	if (_in_ctr) {
		if (memcpy_s(_tmp_ctr, _len_ctr, _in_ctr, _len_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_seal_key) free(_in_seal_key);
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
	size_t _tmp_plain_len = ms->ms_plain_len;
	size_t _len_plain = _tmp_plain_len;
	char* _in_plain = NULL;
	uint8_t* _tmp_crypt = ms->ms_crypt;
	size_t _tmp_crypt_len = ms->ms_crypt_len;
	size_t _len_crypt = _tmp_crypt_len;
	uint8_t* _in_crypt = NULL;

	CHECK_UNIQUE_POINTER(_tmp_plain, _len_plain);
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

	ecall_encrypt_aes_ctr(_in_plain, _tmp_plain_len, _in_crypt, _tmp_crypt_len);
	if (_in_crypt) {
		if (memcpy_s(_tmp_crypt, _len_crypt, _in_crypt, _len_crypt)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_plain) free(_in_plain);
	if (_in_crypt) free(_in_crypt);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_varcall_load_metadata(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_varcall_load_metadata_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_varcall_load_metadata_t* ms = SGX_CAST(ms_ecall_varcall_load_metadata_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_in_seal_key = ms->ms_in_seal_key;
	size_t _tmp_in_seal_len = ms->ms_in_seal_len;
	size_t _len_in_seal_key = _tmp_in_seal_len;
	uint8_t* _in_in_seal_key = NULL;
	uint8_t* _tmp_in_ctr = ms->ms_in_ctr;
	size_t _tmp_in_ctr_len = ms->ms_in_ctr_len;
	size_t _len_in_ctr = _tmp_in_ctr_len;
	uint8_t* _in_in_ctr = NULL;
	uint8_t* _tmp_out_seal_key = ms->ms_out_seal_key;
	size_t _tmp_out_seal_len = ms->ms_out_seal_len;
	size_t _len_out_seal_key = _tmp_out_seal_len;
	uint8_t* _in_out_seal_key = NULL;
	uint8_t* _tmp_out_ctr = ms->ms_out_ctr;
	size_t _tmp_out_ctr_len = ms->ms_out_ctr_len;
	size_t _len_out_ctr = _tmp_out_ctr_len;
	uint8_t* _in_out_ctr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_in_seal_key, _len_in_seal_key);
	CHECK_UNIQUE_POINTER(_tmp_in_ctr, _len_in_ctr);
	CHECK_UNIQUE_POINTER(_tmp_out_seal_key, _len_out_seal_key);
	CHECK_UNIQUE_POINTER(_tmp_out_ctr, _len_out_ctr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_in_seal_key != NULL && _len_in_seal_key != 0) {
		if ( _len_in_seal_key % sizeof(*_tmp_in_seal_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_in_seal_key = (uint8_t*)malloc(_len_in_seal_key);
		if (_in_in_seal_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in_seal_key, _len_in_seal_key, _tmp_in_seal_key, _len_in_seal_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_in_ctr != NULL && _len_in_ctr != 0) {
		if ( _len_in_ctr % sizeof(*_tmp_in_ctr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_in_ctr = (uint8_t*)malloc(_len_in_ctr);
		if (_in_in_ctr == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_in_ctr, _len_in_ctr, _tmp_in_ctr, _len_in_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_out_seal_key != NULL && _len_out_seal_key != 0) {
		if ( _len_out_seal_key % sizeof(*_tmp_out_seal_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out_seal_key = (uint8_t*)malloc(_len_out_seal_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_seal_key, 0, _len_out_seal_key);
	}
	if (_tmp_out_ctr != NULL && _len_out_ctr != 0) {
		if ( _len_out_ctr % sizeof(*_tmp_out_ctr) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_out_ctr = (uint8_t*)malloc(_len_out_ctr)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_ctr, 0, _len_out_ctr);
	}

	ecall_varcall_load_metadata(_in_in_seal_key, _tmp_in_seal_len, _in_in_ctr, _tmp_in_ctr_len, _in_out_seal_key, _tmp_out_seal_len, _in_out_ctr, _tmp_out_ctr_len);
	if (_in_in_ctr) {
		if (memcpy_s(_tmp_in_ctr, _len_in_ctr, _in_in_ctr, _len_in_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_out_seal_key) {
		if (memcpy_s(_tmp_out_seal_key, _len_out_seal_key, _in_out_seal_key, _len_out_seal_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_out_ctr) {
		if (memcpy_s(_tmp_out_ctr, _len_out_ctr, _in_out_ctr, _len_out_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_in_seal_key) free(_in_in_seal_key);
	if (_in_in_ctr) free(_in_in_ctr);
	if (_in_out_seal_key) free(_in_out_seal_key);
	if (_in_out_ctr) free(_in_out_ctr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_varcall_get_pos(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_varcall_get_pos_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_varcall_get_pos_t* ms = SGX_CAST(ms_ecall_varcall_get_pos_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_crypt = ms->ms_crypt;
	size_t _tmp_crypt_len = ms->ms_crypt_len;
	size_t _len_crypt = _tmp_crypt_len;
	uint8_t* _in_crypt = NULL;
	int* _tmp_mapq = ms->ms_mapq;
	size_t _len_mapq = sizeof(int);
	int* _in_mapq = NULL;
	int* _tmp_pos = ms->ms_pos;
	size_t _len_pos = sizeof(int);
	int* _in_pos = NULL;
	int* _tmp_ignore = ms->ms_ignore;
	size_t _len_ignore = sizeof(int);
	int* _in_ignore = NULL;

	CHECK_UNIQUE_POINTER(_tmp_crypt, _len_crypt);
	CHECK_UNIQUE_POINTER(_tmp_mapq, _len_mapq);
	CHECK_UNIQUE_POINTER(_tmp_pos, _len_pos);
	CHECK_UNIQUE_POINTER(_tmp_ignore, _len_ignore);

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
	if (_tmp_mapq != NULL && _len_mapq != 0) {
		if ( _len_mapq % sizeof(*_tmp_mapq) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_mapq = (int*)malloc(_len_mapq);
		if (_in_mapq == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_mapq, _len_mapq, _tmp_mapq, _len_mapq)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_pos != NULL && _len_pos != 0) {
		if ( _len_pos % sizeof(*_tmp_pos) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pos = (int*)malloc(_len_pos)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pos, 0, _len_pos);
	}
	if (_tmp_ignore != NULL && _len_ignore != 0) {
		if ( _len_ignore % sizeof(*_tmp_ignore) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_ignore = (int*)malloc(_len_ignore)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ignore, 0, _len_ignore);
	}

	ecall_varcall_get_pos(_in_crypt, _tmp_crypt_len, _in_mapq, _in_pos, _in_ignore);
	if (_in_pos) {
		if (memcpy_s(_tmp_pos, _len_pos, _in_pos, _len_pos)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_ignore) {
		if (memcpy_s(_tmp_ignore, _len_ignore, _in_ignore, _len_ignore)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_crypt) free(_in_crypt);
	if (_in_mapq) free(_in_mapq);
	if (_in_pos) free(_in_pos);
	if (_in_ignore) free(_in_ignore);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_varcall_find_mutations(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_varcall_find_mutations_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_varcall_find_mutations_t* ms = SGX_CAST(ms_ecall_varcall_find_mutations_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_prefix = ms->ms_prefix;
	size_t _len_prefix = ms->ms_prefix_len ;
	char* _in_prefix = NULL;
	const char* _tmp_ref_seq = ms->ms_ref_seq;
	size_t _len_ref_seq = ms->ms_ref_seq_len ;
	char* _in_ref_seq = NULL;

	CHECK_UNIQUE_POINTER(_tmp_prefix, _len_prefix);
	CHECK_UNIQUE_POINTER(_tmp_ref_seq, _len_ref_seq);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_prefix != NULL && _len_prefix != 0) {
		_in_prefix = (char*)malloc(_len_prefix);
		if (_in_prefix == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_prefix, _len_prefix, _tmp_prefix, _len_prefix)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_prefix[_len_prefix - 1] = '\0';
		if (_len_prefix != strlen(_in_prefix) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ref_seq != NULL && _len_ref_seq != 0) {
		_in_ref_seq = (char*)malloc(_len_ref_seq);
		if (_in_ref_seq == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ref_seq, _len_ref_seq, _tmp_ref_seq, _len_ref_seq)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_ref_seq[_len_ref_seq - 1] = '\0';
		if (_len_ref_seq != strlen(_in_ref_seq) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_varcall_find_mutations((const char*)_in_prefix, (const char*)_in_ref_seq);

err:
	if (_in_prefix) free(_in_prefix);
	if (_in_ref_seq) free(_in_ref_seq);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_varcall_flush_output(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_varcall_flush_output_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_varcall_flush_output_t* ms = SGX_CAST(ms_ecall_varcall_flush_output_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_flush_all = ms->ms_flush_all;
	size_t _len_flush_all = sizeof(int);
	int* _in_flush_all = NULL;

	CHECK_UNIQUE_POINTER(_tmp_flush_all, _len_flush_all);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_flush_all != NULL && _len_flush_all != 0) {
		if ( _len_flush_all % sizeof(*_tmp_flush_all) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_flush_all = (int*)malloc(_len_flush_all);
		if (_in_flush_all == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_flush_all, _len_flush_all, _tmp_flush_all, _len_flush_all)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_varcall_flush_output(_in_flush_all);

err:
	if (_in_flush_all) free(_in_flush_all);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_analysis_set_params(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_analysis_set_params_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_analysis_set_params_t* ms = SGX_CAST(ms_ecall_analysis_set_params_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_roi_begin = ms->ms_roi_begin;
	size_t _len_roi_begin = sizeof(int);
	int* _in_roi_begin = NULL;
	int* _tmp_roi_end = ms->ms_roi_end;
	size_t _len_roi_end = sizeof(int);
	int* _in_roi_end = NULL;

	CHECK_UNIQUE_POINTER(_tmp_roi_begin, _len_roi_begin);
	CHECK_UNIQUE_POINTER(_tmp_roi_end, _len_roi_end);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_roi_begin != NULL && _len_roi_begin != 0) {
		if ( _len_roi_begin % sizeof(*_tmp_roi_begin) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_roi_begin = (int*)malloc(_len_roi_begin);
		if (_in_roi_begin == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_roi_begin, _len_roi_begin, _tmp_roi_begin, _len_roi_begin)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_roi_end != NULL && _len_roi_end != 0) {
		if ( _len_roi_end % sizeof(*_tmp_roi_end) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_roi_end = (int*)malloc(_len_roi_end);
		if (_in_roi_end == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_roi_end, _len_roi_end, _tmp_roi_end, _len_roi_end)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_analysis_set_params(_in_roi_begin, _in_roi_end);

err:
	if (_in_roi_begin) free(_in_roi_begin);
	if (_in_roi_end) free(_in_roi_end);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_analysis_add_file(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_analysis_add_file_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_analysis_add_file_t* ms = SGX_CAST(ms_ecall_analysis_add_file_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_seal_key = ms->ms_seal_key;
	size_t _tmp_seal_len = ms->ms_seal_len;
	size_t _len_seal_key = _tmp_seal_len;
	uint8_t* _in_seal_key = NULL;
	const char* _tmp_path = ms->ms_path;
	size_t _len_path = ms->ms_path_len ;
	char* _in_path = NULL;
	uint8_t* _tmp_ctr = ms->ms_ctr;
	size_t _tmp_ctr_len = ms->ms_ctr_len;
	size_t _len_ctr = _tmp_ctr_len;
	uint8_t* _in_ctr = NULL;

	CHECK_UNIQUE_POINTER(_tmp_seal_key, _len_seal_key);
	CHECK_UNIQUE_POINTER(_tmp_path, _len_path);
	CHECK_UNIQUE_POINTER(_tmp_ctr, _len_ctr);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_seal_key != NULL && _len_seal_key != 0) {
		if ( _len_seal_key % sizeof(*_tmp_seal_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_seal_key = (uint8_t*)malloc(_len_seal_key);
		if (_in_seal_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_seal_key, _len_seal_key, _tmp_seal_key, _len_seal_key)) {
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

	ecall_analysis_add_file(_in_seal_key, _tmp_seal_len, (const char*)_in_path, _in_ctr, _tmp_ctr_len);
	if (_in_ctr) {
		if (memcpy_s(_tmp_ctr, _len_ctr, _in_ctr, _len_ctr)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_seal_key) free(_in_seal_key);
	if (_in_path) free(_in_path);
	if (_in_ctr) free(_in_ctr);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_analysis_start(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_analysis_start();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_analysis_flush_output(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_analysis_flush_output_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_analysis_flush_output_t* ms = SGX_CAST(ms_ecall_analysis_flush_output_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_flush_all = ms->ms_flush_all;
	size_t _len_flush_all = sizeof(int);
	int* _in_flush_all = NULL;

	CHECK_UNIQUE_POINTER(_tmp_flush_all, _len_flush_all);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_flush_all != NULL && _len_flush_all != 0) {
		if ( _len_flush_all % sizeof(*_tmp_flush_all) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_flush_all = (int*)malloc(_len_flush_all);
		if (_in_flush_all == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_flush_all, _len_flush_all, _tmp_flush_all, _len_flush_all)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_analysis_flush_output(_in_flush_all);

err:
	if (_in_flush_all) free(_in_flush_all);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_analysis_read_line(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_analysis_read_line_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_analysis_read_line_t* ms = SGX_CAST(ms_ecall_analysis_read_line_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_id = ms->ms_id;
	size_t _len_id = sizeof(int);
	int* _in_id = NULL;
	uint8_t* _tmp_crypt = ms->ms_crypt;
	size_t _tmp_len_crypt = ms->ms_len_crypt;
	size_t _len_crypt = _tmp_len_crypt;
	uint8_t* _in_crypt = NULL;
	int* _tmp_pause = ms->ms_pause;
	size_t _len_pause = sizeof(int);
	int* _in_pause = NULL;

	CHECK_UNIQUE_POINTER(_tmp_id, _len_id);
	CHECK_UNIQUE_POINTER(_tmp_crypt, _len_crypt);
	CHECK_UNIQUE_POINTER(_tmp_pause, _len_pause);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_id != NULL && _len_id != 0) {
		if ( _len_id % sizeof(*_tmp_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_id = (int*)malloc(_len_id);
		if (_in_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_id, _len_id, _tmp_id, _len_id)) {
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
	if (_tmp_pause != NULL && _len_pause != 0) {
		if ( _len_pause % sizeof(*_tmp_pause) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_pause = (int*)malloc(_len_pause)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_pause, 0, _len_pause);
	}

	ecall_analysis_read_line(_in_id, _in_crypt, _tmp_len_crypt, _in_pause);
	if (_in_pause) {
		if (memcpy_s(_tmp_pause, _len_pause, _in_pause, _len_pause)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_id) free(_in_id);
	if (_in_crypt) free(_in_crypt);
	if (_in_pause) free(_in_pause);
	return status;
}

static sgx_status_t SGX_CDECL sgx_sl_init_switchless(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sl_init_switchless_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sl_init_switchless_t* ms = SGX_CAST(ms_sl_init_switchless_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_sl_data = ms->ms_sl_data;



	ms->ms_retval = sl_init_switchless(_tmp_sl_data);


	return status;
}

static sgx_status_t SGX_CDECL sgx_sl_run_switchless_tworker(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sl_run_switchless_tworker_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sl_run_switchless_tworker_t* ms = SGX_CAST(ms_sl_run_switchless_tworker_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = sl_run_switchless_tworker();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[16];
} g_ecall_table = {
	16,
	{
		{(void*)(uintptr_t)sgx_ecall_get_seal_size, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_gen_key, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_gen_ctr, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt_aes_ctr, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_varcall_load_metadata, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_varcall_get_pos, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_varcall_find_mutations, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_varcall_flush_output, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_analysis_set_params, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_analysis_add_file, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_analysis_start, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_analysis_flush_output, 1, 0},
		{(void*)(uintptr_t)sgx_ecall_analysis_read_line, 1, 0},
		{(void*)(uintptr_t)sgx_sl_init_switchless, 0, 0},
		{(void*)(uintptr_t)sgx_sl_run_switchless_tworker, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[16][16];
} g_dyn_entry_table = {
	16,
	{
		{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_encrypt_file(const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_ocall_encrypt_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_encrypt_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
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
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_varcall_call_sam_file(const char* path, int* mapq)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_mapq = sizeof(int);

	ms_ocall_varcall_call_sam_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_varcall_call_sam_file_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(mapq, _len_mapq);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mapq != NULL) ? _len_mapq : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_varcall_call_sam_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_varcall_call_sam_file_t));
	ocalloc_size -= sizeof(ms_ocall_varcall_call_sam_file_t);

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
	
	if (mapq != NULL) {
		ms->ms_mapq = (int*)__tmp;
		if (_len_mapq % sizeof(*mapq) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, mapq, _len_mapq)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mapq);
		ocalloc_size -= _len_mapq;
	} else {
		ms->ms_mapq = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_varcall_flush_output(const char* output, size_t out_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_output = out_size;

	ms_ocall_varcall_flush_output_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_varcall_flush_output_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(output, _len_output);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (output != NULL) ? _len_output : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_varcall_flush_output_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_varcall_flush_output_t));
	ocalloc_size -= sizeof(ms_ocall_varcall_flush_output_t);

	if (output != NULL) {
		ms->ms_output = (const char*)__tmp;
		if (_len_output % sizeof(*output) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, output, _len_output)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_output);
		ocalloc_size -= _len_output;
	} else {
		ms->ms_output = NULL;
	}
	
	ms->ms_out_size = out_size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_analysis_add_file(const char* path, int* success)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;
	size_t _len_success = sizeof(int);

	ms_ocall_analysis_add_file_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_analysis_add_file_t);
	void *__tmp = NULL;

	void *__tmp_success = NULL;

	CHECK_ENCLAVE_POINTER(path, _len_path);
	CHECK_ENCLAVE_POINTER(success, _len_success);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (success != NULL) ? _len_success : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_analysis_add_file_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_analysis_add_file_t));
	ocalloc_size -= sizeof(ms_ocall_analysis_add_file_t);

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
	
	if (success != NULL) {
		ms->ms_success = (int*)__tmp;
		__tmp_success = __tmp;
		if (_len_success % sizeof(*success) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_success, 0, _len_success);
		__tmp = (void *)((size_t)__tmp + _len_success);
		ocalloc_size -= _len_success;
	} else {
		ms->ms_success = NULL;
	}
	
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (success) {
			if (memcpy_s((void*)success, _len_success, __tmp_success, _len_success)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_analysis_start(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(4, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall_analysis_flush_output(const char* output)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_output = output ? strlen(output) + 1 : 0;

	ms_ocall_analysis_flush_output_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_analysis_flush_output_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(output, _len_output);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (output != NULL) ? _len_output : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_analysis_flush_output_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_analysis_flush_output_t));
	ocalloc_size -= sizeof(ms_ocall_analysis_flush_output_t);

	if (output != NULL) {
		ms->ms_output = (const char*)__tmp;
		if (_len_output % sizeof(*output) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, output, _len_output)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_output);
		ocalloc_size -= _len_output;
	} else {
		ms->ms_output = NULL;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_analysis_remove_files(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(6, NULL);

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
	
	status = sgx_ocall(7, ms);

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
	status = sgx_ocall(8, ms);

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
	status = sgx_ocall(9, ms);

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
	status = sgx_ocall(10, ms);

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
	status = sgx_ocall(11, ms);

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
	status = sgx_ocall(12, ms);

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
	status = sgx_ocall(13, ms);

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
	status = sgx_ocall(14, ms);

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
	status = sgx_ocall(15, ms);

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
