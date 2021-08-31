#include "Enclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL Enclave_ocall_encrypt_file(void* pms)
{
	ms_ocall_encrypt_file_t* ms = SGX_CAST(ms_ocall_encrypt_file_t*, pms);
	ocall_encrypt_file(ms->ms_path);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_varcall_call_sam_file(void* pms)
{
	ms_ocall_varcall_call_sam_file_t* ms = SGX_CAST(ms_ocall_varcall_call_sam_file_t*, pms);
	ocall_varcall_call_sam_file(ms->ms_path, ms->ms_mapq);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_varcall_flush_output(void* pms)
{
	ms_ocall_varcall_flush_output_t* ms = SGX_CAST(ms_ocall_varcall_flush_output_t*, pms);
	ocall_varcall_flush_output(ms->ms_output, ms->ms_out_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_analysis_add_file(void* pms)
{
	ms_ocall_analysis_add_file_t* ms = SGX_CAST(ms_ocall_analysis_add_file_t*, pms);
	ocall_analysis_add_file(ms->ms_path, ms->ms_success);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_analysis_start(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_analysis_start();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_analysis_flush_output(void* pms)
{
	ms_ocall_analysis_flush_output_t* ms = SGX_CAST(ms_ocall_analysis_flush_output_t*, pms);
	ocall_analysis_flush_output(ms->ms_output);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_analysis_remove_files(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall_analysis_remove_files();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_printf(void* pms)
{
	ms_ocall_printf_t* ms = SGX_CAST(ms_ocall_printf_t*, pms);
	ocall_printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_printf_num(void* pms)
{
	ms_ocall_printf_num_t* ms = SGX_CAST(ms_ocall_printf_num_t*, pms);
	ocall_printf_num(ms->ms_num);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_printf_hex(void* pms)
{
	ms_ocall_printf_hex_t* ms = SGX_CAST(ms_ocall_printf_hex_t*, pms);
	ocall_printf_hex(ms->ms_num, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sgxssl_ftime64(void* pms)
{
	ms_u_sgxssl_ftime64_t* ms = SGX_CAST(ms_u_sgxssl_ftime64_t*, pms);
	u_sgxssl_ftime64(ms->ms_timeptr, ms->ms_timeb64Len);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[16];
} ocall_table_Enclave = {
	16,
	{
		(void*)(uintptr_t)Enclave_ocall_encrypt_file,
		(void*)(uintptr_t)Enclave_ocall_varcall_call_sam_file,
		(void*)(uintptr_t)Enclave_ocall_varcall_flush_output,
		(void*)(uintptr_t)Enclave_ocall_analysis_add_file,
		(void*)(uintptr_t)Enclave_ocall_analysis_start,
		(void*)(uintptr_t)Enclave_ocall_analysis_flush_output,
		(void*)(uintptr_t)Enclave_ocall_analysis_remove_files,
		(void*)(uintptr_t)Enclave_ocall_printf,
		(void*)(uintptr_t)Enclave_ocall_printf_num,
		(void*)(uintptr_t)Enclave_ocall_printf_hex,
		(void*)(uintptr_t)Enclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)(uintptr_t)Enclave_u_sgxssl_ftime64,
	}
};

sgx_status_t ecall_get_seal_size(sgx_enclave_id_t eid, size_t orig, size_t* seal)
{
	sgx_status_t status;
	ms_ecall_get_seal_size_t ms;
	ms.ms_orig = orig;
	ms.ms_seal = seal;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_gen_key(sgx_enclave_id_t eid, uint8_t* key, size_t len)
{
	sgx_status_t status;
	ms_ecall_gen_key_t ms;
	ms.ms_key = key;
	ms.ms_len = len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_gen_ctr(sgx_enclave_id_t eid, uint8_t* ctr, size_t len)
{
	sgx_status_t status;
	ms_ecall_gen_ctr_t ms;
	ms.ms_ctr = ctr;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_encrypt(sgx_enclave_id_t eid, uint8_t* seal_key, size_t seal_len, const char* path, uint8_t* ctr, size_t ctr_len)
{
	sgx_status_t status;
	ms_ecall_encrypt_t ms;
	ms.ms_seal_key = seal_key;
	ms.ms_seal_len = seal_len;
	ms.ms_path = path;
	ms.ms_path_len = path ? strlen(path) + 1 : 0;
	ms.ms_ctr = ctr;
	ms.ms_ctr_len = ctr_len;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_encrypt_aes_ctr(sgx_enclave_id_t eid, char* plain, size_t plain_len, uint8_t* crypt, size_t crypt_len)
{
	sgx_status_t status;
	ms_ecall_encrypt_aes_ctr_t ms;
	ms.ms_plain = plain;
	ms.ms_plain_len = plain_len;
	ms.ms_crypt = crypt;
	ms.ms_crypt_len = crypt_len;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_varcall_load_metadata(sgx_enclave_id_t eid, uint8_t* in_seal_key, size_t in_seal_len, uint8_t* in_ctr, size_t in_ctr_len, uint8_t* out_seal_key, size_t out_seal_len, uint8_t* out_ctr, size_t out_ctr_len)
{
	sgx_status_t status;
	ms_ecall_varcall_load_metadata_t ms;
	ms.ms_in_seal_key = in_seal_key;
	ms.ms_in_seal_len = in_seal_len;
	ms.ms_in_ctr = in_ctr;
	ms.ms_in_ctr_len = in_ctr_len;
	ms.ms_out_seal_key = out_seal_key;
	ms.ms_out_seal_len = out_seal_len;
	ms.ms_out_ctr = out_ctr;
	ms.ms_out_ctr_len = out_ctr_len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_varcall_get_pos(sgx_enclave_id_t eid, uint8_t* crypt, size_t crypt_len, int* mapq, int* pos, int* ignore)
{
	sgx_status_t status;
	ms_ecall_varcall_get_pos_t ms;
	ms.ms_crypt = crypt;
	ms.ms_crypt_len = crypt_len;
	ms.ms_mapq = mapq;
	ms.ms_pos = pos;
	ms.ms_ignore = ignore;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_varcall_find_mutations(sgx_enclave_id_t eid, const char* prefix, const char* ref_seq)
{
	sgx_status_t status;
	ms_ecall_varcall_find_mutations_t ms;
	ms.ms_prefix = prefix;
	ms.ms_prefix_len = prefix ? strlen(prefix) + 1 : 0;
	ms.ms_ref_seq = ref_seq;
	ms.ms_ref_seq_len = ref_seq ? strlen(ref_seq) + 1 : 0;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_varcall_flush_output(sgx_enclave_id_t eid, int* flush_all)
{
	sgx_status_t status;
	ms_ecall_varcall_flush_output_t ms;
	ms.ms_flush_all = flush_all;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_analysis_set_params(sgx_enclave_id_t eid, int* roi_begin, int* roi_end)
{
	sgx_status_t status;
	ms_ecall_analysis_set_params_t ms;
	ms.ms_roi_begin = roi_begin;
	ms.ms_roi_end = roi_end;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_analysis_add_file(sgx_enclave_id_t eid, uint8_t* seal_key, size_t seal_len, const char* path, uint8_t* ctr, size_t ctr_len)
{
	sgx_status_t status;
	ms_ecall_analysis_add_file_t ms;
	ms.ms_seal_key = seal_key;
	ms.ms_seal_len = seal_len;
	ms.ms_path = path;
	ms.ms_path_len = path ? strlen(path) + 1 : 0;
	ms.ms_ctr = ctr;
	ms.ms_ctr_len = ctr_len;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_analysis_start(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 11, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_analysis_flush_output(sgx_enclave_id_t eid, int* flush_all)
{
	sgx_status_t status;
	ms_ecall_analysis_flush_output_t ms;
	ms.ms_flush_all = flush_all;
	status = sgx_ecall(eid, 12, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_analysis_read_line(sgx_enclave_id_t eid, int* id, uint8_t* crypt, size_t len_crypt, int* pause)
{
	sgx_status_t status;
	ms_ecall_analysis_read_line_t ms;
	ms.ms_id = id;
	ms.ms_crypt = crypt;
	ms.ms_len_crypt = len_crypt;
	ms.ms_pause = pause;
	status = sgx_ecall(eid, 13, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t sl_init_switchless(sgx_enclave_id_t eid, sgx_status_t* retval, void* sl_data)
{
	sgx_status_t status;
	ms_sl_init_switchless_t ms;
	ms.ms_sl_data = sl_data;
	status = sgx_ecall(eid, 14, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sl_run_switchless_tworker(sgx_enclave_id_t eid, sgx_status_t* retval)
{
	sgx_status_t status;
	ms_sl_run_switchless_tworker_t ms;
	status = sgx_ecall(eid, 15, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

