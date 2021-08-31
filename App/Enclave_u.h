#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tseal.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_ENCRYPT_FILE_DEFINED__
#define OCALL_ENCRYPT_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_encrypt_file, (const char* path));
#endif
#ifndef OCALL_VARCALL_CALL_SAM_FILE_DEFINED__
#define OCALL_VARCALL_CALL_SAM_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_varcall_call_sam_file, (const char* path, int* mapq));
#endif
#ifndef OCALL_VARCALL_FLUSH_OUTPUT_DEFINED__
#define OCALL_VARCALL_FLUSH_OUTPUT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_varcall_flush_output, (const char* output));
#endif
#ifndef OCALL_ANALYSIS_ADD_FILE_DEFINED__
#define OCALL_ANALYSIS_ADD_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_analysis_add_file, (const char* path, int* success));
#endif
#ifndef OCALL_ANALYSIS_START_DEFINED__
#define OCALL_ANALYSIS_START_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_analysis_start, (void));
#endif
#ifndef OCALL_ANALYSIS_FLUSH_OUTPUT_DEFINED__
#define OCALL_ANALYSIS_FLUSH_OUTPUT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_analysis_flush_output, (const char* output));
#endif
#ifndef OCALL_ANALYSIS_REMOVE_FILES_DEFINED__
#define OCALL_ANALYSIS_REMOVE_FILES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_analysis_remove_files, (void));
#endif
#ifndef OCALL_PRINTF_DEFINED__
#define OCALL_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf, (const char* str));
#endif
#ifndef OCALL_PRINTF_NUM_DEFINED__
#define OCALL_PRINTF_NUM_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf_num, (long int num));
#endif
#ifndef OCALL_PRINTF_HEX_DEFINED__
#define OCALL_PRINTF_HEX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_printf_hex, (const uint8_t* num, size_t len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef U_SGXSSL_FTIME64_DEFINED__
#define U_SGXSSL_FTIME64_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime64, (void* timeptr, uint32_t timeb64Len));
#endif

sgx_status_t ecall_get_seal_size(sgx_enclave_id_t eid, size_t orig, size_t* seal);
sgx_status_t ecall_gen_key(sgx_enclave_id_t eid, uint8_t* key, size_t len);
sgx_status_t ecall_gen_ctr(sgx_enclave_id_t eid, uint8_t* ctr, size_t len);
sgx_status_t ecall_encrypt(sgx_enclave_id_t eid, uint8_t* seal_key, size_t seal_len, const char* path, uint8_t* ctr, size_t ctr_len);
sgx_status_t ecall_encrypt_aes_ctr(sgx_enclave_id_t eid, char* plain, size_t plain_len, uint8_t* crypt, size_t crypt_len);
sgx_status_t ecall_varcall_load_metadata(sgx_enclave_id_t eid, uint8_t* seal_key, size_t seal_len, uint8_t* ctr, size_t ctr_len);
sgx_status_t ecall_varcall_get_pos(sgx_enclave_id_t eid, uint8_t* crypt, size_t crypt_len, int* mapq, int* pos, int* ignore);
sgx_status_t ecall_varcall_find_mutations(sgx_enclave_id_t eid, const char* prefix, const char* ref_seq);
sgx_status_t ecall_varcall_flush_output(sgx_enclave_id_t eid, int* flush_all);
sgx_status_t ecall_analysis_set_params(sgx_enclave_id_t eid, int* roi_begin, int* roi_end);
sgx_status_t ecall_analysis_add_file(sgx_enclave_id_t eid, uint8_t* seal_key, size_t seal_len, const char* path, uint8_t* ctr, size_t ctr_len);
sgx_status_t ecall_analysis_start(sgx_enclave_id_t eid);
sgx_status_t ecall_analysis_flush_output(sgx_enclave_id_t eid, int* flush_all);
sgx_status_t ecall_analysis_read_line(sgx_enclave_id_t eid, int* id, uint8_t* crypt, size_t len_crypt, int* pause);
sgx_status_t sl_init_switchless(sgx_enclave_id_t eid, sgx_status_t* retval, void* sl_data);
sgx_status_t sl_run_switchless_tworker(sgx_enclave_id_t eid, sgx_status_t* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
