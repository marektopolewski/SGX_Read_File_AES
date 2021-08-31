#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tseal.h"
#include "sgxssl_texception.h"

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_get_seal_size(size_t orig, size_t* seal);
void ecall_gen_key(uint8_t* key, size_t len);
void ecall_gen_ctr(uint8_t* ctr, size_t len);
void ecall_encrypt(uint8_t* seal_key, size_t seal_len, const char* path, uint8_t* ctr, size_t ctr_len);
void ecall_encrypt_aes_ctr(char* plain, size_t plain_len, uint8_t* crypt, size_t crypt_len);
void ecall_varcall_load_metadata(uint8_t* seal_key, size_t seal_len, uint8_t* ctr, size_t ctr_len);
void ecall_varcall_get_pos(uint8_t* crypt, size_t crypt_len, int* mapq, int* pos, int* ignore);
void ecall_varcall_find_mutations(const char* prefix, const char* ref_seq);
void ecall_varcall_flush_output(int* flush_all);
void ecall_analysis_set_params(int* roi_begin, int* roi_end);
void ecall_analysis_add_file(uint8_t* seal_key, size_t seal_len, const char* path, uint8_t* ctr, size_t ctr_len);
void ecall_analysis_start(void);
void ecall_analysis_flush_output(int* flush_all);
void ecall_analysis_read_line(int* id, uint8_t* crypt, size_t len_crypt, int* pause);
sgx_status_t sl_init_switchless(void* sl_data);
sgx_status_t sl_run_switchless_tworker(void);

sgx_status_t SGX_CDECL ocall_encrypt_file(const char* path);
sgx_status_t SGX_CDECL ocall_varcall_call_sam_file(const char* path, int* mapq);
sgx_status_t SGX_CDECL ocall_varcall_flush_output(const char* output);
sgx_status_t SGX_CDECL ocall_analysis_add_file(const char* path, int* success);
sgx_status_t SGX_CDECL ocall_analysis_start(void);
sgx_status_t SGX_CDECL ocall_analysis_flush_output(const char* output);
sgx_status_t SGX_CDECL ocall_analysis_remove_files(void);
sgx_status_t SGX_CDECL ocall_printf(const char* str);
sgx_status_t SGX_CDECL ocall_printf_num(long int num);
sgx_status_t SGX_CDECL ocall_printf_hex(const uint8_t* num, size_t len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL u_sgxssl_ftime64(void* timeptr, uint32_t timeb64Len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
