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
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_encrypt_file, (const char* path, uint8_t* ctr, size_t ctrLen));
#endif
#ifndef OCALL_DECRYPT_FILE_DEFINED__
#define OCALL_DECRYPT_FILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_decrypt_file, (const char* path, uint8_t* ctr, size_t ctrLen));
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
sgx_status_t ecall_encrypt(sgx_enclave_id_t eid, uint8_t* sealKey, size_t sealLen, const char* path, uint8_t* ctr, size_t ctrLen);
sgx_status_t ecall_decrypt(sgx_enclave_id_t eid, uint8_t* sealKey, size_t sealLen, const char* path, uint8_t* ctr, size_t ctrLen);
sgx_status_t ecall_encrypt_aes_ctr(sgx_enclave_id_t eid, char* plain, size_t lenPlain, uint8_t* count, size_t lenCount, uint8_t* crypt, size_t lenCrypt);
sgx_status_t ecall_decrypt_aes_ctr(sgx_enclave_id_t eid, uint8_t* crypt, size_t lenCrypt, uint8_t* count, size_t lenCount, char* plain, size_t lenPlain);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
