#ifndef OCALLS_H_
#define OCALLS_H_

#include "Enclave_u.h"

void ocall_encrypt_file(uint8_t * key, size_t keyLen,
						const char * path,
						uint8_t * ctr, size_t ctrLen);
void ocall_decrypt_file(uint8_t * key, size_t keyLen,
						const char * path,
						uint8_t * ctr, size_t ctrLen);

void ocall_printf(const char * str);
void ocall_printf_num(long int num);
void ocall_printf_hex(const uint8_t * num, size_t len);

#endif // OCALLS_H_
