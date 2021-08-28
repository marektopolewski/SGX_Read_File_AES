#ifndef OCALLS_H_
#define OCALLS_H_

#include "Enclave_u.h"

void ocall_encrypt_file(const char * path);
void ocall_decrypt_file(const char * path);

void ocall_printf(const char * str);
void ocall_printf_num(long int num);
void ocall_printf_hex(const uint8_t * num, size_t len);

#endif // OCALLS_H_
