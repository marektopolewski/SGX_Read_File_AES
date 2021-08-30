#ifndef OCALLS_H_
#define OCALLS_H_

#include "Enclave_u.h"

#include <string>

void ocall_encrypt_file(const char * path);
void ocall_decrypt_file(const char * path);

void ocalls_sequence_set_ref_file(const char * path);
void ocalls_sequence_call_sam_file(const char * path, int * mapq);

void ocall_analysis_add_file(const char * path, int * success);
void ocall_analysis_start();
void ocall_analysis_flush_output(const char * output);
void ocall_analysis_remove_files();

std::string ocall_return_output();

void ocall_printf(const char * str);
void ocall_printf_hex(const uint8_t * num, size_t len);

#endif // OCALLS_H_
