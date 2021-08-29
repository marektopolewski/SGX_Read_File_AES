#ifndef ENCLAVE_DECRYPT_H_
#define ENCLAVE_DECRYPT_H_

#include <memory>

void ecall_decrypt_aes_ctr(uint8_t * unsealedKey, uint8_t * counterIv,
						   uint8_t * cryptMessage, size_t crypt_len,
						   char * plainMessage, size_t plain_len);

#endif // ENCLAVE_DECRYPT_H_
