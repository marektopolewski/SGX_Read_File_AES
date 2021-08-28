#include "OCalls.h"

#include "Constants.h"

#include <assert.h>
#include <stdio.h>
#include <string>

namespace
{

	void _printf_hex(const uint8_t * num, size_t len)
	{
		for (int i = 0; i < len; ++i)
			printf("%x", num[i] & 0xff);
		printf("\n");
	}

} // unnamed namespace

void ocall_printf(const char * str)
{
	printf("[ENCLAVE] %s\n", str);
}

void ocall_printf_num(long int num)
{
	printf("[ENCLAVE] %ld\n", num);
}

void ocall_printf_hex(const uint8_t * num, size_t len)
{
	if (len < 1)
		return;
	printf("[ENCLAVE] ");
	_printf_hex(num, len);
}

void ocall_encrypt_file(const char * path, const char * encPath)
{
	// Open files
	FILE * file_to_read;
	fopen_s(&file_to_read, path, "rb");
	if (file_to_read == NULL) {
		printf("Fatal error: could not open file - \"%s\"", path);
		return;
	}
	FILE * file_to_write;
	fopen_s(&file_to_write, encPath, "wb");
	if (file_to_write == NULL) {
		printf("Fatal error: could not open file - \"%s\"", encPath);
		fclose(file_to_read);
		return;
	}

	// Read and encrypt file
	char read_buffer[READ_BUFFER_SIZE + 1] = "";
	int inc = 0;
	while (!feof(file_to_read)) {
		// Read chunk
		size_t size_read = fread(read_buffer, sizeof(char), READ_BUFFER_SIZE, file_to_read);
		read_buffer[size_read] = '\0';

		// Encrypt chunk
		uint8_t enc_buffer[READ_BUFFER_SIZE];
		printf("\t%d: encrypted\n", ++inc);
		ecall_encrypt_aes_ctr(global_eid, read_buffer, size_read, enc_buffer, size_read);

		// Save to disk
		fwrite(enc_buffer, sizeof(uint8_t), size_read, file_to_write);
	}

	// Close file and return init vector (counter)
	fclose(file_to_read);
	fclose(file_to_write);
}


void ocall_decrypt_file(const char * path)
{
	// Open file
	FILE * file_to_read;
	fopen_s(&file_to_read, path, "rb");
	if (file_to_read == NULL) {
		printf("Fatal error: could not open file - \"%s\"", path);
		return;
	}

	uint8_t read_buffer[READ_BUFFER_SIZE] = "";
	int inc = 0;
	while (!feof(file_to_read)) {
		// Read chunk
		size_t size_read = fread(read_buffer, sizeof(uint8_t), READ_BUFFER_SIZE, file_to_read);

		// Decrypt chunk
		char dec_buffer[READ_BUFFER_SIZE + 1];
		ecall_decrypt_aes_ctr(global_eid, read_buffer, size_read, dec_buffer, size_read);
		dec_buffer[size_read] = '\0';

		// Print to stdout
		printf("\t%d: %s\n", ++inc, dec_buffer);
	}

	// Close file
	fclose(file_to_read);
}
