#include "OCalls.h"

#include "Constants.h"

#include <cassert>
#include <fstream>
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

void ocall_encrypt_file(const char * path)
{
	// Define size of the encrypted block
	size_t block_size;
	auto suffix = std::string(path).substr(strlen(path) - 3, 3);
	if (suffix == "sam")
		block_size = READ_BUFFER_SIZE_L;
	else if (suffix == "vcf")
		block_size = READ_BUFFER_SIZE_S;
	else
		assert(false && "Unsupported file format for encryption: " && suffix.c_str());

	// Open files
	std::ifstream file_to_read(GET_DATA_DIR() + path);
	if (!file_to_read.is_open()) {
		printf("Fatal error: could not open file - \"%s\"", path);
		return;
	}
	auto enc_path = std::string(path) + ".enc";
	std::ofstream file_to_write(GET_DATA_DIR() + enc_path, std::ios::binary);
	if (!file_to_write.is_open()) {
		printf("Fatal error: could not open file - \"%s\"", enc_path.c_str());
		file_to_read.close();
		return;
	}

	// Read and encrypt file
	auto read_block = (char *)malloc(block_size + 1);
	auto enc_block = (uint8_t *)malloc(block_size);
	std::string read_line;
	int inc = 0;
	while (std::getline(file_to_read, read_line)) {

		// Encrypt line
		strcpy_s(read_block, block_size, read_line.c_str());

		char plain_buffer[MAX_BUFFER_SIZE + 1] = { 0 };
		uint8_t crypt_buffer[MAX_BUFFER_SIZE] = { 0 };
		int bytes_read = 0;
		while (bytes_read < block_size) {
			auto bytes_to_read = block_size - bytes_read < MAX_BUFFER_SIZE ? block_size - bytes_read : MAX_BUFFER_SIZE;
			memcpy(plain_buffer, read_block + bytes_read, bytes_to_read);
			ecall_encrypt_aes_ctr(global_eid, plain_buffer, bytes_to_read, crypt_buffer, bytes_to_read);
			memcpy(enc_block + bytes_read, crypt_buffer, bytes_to_read);
			bytes_read += bytes_to_read;
		}
		// Save to disk
		file_to_write.write((char *)enc_block, block_size);

		memset(read_block, 0, block_size + 1);
		memset(enc_block, 0, block_size);
	}

	// Close file and return init vector (counter)
	file_to_read.close();
	file_to_write.close();
}
