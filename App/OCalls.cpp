#include "OCalls.h"
#include "Constants.h"

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
	char read_buffer[READ_BUFFER_SIZE + 1] = "";
	uint8_t enc_buffer[READ_BUFFER_SIZE] = "";
	std::string read_line;
	int inc = 0;
	while (std::getline(file_to_read, read_line)) {

		// Encrypt line
		strcpy_s(read_buffer, READ_BUFFER_SIZE, read_line.c_str());
		ecall_encrypt_aes_ctr(global_eid, read_buffer, READ_BUFFER_SIZE, enc_buffer, READ_BUFFER_SIZE);

		// Save to disk
		file_to_write.write((char *)enc_buffer, READ_BUFFER_SIZE);

		memset(read_buffer, 0, READ_BUFFER_SIZE + 1);
		memset(enc_buffer, 0, READ_BUFFER_SIZE);
	}

	// Close file and return init vector (counter)
	file_to_read.close();
	file_to_write.close();
}
