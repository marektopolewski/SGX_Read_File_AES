#include "Enclave_t.h"
#include "sgx_tseal.h"

#include "Constants.h"
#include "EnclaveDecrypt.h"
#include "Variant.h"

#include <map>
#include <string>
#include <vector>

struct FileMetadata {
	FileMetadata() {
		key = (uint8_t *)malloc(SGX_AESCTR_KEY_SIZE);
		ctr = (uint8_t *)malloc(COUNTER_BLOCK_SIZE);
	}
	uint8_t * key;
	uint8_t * ctr;
};
static std::vector<FileMetadata> file_metadata;

static int region_of_interest_begin = 0;
static int region_of_interest_end = INT_MAX;
static int map_quality_threshold = 0;

static int min_genome_position = INT_MAX;
static std::map<VariantEntry, size_t, VariantEntryComparator> variant_counts;

void ecall_analysis_set_params(int * roi_begin, int * roi_end)
{
	region_of_interest_begin = *roi_begin;
	region_of_interest_end = *roi_end;
}

void ecall_analysis_add_file(uint8_t * seal_key, size_t seal_len,
	const char * path,
	uint8_t * ctr, size_t ctr_len)
{
	assert(SGX_AESCTR_KEY_SIZE + sizeof(sgx_sealed_data_t) == seal_len);
	assert(COUNTER_BLOCK_SIZE == ctr_len);

	file_metadata.push_back({});
	memcpy(file_metadata.back().ctr, ctr, COUNTER_BLOCK_SIZE);

	uint32_t keyLen = SGX_AESCTR_KEY_SIZE;
	auto seal_status = sgx_unseal_data((sgx_sealed_data_t *)seal_key, NULL, NULL, file_metadata.back().key, &keyLen);
	assert(seal_status == SGX_SUCCESS);

	int open_status = 0;
	ocall_analysis_add_file(path, &open_status);
	assert(open_status == 0);
}

void ecall_analysis_start()
{
	ocall_analysis_start();
	ocall_analysis_remove_files();
}

void ecall_analysis_flush_output(int * flush_all)
{
	if (*flush_all == 1)
		min_genome_position = INT_MAX;

	std::string output = "";
	auto it = variant_counts.begin();
	for (; it != variant_counts.end(); ++it) {
		// Stop if reached a position that may overlap
		if (it->first.pos >= min_genome_position)
			break;

		// Extend the string to flush
		output += std::to_string(it->first.pos);
		output += ",";
		output += it->first.variant;
		output += ",";
		output += std::to_string(it->second);
		output += "\r\n";

		// Flush string early if too large
		if (output.length() > MAX_FLUSH_STRING_SIZE) {
			ocall_analysis_flush_output(output.c_str());
			output.clear();
		}
	}

	// Remove flushed variants from the map
	variant_counts.erase(variant_counts.begin(), it);
	min_genome_position = INT_MAX;

	ocall_analysis_flush_output(output.c_str());
}

void ecall_analysis_read_line(int * id, uint8_t * cryptMessage, size_t crypt_len, int * pause)
{
	// Decrypt line
	auto plainMessage = (char *)malloc(crypt_len + 1);
	ecall_decrypt_aes_ctr(file_metadata[*id].key, file_metadata[*id].ctr,
						  cryptMessage, crypt_len, plainMessage, crypt_len);

	// Analyse line
	auto variant_str = std::string(plainMessage);
	auto delim_split = variant_str.find('\t', 0);
	assert(delim_split != std::string::npos);
	auto position = std::stoi(variant_str.substr(0, delim_split));
	auto variant = variant_str.substr(delim_split + 1, variant_str.length() - delim_split - 1);
	if (min_genome_position > position)
		min_genome_position = position;

	// Update variant statistics
	if (region_of_interest_begin <= position && position <= region_of_interest_end)
		++variant_counts[{ position, variant }];

	// If the read is too far ahead of other files, request pause on this file
	if (position - variant_counts.cbegin()->first.pos > MAX_POSITION_DISTANCE)
		*pause = 1;
}

void ecall_remove_analysis_files()
{
	ocall_analysis_remove_files();
	file_metadata.clear();
}
