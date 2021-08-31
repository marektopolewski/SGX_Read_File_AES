#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tseal.h"

#include "Cigar.h"
#include "Constants.h"
#include "EnclaveDecrypt.h"
#include "Variant.h"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#define SEQ_READ_SIZE 82

#define SAM_COLUMN_POSITION 3
#define SAM_COLUMN_MAPQ     4
#define SAM_COLUMN_CIGAR    5
#define SAM_COLUMN_SEQUENCE 9

#define WILDCARD_NUCLEOTIDE 'N'

#define VARIANT_BATCH_SIZE 100


static uint8_t sam_key[SGX_AESCTR_KEY_SIZE] = { 0 };
static uint8_t sam_ctr[COUNTER_BLOCK_SIZE] = { 0 };
static uint8_t vcf_key[SGX_AESCTR_KEY_SIZE] = { 0 };
static uint8_t vcf_ctr[COUNTER_BLOCK_SIZE] = { 0 };

static int m_iterSinceFlush = 0;
static int m_pos;
static int m_mapq;
static Cigar * m_cigar;
static std::string m_sequence;

static std::set<VariantEntry, VariantEntryComparator> m_set;

void _save(size_t pos, const std::string & ref, const std::string & alt)
{
	m_set.emplace(pos, ref + "," + alt);
}

void _encrypt(const char * plain_block, uint8_t * crypt_block)
{
	char plain_buffer[MAX_BUFFER_SIZE + 1] = { 0 };
	uint8_t crypt_buffer[MAX_BUFFER_SIZE] = { 0 };
	int bytes_read = 0;
	while (bytes_read < ENC_BLOCK_SIZE_S) {
		auto bytes_to_read = ENC_BLOCK_SIZE_S - bytes_read < MAX_BUFFER_SIZE
						   ? ENC_BLOCK_SIZE_S - bytes_read : MAX_BUFFER_SIZE;
		memcpy(plain_buffer, plain_block + bytes_read, bytes_to_read);
		sgx_aes_ctr_encrypt((sgx_aes_ctr_128bit_key_t *)vcf_key, (uint8_t *)plain_buffer,
							bytes_to_read, vcf_ctr, COUNTER_BLOCK_INC, crypt_buffer);
		memcpy(crypt_block + bytes_read, crypt_buffer, bytes_to_read);
		bytes_read += bytes_to_read;
	}
}


void ecall_varcall_load_metadata(uint8_t * in_seal_key, size_t in_seal_len,
								 uint8_t * in_ctr, size_t in_ctr_len,
								 uint8_t * out_seal_key, size_t out_seal_len,
								 uint8_t * out_ctr, size_t out_ctr_len)
{
	// Unseal SAM key and counter
	uint32_t key_len = SGX_AESCTR_KEY_SIZE;
	auto unseal_status = sgx_unseal_data((sgx_sealed_data_t *)in_seal_key, NULL, NULL, sam_key, &key_len);
	assert(unseal_status == SGX_SUCCESS && "Could not unseal SAM key");
	memcpy(sam_ctr, in_ctr, COUNTER_BLOCK_SIZE);

	// Generate VCF key and counter
	sgx_read_rand(vcf_key, SGX_AESCTR_KEY_SIZE);
	auto seal_status = sgx_seal_data(0, NULL, SGX_AESCTR_KEY_SIZE, vcf_key,
								     out_seal_len, (sgx_sealed_data_t *)out_seal_key);
	assert(seal_status == SGX_SUCCESS && "Could not seal VCF key");

	sgx_read_rand(vcf_ctr, COUNTER_BLOCK_SIZE);
	memcpy(out_ctr, vcf_ctr, COUNTER_BLOCK_SIZE);
}

void ecall_varcall_get_pos(uint8_t * crypt, size_t crypt_len, int * mapq, int * pos, int * ignore)
{
	// Reset values
	m_pos = -1;
	m_mapq = -1;
	delete m_cigar;
	m_sequence = "";

	// Decrypt line
	char plain[ENC_BLOCK_SIZE_L + 1] = { 0 };
	char plain_buffer[MAX_BUFFER_SIZE + 1] = { 0 };
	uint8_t crypt_buffer[MAX_BUFFER_SIZE] = { 0 };
	int bytes_read = 0;
	while (bytes_read < crypt_len) {
		auto bytes_to_read = crypt_len - bytes_read < MAX_BUFFER_SIZE ? crypt_len - bytes_read : MAX_BUFFER_SIZE;
		memcpy(crypt_buffer, crypt + bytes_read, bytes_to_read);
		ecall_decrypt_aes_ctr(sam_key, sam_ctr, crypt_buffer, bytes_to_read, plain_buffer, bytes_to_read);
		memcpy(plain + bytes_read, plain_buffer, bytes_to_read);
		bytes_read += bytes_to_read;
	}

	// Parse line
	auto line = std::string(plain);
	int column = 0, currentPos = 0;
	int entryPos = line.find('\t');
	do {
		switch (column) {
		case SAM_COLUMN_POSITION:
			m_pos = std::stoi(line.substr(currentPos, entryPos - currentPos));
			*pos = m_pos;
			break;
		case SAM_COLUMN_MAPQ:
			m_mapq = std::stoi(line.substr(currentPos, entryPos - currentPos));
			*ignore = m_mapq < *mapq ? 1 : 0;
			break;
		case SAM_COLUMN_CIGAR:
			m_cigar = new Cigar{ line.substr(currentPos, entryPos - currentPos) };
			break;
		case SAM_COLUMN_SEQUENCE:
			m_sequence = line.substr(currentPos, entryPos - currentPos);
			break;
		default:
			break;
		}
		currentPos = entryPos + 1;
		entryPos = line.find('\t', currentPos);
		++column;
	} while (entryPos != -1 && column <= SAM_COLUMN_SEQUENCE);

	if (m_pos == -1 || m_mapq == -1 || !m_cigar || m_sequence.empty())
		*ignore = true;
}

void ecall_varcall_find_mutations(const char * prefix, const char * ref_seq)
{
	auto ref = std::string(ref_seq);
	auto & alt = m_sequence;
	int ref_pos = 0, alt_pos = 0;
	for (const auto & cigarEntry : m_cigar->getEntries()) {
		auto basesLeft = std::min(SEQ_READ_SIZE - std::max(ref_pos, alt_pos), cigarEntry.second);
		switch (cigarEntry.first) {
		case Cigar::Op::Match:
			for (int i = 0; i < basesLeft; ++i) {
				if (ref[ref_pos + i] == alt[alt_pos + i] || ref[ref_pos + i] == WILDCARD_NUCLEOTIDE
					|| alt[alt_pos + i] == WILDCARD_NUCLEOTIDE)
					continue;
				_save(m_pos + ref_pos + i, ref.substr(ref_pos + i, 1), alt.substr(alt_pos + i, 1));
			}
			ref_pos += basesLeft;
			alt_pos += basesLeft;
			break;
		case Cigar::Op::Insert:
			if (ref_pos == 0)
				_save(m_pos + ref_pos, prefix, prefix + alt.substr(alt_pos, basesLeft));
			else
				_save(m_pos + ref_pos, ref.substr(ref_pos - 1, 1), alt.substr(alt_pos - 1, basesLeft + 1));
			alt_pos += basesLeft;
			break;
		case Cigar::Op::Delete:
			if (ref_pos == 0)
				_save(m_pos + ref_pos, prefix + ref.substr(ref_pos, basesLeft), prefix);
			else
				_save(m_pos + ref_pos, ref.substr(ref_pos - 1, basesLeft + 1), alt.substr(alt_pos - 1, 1));
			ref_pos += basesLeft;
			break;
		case Cigar::Op::SoftClip:
			alt_pos += basesLeft;
			break;
		case Cigar::Op::HardClip:
			break;

		default:
			assert(false && "Unhandled CIGAR operation");
			break;
		}
	}

	// Check if should flush to disk
	if (++m_iterSinceFlush >= VARIANT_BATCH_SIZE)
		ecall_varcall_flush_output(new int(0));
}

void ecall_varcall_flush_output(int * flush_all)
{
	// Build the output to flush in a string
	auto entryIt = m_set.begin();
	for (; entryIt != m_set.end(); ++entryIt) {
		if (entryIt->pos + SEQ_READ_SIZE >= m_pos && *flush_all != 1)
			break;
		auto output = std::to_string(entryIt->pos) + "," + entryIt->variant;

		// Encrypt line
		char plain_block[ENC_BLOCK_SIZE_S + 1] = { 0 };
		uint8_t crypt_block[ENC_BLOCK_SIZE_S] = { 0 };
		strncpy(plain_block, output.c_str(), ENC_BLOCK_SIZE_S);
		_encrypt(plain_block, crypt_block);

		// Write line
		ocall_varcall_flush_output((char *)crypt_block, ENC_BLOCK_SIZE_S);
	}

	// Flush and remove selected SNPs
	m_set.erase(m_set.begin(), entryIt);
	m_iterSinceFlush = 0;
}
