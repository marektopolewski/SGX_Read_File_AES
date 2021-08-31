#include "OCalls.h"

#include "Cigar.h"
#include "ReferenceHandler.h"

#include <cassert>
#include <fstream>

static std::string ref_path = "<none>";
static std::ofstream * vcf_file;

void ocall_varcall_set_ref_file(const char * path)
{
	ref_path = path;
}

void ocall_varcall_call_sam_file(const char * path, int * mapq)
{
	// Create the reference handler
	ReferenceHandler ref_handler(GET_DATA_DIR() + ref_path);
	if (!ref_handler.valid()) {
		printf("Fatal error: Could not open the refernce genome: \"%s\"\n", path);
		return;
	}

	// Create the sequence file handle
	std::ifstream sam_file(GET_DATA_DIR() + path + ".enc", std::ios::binary);
	if (!sam_file.is_open()) {
		printf("Fatal error: Could not open the SAM file: \"%s.enc\"\n", path);
		return;
	}

	// Create the variant caller file handle
	auto vcf_path = MAKE_SUB_PATH(path, "vcf");
	vcf_file = new std::ofstream(GET_DATA_DIR() + vcf_path);
	if (!vcf_file->is_open()) {
		printf("Fatal error: Could not open the output file: \"%s\"\n", vcf_path.c_str());
		return;
	}

	// Iteratively call variants scanning through FASTA and SAM in parallel
	char read_buffer[READ_BUFFER_SIZE_L + 1];
	while (sam_file.read(read_buffer, READ_BUFFER_SIZE_L)) {

		// Decrypt line and return read position
		int pos, ignore;
		ecall_varcall_get_pos(global_eid, (uint8_t *)read_buffer, READ_BUFFER_SIZE_L, mapq, &pos, &ignore);
		memset(read_buffer, 0, READ_BUFFER_SIZE_L);

		// Ignore reads below MAPQ threshold or has missing values
		if (ignore == 1)
			continue;

		// Call variant
		ref_handler.seek(pos);
		ecall_varcall_find_mutations(global_eid, ref_handler.getPrefix().c_str(), ref_handler.getSequence().c_str());
	}

	// Flush the remaining variants
	ecall_varcall_flush_output(global_eid, new int(1));

	sam_file.close();
	vcf_file->close();
}

void ocall_varcall_flush_output(const char * output)
{
	*vcf_file << output;
}
