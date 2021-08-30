#include "OCalls.h"

#include "Cigar.h"
#include "ReferenceHandler.h"
#include "SequenceHandler.h"
#include "VariantHandler.h"

#include <cassert>
#include <fstream>

static std::string ref_path = "<none>";

void ocalls_sequence_set_ref_file(const char * path)
{
	ref_path = path;
}

void ocalls_sequence_call_sam_file(const char * path, int * mapq)
{
	// Create the reference handler
	ReferenceHandler ref_handler(GET_DATA_DIR() + ref_path);
	if (!ref_handler.valid()) {
		printf("Fatal error: Could not open the refernce genome: \"%s\"\n", path);
		return;
	}

	// Create the sequence handler
	SequenceHandler seq_handler(GET_DATA_DIR() + path);
	if (!seq_handler.valid()) {
		printf("Fatal error: Could not open the SAM file: \"%s\"\n", path);
		return;
	}

	// Create the variant caller
	auto vcf_path = MAKE_SUB_PATH(path, "vcf");
	VariantHandler var_handler(GET_DATA_DIR() + vcf_path);
	if (!seq_handler.valid()) {
		printf("Fatal error: Could not open the output file: \"%s\"\n", vcf_path.c_str());
		return;
	}

	// Iteratively call variants scanning through FASTA and SAM in parallel
	while (seq_handler.next()) {

		// Ignore reads below MAPQ threshold
		if (seq_handler.getMapQuality() < *mapq)
			continue;

		// Call variant
		Cigar cigar{ seq_handler.getCigar() };
		ref_handler.seek(seq_handler.getPosition());
		var_handler.call(seq_handler.getPosition(), ref_handler.getPrefix(), ref_handler.getSequence(),
					      seq_handler.getSequence(), cigar.getEntries());
	}
}
