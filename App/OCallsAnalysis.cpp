#include "OCalls.h"
#include "Constants.h"

#include <fstream>
#include <stdio.h>
#include <string>
#include <vector>

struct VcfFileHandle
{
	std::ifstream * handle;
	bool done = false;
};
static std::vector<VcfFileHandle> vcf_files;

static const char * output_path = "csv/analysis.csv";
static std::ofstream * analysis_file;

void ocall_analysis_add_file(const char * path, int * success)
{
	auto vcf_file = new std::ifstream(GET_DATA_DIR() + path, std::ios::binary);
	if (!vcf_file->is_open()) {
		printf("Fatal error: could not open file - \"%s\"", path);
		*success = 1;
	}
	else
		vcf_files.push_back({ vcf_file });
}

void ocall_analysis_start()
{
	bool outputUpdated = true;
	analysis_file = new std::ofstream(GET_DATA_DIR() + output_path);
	if (!analysis_file->is_open()) {
		printf("Fatal error: could not open the output file - \"%s\"", output_path);
		return;
	}

	// Read files sequentially in batches until no lines remain
	std::vector<int> poss(vcf_files.size(), 0);
	while (outputUpdated) {
		outputUpdated = false;
		for (int it = 0; it < vcf_files.size(); ++it) {

			// If nothing to read, go to next file
			auto & vcf_file = vcf_files[it];
			if (vcf_file.done)
				continue;

			// Find file in the handle list
			if (!vcf_file.handle || !vcf_file.handle->is_open()) {
				printf("Fatal error: could not find file - \"%d\"", it);
				return;
			}

			// Read and analyse a batch of a file
			char read_buffer[READ_BUFFER_SIZE_S] = "";
			int batch_it = 0;
			while (batch_it < READ_BATCH_SIZE) {

				// Read a line (each is READ_BUFFER_SIZE bytes long)
				if (!vcf_file.handle->read(read_buffer, READ_BUFFER_SIZE_S)) {
					vcf_file.done = true;
					break;
				}

				// Decrypt and analyse the line
				int pause = 0;
				ecall_analysis_read_line(global_eid, &it, (uint8_t *)read_buffer, READ_BUFFER_SIZE_S, &pause);
				memset(read_buffer, 0, READ_BUFFER_SIZE_S);

				// Pause reading current file if too far ahead of global position
				if (pause == 1)
					break;
				++batch_it;
			}
			outputUpdated = outputUpdated || !vcf_file.done;
		}
		ecall_analysis_flush_output(global_eid, new int(0));
	}

	// Flush remaining variants
	ecall_analysis_flush_output(global_eid, new int(1));
	analysis_file->close();
}

void ocall_analysis_flush_output(const char * output)
{
	*analysis_file << output;
}

void ocall_analysis_remove_files()
{
	for (auto & entry : vcf_files)
		entry.handle->close();
	vcf_files.clear();
}

std::string ocall_return_output()
{
	std::ifstream output_file(GET_DATA_DIR() + output_path);
	if (!output_file.is_open())
		return "Could not read the output file";

	std::string return_output;
	output_file.seekg(0, std::ios::end);
	return_output.reserve(output_file.tellg());
	output_file.seekg(0, std::ios::beg);
	return_output.assign(std::istreambuf_iterator<char>(output_file),
						 std::istreambuf_iterator<char>());
	return return_output;
}
