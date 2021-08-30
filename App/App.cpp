#include "App.h"
#include "Constants.h"
#include "ErrorSignal.h"
#include "Server.h"
#include "OCalls.h"

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_uswitchless.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <exception>

sgx_enclave_id_t global_eid = 0;

int initialize_enclave()
{
	sgx_launch_token_t token = { 0 };
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;

	sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
	us_config.num_uworkers = 2;
	us_config.num_tworkers = 2;
	const void* enclave_ex_p[32] = { 0 };
	enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void *)&us_config;

	ret = sgx_create_enclave_ex(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated,
		&global_eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
	// ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		return -1;
	}
	return 0;
}

int destroy_enclave()
{
	sgx_destroy_enclave(global_eid);
	return 0;
}

void generate_encryption_key(uint8_t * key, size_t seal_len)
{
	auto ret = ecall_gen_key(global_eid, key, seal_len);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		getchar();
		throw std::exception("Could not seal AES key");
	}
}

void generate_init_vector(uint8_t * iv)
{
	auto ret = ecall_gen_ctr(global_eid, iv, SGX_AESCTR_CTR_SIZE);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		getchar();
		throw std::exception("Could not generate AES counter");
	}
}

void add_vcf_file(const std::string & name, uint8_t * key, size_t seal_len, uint8_t * ctr)
{
	auto add_status = ecall_analysis_add_file(global_eid, key, seal_len, (name + ".enc").c_str(),
											  ctr, SGX_AESCTR_CTR_SIZE);
	if (add_status != SGX_SUCCESS) {
		ErrorSignal::print_error_message(add_status);
		getchar();
		throw std::exception("Could not open a VCF file");
	}
}

Results run_gwas(Parameters params) 
{
	// Create the enclave
	if (initialize_enclave() < 0) {
		printf("Enter a character before exit ...\n");
		getchar();
		throw std::exception("Could not init enclave");
	}
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	printf("Enclave started.\n");

	// Get size of AES key when sealed
	size_t seal_len;
	ret = ecall_get_seal_size(global_eid, SGX_AESCTR_KEY_SIZE, &seal_len);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		getchar();
		throw std::exception("Could not calculate sealed AES key size");
	}

	///////////////////////////////////// SAM //////////////////////////////////////////
	
	// Call variants on each SAM file against the reference FASTA file
	printf("Calling variants on SAM file(s)...\n");
	ocalls_sequence_set_ref_file(params.reference_genome.c_str());
	for (const auto & sam_path : params.list_of_files) {
		printf("  Calling %s ...", sam_path.c_str());
		ocalls_sequence_call_sam_file(sam_path.c_str(), &params.map_quality_threshold);
		printf("done.\n");
	}
	printf("done.\n\n");

	// Encrypt input files
	printf("Encrypting VCF file(s)...\n");
	std::vector<uint8_t *> keys;
	std::vector<uint8_t *> ivs;

	for (const auto & sam_path : params.list_of_files) {

		auto vcf_path = MAKE_SUB_PATH(sam_path.c_str(), "vcf");
		printf("  Encrpyting %s ... ", vcf_path.c_str());

		// Generate AES key and seal it
		auto key = (uint8_t *)malloc(seal_len);
		generate_encryption_key(key, seal_len);
		keys.push_back(key);

		// Generate AES initialisation vector
		auto iv = (uint8_t *)malloc(SGX_AESCTR_CTR_SIZE);
		generate_init_vector(iv);
		ivs.push_back(iv);

		// Encrypt file using generated parameters
		ret = ecall_encrypt(global_eid, key, seal_len, vcf_path.c_str(), iv, SGX_AESCTR_CTR_SIZE);
		if (ret != SGX_SUCCESS) {
			ErrorSignal::print_error_message(ret);
			getchar();
			throw std::exception("Could not encrypt data");
		}
		printf("done.\n");
	}
	printf("done.\n\n");


	///////////////////////////////////// VCF //////////////////////////////////////////

	// Transfer analysis parameters into the enclave
	printf("Setting parameters for analysis...\n");
	ret = ecall_analysis_set_params(global_eid, &params.region_of_interest.first,
									&params.region_of_interest.second);
	if (ret != SGX_SUCCESS) {
		ErrorSignal::print_error_message(ret);
		getchar();
		throw std::exception("Could not set analysis parameters");
	}
	printf("done.\n\n");

	// Open all reuqired files for the analysis
	printf("Opening VCF file(s) for analysis...\n");
	for (int it = 0; it < params.list_of_files.size(); ++it) {
		add_vcf_file(MAKE_SUB_PATH(params.list_of_files[it].c_str(), "vcf"), keys[it], seal_len, ivs[it]);
	}
	printf("done.\n\n");

	// Perform the analysis
	printf("Analysing VCF file(s)...\n");
	ecall_analysis_start(global_eid);
	printf("done.\n\n");

	// Destroy the enclave
	destroy_enclave();
	printf("Enclave stopped.\n");

	// Read output into memory if required
	return {
		"success",
		params.return_output ? ocall_return_output()
			: "Results path: \"" + GET_DATA_DIR() + "data/csv/analysis.csv\""
	};
}

int SGX_CDECL main(int argc, char *argv[])
{
	try {
		GwasServer server(&run_gwas);
		server.open().wait();
		printf("Press any key to exit\n");
		getchar();
		server.close().wait();
	}
	catch (const std::exception & e) {
		printf("Error occurred in the main loop: %s", e.what());
	}
	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
