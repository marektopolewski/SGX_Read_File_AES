#ifndef APP_H_
#define APP_H_

#include <string>
#include <vector>
#include <functional>

struct Paramters;
struct Results;
struct Sample;

struct Parameters
{
	std::string reference_genome;
	std::vector<std::string> list_of_files;
	std::pair<int, int> region_of_interest;
	int map_quality_threshold;
	bool return_output;
};

struct Results
{
	std::string status;
	int elapsed_time_ms;
	std::string result;
};

struct Sample
{
	std::string snp;
	double value;
};

using AnalysisCallback = std::function<Results(Parameters)>;

#endif // !APP_H_
