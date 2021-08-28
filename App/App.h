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
	std::vector<std::string> listOfFiles;
	double mapQualityThreshold;
	size_t batchSize;
};

struct Results
{
	std::string status;
	std::vector<Sample> samples;
};

struct Sample
{
	std::string snp;
	double value;
};

using AnalysisCallback = std::function<Results(Parameters)>;

#endif // !APP_H_
