#ifndef VARIANT_H
#define VARIANT_H

#include <string>

struct VariantEntry
{
	VariantEntry(int pos, const std::string & variant);
	int pos;
	std::string variant;
};

struct VariantEntryComparator
{
	bool operator()(const VariantEntry & lhs, const VariantEntry & rhs) const;
};

#endif // VARIANT_H
