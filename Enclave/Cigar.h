#ifndef CIGAR_H
#define CIGAR_H

#include <string>
#include <vector>

class Cigar
{
public:
	enum class Op {
		Invalid = -1,
		Match,
		Insert,
		Delete,
		SoftClip,
		HardClip
	};

	Cigar(const std::string & cigarStr) {
		int bases = 0;
		for (const char & c : cigarStr) {
			if (c >= 'A' && c <= 'Z') {
				m_entries.emplace_back(charToOp(c), bases);
				bases = 0;
			}
			else if (c >= '0' && c <= '9') {
				bases = bases * 10 + (c - '0');
			}
		}
	}

	using Entries = std::vector<std::pair<Op, int>>;
	const Entries & getEntries() { return m_entries; }

	static Op charToOp(const char & c)
	{
		if (c == 'M')
			return Cigar::Op::Match;
		else if (c == 'I')
			return Cigar::Op::Insert;
		else if (c == 'D')
			return Cigar::Op::Delete;
		else if (c == 'S')
			return Cigar::Op::SoftClip;
		else if (c == 'H')
			return Cigar::Op::HardClip;
		return Cigar::Op::Invalid;
	}

private:
	Entries m_entries;
	bool m_hasVariant;
};

#endif // CIGAR_H
