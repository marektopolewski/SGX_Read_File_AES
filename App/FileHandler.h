#ifndef FILE_HANDLER_H
#define FILE_HANDLER_H

#include <fstream>
#include <string>

class InFileHandler
{
public:
	InFileHandler(const std::string & path, bool binary = false)
		: m_file(path, binary ? std::ios::binary|std::ios::out : std::ios::in) {}
	~InFileHandler() { m_file.close(); }
	bool valid() { return m_file.is_open(); }

protected:
	std::ifstream m_file;
};

class OutFileHandler
{
public:
	OutFileHandler(const std::string & path, bool binary = false)
		: m_file(path, binary ? std::ios::binary|std::ios::out : std::ios::out) {}
	~OutFileHandler() { m_file.close(); }
	bool valid() { return m_file.is_open(); }

protected:
	std::ofstream m_file;
};

#endif // FILE_HANDLER_H
