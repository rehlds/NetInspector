//=============================================================================//
//
// Reading .gcap files
//
//=============================================================================//

// The standard fopen; fopen_s is MSVC's alone
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "netinspector/reader.h"

#include <cstring>

namespace NetInspector
{

CReader::~CReader()
{
	Close();
}

bool CReader::Open(const char *path)
{
	Close();

	m_File = std::fopen(path, "rb");
	if (!m_File)
		return false;

	// The fields known here come first; a newer writer's longer header is skipped past
	const bool valid = std::fread(&m_Header, 1, sizeof(m_Header), m_File) == sizeof(m_Header)
		&& std::memcmp(m_Header.magic, FILE_MAGIC, sizeof(FILE_MAGIC)) == 0
		&& m_Header.headerSize >= sizeof(m_Header)
		&& Rewind();

	if (!valid)
	{
		Close();
		return false;
	}

	m_Header.application[sizeof(m_Header.application) - 1] = '\0';
	return true;
}

void CReader::Close()
{
	if (!m_File)
		return;

	std::fclose(m_File);
	m_File = nullptr;
}

bool CReader::Rewind()
{
	m_Truncated = false;
	return m_File && std::fseek(m_File, long(m_Header.headerSize), SEEK_SET) == 0;
}

bool CReader::Next(EntryHeader &header, const uint8_t *&body)
{
	if (!m_File)
		return false;

	const size_t headerRead = std::fread(&header, 1, sizeof(header), m_File);
	if (headerRead != sizeof(header))
	{
		m_Truncated = headerRead != 0;
		return false;
	}

	if (header.length > MAX_ENTRY_BODY)
	{
		m_Truncated = true;
		return false;
	}

	m_Body.resize(header.length + 1);
	m_Body[header.length] = 0;

	if (header.length && std::fread(m_Body.data(), 1, header.length, m_File) != header.length)
	{
		m_Truncated = true;
		return false;
	}

	body = m_Body.data();
	return true;
}

} // namespace NetInspector
