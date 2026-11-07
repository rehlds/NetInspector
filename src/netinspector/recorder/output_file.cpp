//=============================================================================//
//
// Writing the .gcap file
//
//=============================================================================//

// The standard fopen; fopen_s is MSVC's alone
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "netinspector/recorder/output_file.h"

namespace NetInspector
{

COutputFile::~COutputFile()
{
	Close();
}

bool COutputFile::Open(const char *path, const FileHeader &header)
{
	Close();

	m_File = std::fopen(path, "wb");
	if (!m_File)
		return false;

	m_BytesWritten = 0;
	m_Failed = false;

	if (!WriteBytes(&header, sizeof(header)))
	{
		Close();
		return false;
	}

	Flush();
	return true;
}

void COutputFile::Close()
{
	if (!m_File)
		return;

	std::fclose(m_File);
	m_File = nullptr;
}

bool COutputFile::Write(const EntryHeader &header, const void *head, size_t headLength, const void *tail, size_t tailLength)
{
	if (!m_File || m_Failed)
		return false;

	EntryHeader written = header;
	written.length = uint32_t(headLength + tailLength);

	return WriteBytes(&written, sizeof(written))
		&& (headLength == 0 || WriteBytes(head, headLength))
		&& (tailLength == 0 || WriteBytes(tail, tailLength));
}

void COutputFile::Flush()
{
	if (m_File)
		std::fflush(m_File);
}

bool COutputFile::WriteBytes(const void *data, size_t length)
{
	if (std::fwrite(data, 1, length, m_File) != length)
	{
		m_Failed = true;
		return false;
	}

	m_BytesWritten += length;
	return true;
}

} // namespace NetInspector
