//=============================================================================//
//
// The .gcap file being written: the header first, then whole entries. A write
// the disk refuses marks the file failed and every later write is skipped, so
// the file never holds half an entry in the middle.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "netinspector/format.h"

namespace NetInspector
{

class COutputFile
{
public:
	COutputFile() = default;
	~COutputFile();

	COutputFile(const COutputFile &) = delete;
	COutputFile &operator=(const COutputFile &) = delete;

	bool Open(const char *path, const FileHeader &header);
	void Close();

	// The body is head followed by tail, either may be empty; header.length is set here
	bool Write(const EntryHeader &header, const void *head, size_t headLength, const void *tail, size_t tailLength);
	void Flush();

	uint64_t GetBytesWritten() const { return m_BytesWritten; }
	bool HasFailed() const { return m_Failed; }

private:
	bool WriteBytes(const void *data, size_t length);

	std::FILE	*m_File = nullptr;
	uint64_t	m_BytesWritten = 0;
	bool		m_Failed = false;
};

} // namespace NetInspector
