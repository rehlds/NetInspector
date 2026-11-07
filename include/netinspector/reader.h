//=============================================================================//
//
// Reads a .gcap file entry by entry. A file whose writer was killed ends inside
// an entry; the reader stops before it and says so.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <cstdio>
#include <vector>

#include "netinspector/format.h"

namespace NetInspector
{

class CReader
{
public:
	CReader() = default;
	~CReader();

	CReader(const CReader &) = delete;
	CReader &operator=(const CReader &) = delete;

	// False if the file is missing or is not a .gcap file
	bool Open(const char *path);
	void Close();

	const FileHeader &GetHeader() const { return m_Header; }

	//-----------------------------------------------------------------------------
	// The next entry. Its body stays valid until the next call and is followed by
	// a zero byte, so text bodies read as strings. False at the end of the file.
	//-----------------------------------------------------------------------------
	bool Next(EntryHeader &header, const uint8_t *&body);

	// The last Next stopped at an entry cut short
	bool IsTruncated() const { return m_Truncated; }

	// Back to the first entry
	bool Rewind();

private:
	std::FILE				*m_File = nullptr;
	FileHeader				m_Header = {};
	std::vector<uint8_t>	m_Body;
	bool					m_Truncated = false;
};

} // namespace NetInspector
