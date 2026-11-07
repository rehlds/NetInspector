//=============================================================================//
//
// Entry times as the reports print them: seconds since the recording started, and the wall
// time that lines up with the game's or the server's own logs
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <string>

#include "netinspector/format.h"

namespace NetInspector
{

class CReportClock
{
public:
	explicit CReportClock(const FileHeader &header) : m_StartUtcMicroseconds(header.startUtcMicroseconds) {}

	// "  12.345678"
	std::string Relative(uint64_t time) const;

	// "16:58:02.165", local time
	std::string LocalTime(uint64_t time) const;

	// "2026-11-07 09:58:02.165"
	std::string UtcDateTime(uint64_t time) const;

private:
	std::string Format(uint64_t time, bool utc, bool withDate) const;

	uint64_t m_StartUtcMicroseconds;
};

} // namespace NetInspector
