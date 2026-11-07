//=============================================================================//
//
// Time formatting for the reports
//
//=============================================================================//

#include "report_clock.h"

#include <cstdio>
#include <ctime>

namespace NetInspector
{

std::string CReportClock::Relative(uint64_t time) const
{
	char text[32];
	std::snprintf(text, sizeof(text), "%11.6f", double(time) / 1000000.0);
	return text;
}

std::string CReportClock::LocalTime(uint64_t time) const
{
	return Format(time, false, false);
}

std::string CReportClock::UtcDateTime(uint64_t time) const
{
	return Format(time, true, true);
}

std::string CReportClock::Format(uint64_t time, bool utc, bool withDate) const
{
	const uint64_t wall = m_StartUtcMicroseconds + time;
	const std::time_t seconds = std::time_t(wall / 1000000);
	const unsigned milliseconds = unsigned(wall / 1000 % 1000);

	std::tm parts = {};
#ifdef _WIN32
	if (utc)
		gmtime_s(&parts, &seconds);
	else
		localtime_s(&parts, &seconds);
#else
	if (utc)
		gmtime_r(&seconds, &parts);
	else
		localtime_r(&seconds, &parts);
#endif

	char text[48];
	if (withDate)
	{
		std::snprintf(text, sizeof(text), "%04d-%02d-%02d %02d:%02d:%02d.%03u", parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday,
			parts.tm_hour, parts.tm_min, parts.tm_sec, milliseconds);
	}
	else
	{
		std::snprintf(text, sizeof(text), "%02d:%02d:%02d.%03u", parts.tm_hour, parts.tm_min, parts.tm_sec, milliseconds);
	}

	return text;
}

} // namespace NetInspector
