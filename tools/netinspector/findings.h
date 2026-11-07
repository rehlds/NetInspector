//=============================================================================//
//
// What the health and threats reports found: each finding one kind of thing
// at one endpoint, how often and from when to when, and the command that shows
// the packets behind it. Findings of one kind at one endpoint are kept as one.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>

#include "endpoint_directory.h"
#include "json_writer.h"
#include "netinspector/format.h"
#include "report_clock.h"

namespace NetInspector
{

enum class Severity
{
	Info		= 0,	// odd, with an ordinary explanation at hand
	Medium		= 1,	// heavier than play needs
	High		= 2,	// a known way to hurt a server
	Critical	= 3,	// what an honest client cannot send
};

const char *ToString(Severity severity);

class CFindings
{
public:
	//-----------------------------------------------------------------------------
	// kind names the finding and stays the same for every occurrence; detail
	// is kept from the worst occurrence, the first among equals
	//-----------------------------------------------------------------------------
	void Add(Severity severity, EndpointId endpoint, const std::string &kind, uint64_t time, const std::string &detail);

	bool IsEmpty() const { return m_Findings.empty(); }

	// The worst first; path is the recording, for the command that shows each finding
	void Print(const CEndpointDirectory &endpoints, const CReportClock &clock, const std::string &path) const;
	void Write(const CEndpointDirectory &endpoints, const std::string &path, CJsonWriter &json) const;

private:
	struct Finding
	{
		Severity	severity;
		EndpointId	endpoint;
		std::string	kind;
		std::string	detail;
		uint64_t	first;
		uint64_t	last;
		uint32_t	count;
	};

	std::string NextCommand(const Finding &finding, const CEndpointDirectory &endpoints, const std::string &path) const;

	std::map<std::pair<EndpointId, std::string>, Finding> m_Findings;
};

} // namespace NetInspector
