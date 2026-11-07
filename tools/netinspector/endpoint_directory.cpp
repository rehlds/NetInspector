//=============================================================================//
//
// Endpoint names for the reports
//
//=============================================================================//

#include "endpoint_directory.h"

#include <cstdio>
#include <cstdlib>

namespace NetInspector
{

void CEndpointDirectory::Add(EndpointId id, const EndpointEntry &address)
{
	char text[32];
	std::snprintf(text, sizeof(text), "%u.%u.%u.%u:%u", address.ip[0], address.ip[1], address.ip[2], address.ip[3], address.port);
	m_Endpoints[id] = text;
}

std::string CEndpointDirectory::Describe(EndpointId id) const
{
	std::string text = "#" + std::to_string(id.value);

	const std::map<EndpointId, std::string>::const_iterator known = m_Endpoints.find(id);
	if (known != m_Endpoints.end())
		text += " " + known->second;

	return text;
}

bool CEndpointDirectory::Matches(EndpointId id, const std::string &filter) const
{
	if (filter.empty())
		return true;

	const char *number = filter[0] == '#' ? filter.c_str() + 1 : filter.c_str();
	char *end = nullptr;
	const unsigned long value = std::strtoul(number, &end, 10);
	if (end != number && *end == '\0')
		return value == id.value;

	const std::map<EndpointId, std::string>::const_iterator known = m_Endpoints.find(id);
	return known != m_Endpoints.end() && known->second == filter;
}

} // namespace NetInspector
