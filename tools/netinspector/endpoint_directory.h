//=============================================================================//
//
// The endpoints a file defined, by id, in the form the reports print and filter them
//
//=============================================================================//

#pragma once

#include <map>
#include <string>

#include "netinspector/format.h"

namespace NetInspector
{

class CEndpointDirectory
{
public:
	void Add(EndpointId id, const EndpointEntry &address);

	// "#3 1.2.3.4:27015", or "#3" for an id the file has not defined yet
	std::string Describe(EndpointId id) const;

	// filter is "#3", "3" or "1.2.3.4:27015"; an empty filter matches everything
	bool Matches(EndpointId id, const std::string &filter) const;

private:
	std::map<EndpointId, std::string> m_Endpoints;
};

} // namespace NetInspector
