//=============================================================================//
//
// The ids of a recording's endpoints. Each endpoint is written once as an
// Endpoint entry; the entries after it refer to its id.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <map>

#include "netinspector/format.h"

namespace NetInspector
{

class CEndpointRegistry
{
public:
	void Clear();

	// The endpoint's id; added tells the caller to write its Endpoint entry first
	EndpointId Register(const Endpoint &endpoint, bool &added);

private:
	static uint64_t MakeKey(const Endpoint &endpoint);

	std::map<uint64_t, EndpointId> m_Ids;
	uint32_t m_NextId = 1;
};

} // namespace NetInspector
