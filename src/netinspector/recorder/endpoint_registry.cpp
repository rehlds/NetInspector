//=============================================================================//
//
// Endpoint ids of the recording being written
//
//=============================================================================//

#include "netinspector/recorder/endpoint_registry.h"

namespace NetInspector
{

void CEndpointRegistry::Clear()
{
	m_Ids.clear();
	m_NextId = 1;
}

uint64_t CEndpointRegistry::MakeKey(const Endpoint &endpoint)
{
	return (uint64_t(endpoint.ip[0]) << 40) | (uint64_t(endpoint.ip[1]) << 32) | (uint64_t(endpoint.ip[2]) << 24)
		| (uint64_t(endpoint.ip[3]) << 16) | endpoint.port;
}

EndpointId CEndpointRegistry::Register(const Endpoint &endpoint, bool &added)
{
	const uint64_t key = MakeKey(endpoint);

	const std::map<uint64_t, EndpointId>::const_iterator known = m_Ids.find(key);
	if (known != m_Ids.end())
	{
		added = false;
		return known->second;
	}

	const EndpointId id = { m_NextId++ };
	m_Ids.emplace(key, id);
	added = true;
	return id;
}

} // namespace NetInspector
