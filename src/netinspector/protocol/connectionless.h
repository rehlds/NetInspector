//=============================================================================//
//
// The layout of the connectionless requests that carry secrets: connect and rcon
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>

namespace NetInspector
{

constexpr size_t CONNECTIONLESS_HEADER_SIZE = 4;	// the -1 in front of the text

// connect <protocol> <challenge> "<protocol info>" "<userinfo>"\n<auth blob>
// Offsets are into the whole packet; a part that is missing is empty.
struct ConnectRequest
{
	size_t protocolInfoBegin;
	size_t protocolInfoEnd;
	size_t userInfoBegin;
	size_t userInfoEnd;
	size_t authBlobBegin;	// after the line; the blob runs to the end of the packet
};

bool IsConnectRequest(const uint8_t *packet, size_t length);
bool IsRconRequest(const uint8_t *packet, size_t length);

void ParseConnectRequest(const uint8_t *packet, size_t length, ConnectRequest &request);

//-----------------------------------------------------------------------------
// rcon <challenge> "<password>" <command>, the password quoted or not.
// False if the request ends before a password.
//-----------------------------------------------------------------------------
bool FindRconPassword(const uint8_t *packet, size_t length, size_t &begin, size_t &end);

} // namespace NetInspector
