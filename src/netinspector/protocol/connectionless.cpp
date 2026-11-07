//=============================================================================//
//
// connect and rcon requests
//
//=============================================================================//

#include "netinspector/protocol/connectionless.h"

#include <cstring>

#include "netinspector/common/strtools.h"

namespace NetInspector
{

namespace
{

// The next quoted string at or after position and before limit
bool FindQuoted(const uint8_t *packet, size_t &position, size_t limit, size_t &begin, size_t &end)
{
	while (position < limit && packet[position] != '"')
		position++;

	if (position >= limit)
		return false;

	begin = ++position;
	while (position < limit && packet[position] != '"')
		position++;

	end = position;
	if (position < limit)
		position++;

	return true;
}

size_t SkipSpaces(const uint8_t *packet, size_t position, size_t length)
{
	while (position < length && packet[position] == ' ')
		position++;
	return position;
}

size_t SkipWord(const uint8_t *packet, size_t position, size_t length)
{
	while (position < length && packet[position] != ' ')
		position++;
	return position;
}

} // namespace

bool IsConnectRequest(const uint8_t *packet, size_t length)
{
	return StartsWith(packet, length, CONNECTIONLESS_HEADER_SIZE, "connect ");
}

bool IsRconRequest(const uint8_t *packet, size_t length)
{
	return StartsWith(packet, length, CONNECTIONLESS_HEADER_SIZE, "rcon ");
}

void ParseConnectRequest(const uint8_t *packet, size_t length, ConnectRequest &request)
{
	size_t lineEnd = CONNECTIONLESS_HEADER_SIZE;
	while (lineEnd < length && packet[lineEnd] != '\n')
		lineEnd++;

	request = {};

	size_t position = CONNECTIONLESS_HEADER_SIZE;
	FindQuoted(packet, position, lineEnd, request.protocolInfoBegin, request.protocolInfoEnd);
	FindQuoted(packet, position, lineEnd, request.userInfoBegin, request.userInfoEnd);

	request.authBlobBegin = lineEnd < length ? lineEnd + 1 : length;
}

bool FindRconPassword(const uint8_t *packet, size_t length, size_t &begin, size_t &end)
{
	size_t position = CONNECTIONLESS_HEADER_SIZE + std::strlen("rcon ");
	position = SkipSpaces(packet, position, length);
	position = SkipWord(packet, position, length);		// the challenge
	position = SkipSpaces(packet, position, length);

	if (position >= length)
		return false;

	const bool quoted = packet[position] == '"';
	if (quoted)
		position++;

	begin = position;
	while (position < length)
	{
		const uint8_t c = packet[position];
		if (quoted ? c == '"' : (c == ' ' || c == '\n' || c == '\0'))
			break;

		position++;
	}

	end = position;
	return true;
}

} // namespace NetInspector
