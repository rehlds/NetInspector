//=============================================================================//
//
// Text over byte buffers
//
//=============================================================================//

#include "netinspector/common/strtools.h"

#include <cstdio>
#include <cstring>

namespace NetInspector
{

bool TextSpan::Equals(const char *text) const
{
	return std::strlen(text) == length && std::memcmp(data, text, length) == 0;
}

void CopyString(char *destination, size_t size, const char *source)
{
	if (size == 0)
		return;

	size_t length = 0;
	if (source)
	{
		while (length + 1 < size && source[length])
			length++;

		std::memcpy(destination, source, length);
	}

	destination[length] = '\0';
}

bool StartsWith(const uint8_t *buffer, size_t length, size_t offset, const char *prefix)
{
	const size_t prefixLength = std::strlen(prefix);
	return offset <= length && length - offset >= prefixLength && std::memcmp(buffer + offset, prefix, prefixLength) == 0;
}

bool ParseIPv4(const uint8_t *buffer, size_t position, size_t limit, uint32_t &ip, size_t &end)
{
	ip = 0;

	for (int octet = 0; octet < 4; octet++)
	{
		if (octet > 0)
		{
			if (position >= limit || buffer[position] != '.')
				return false;

			position++;
		}

		uint32_t value = 0;
		int digits = 0;
		while (position < limit && IsDigit(buffer[position]) && digits <= 3)
		{
			value = value * 10 + uint32_t(buffer[position] - '0');
			position++;
			digits++;
		}

		if (digits == 0 || digits > 3 || value > 255)
			return false;

		ip = (ip << 8) | value;
	}

	end = position;
	return true;
}

int FormatIPv4(uint32_t ip, char *text, size_t size)
{
	return std::snprintf(text, size, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

} // namespace NetInspector
