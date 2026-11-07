//=============================================================================//
//
// Text over byte buffers that are not NUL-terminated: spans, comparisons, and
// dotted IPv4 addresses
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>

namespace NetInspector
{

// A view of text inside a larger buffer
struct TextSpan
{
	const char	*data;
	size_t		length;

	bool Equals(const char *text) const;
};

inline bool IsDigit(uint8_t c)
{
	return c >= '0' && c <= '9';
}

// Copies as much of source as fits with a terminator; a null source copies nothing
void CopyString(char *destination, size_t size, const char *source);

// The buffer, from offset, starts with prefix
bool StartsWith(const uint8_t *buffer, size_t length, size_t offset, const char *prefix);

//-----------------------------------------------------------------------------
// A dotted quad starting at position and ending before limit, as a host-order
// address. end gets the position after its last digit.
//-----------------------------------------------------------------------------
bool ParseIPv4(const uint8_t *buffer, size_t position, size_t limit, uint32_t &ip, size_t &end);

// "a.b.c.d" into text, which holds at least 16 characters; returns the length
int FormatIPv4(uint32_t ip, char *text, size_t size);

} // namespace NetInspector
