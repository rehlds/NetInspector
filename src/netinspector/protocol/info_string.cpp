//=============================================================================//
//
// GoldSrc info strings
//
//=============================================================================//

#include "netinspector/protocol/info_string.h"

#include <cstring>

namespace NetInspector
{

void ScrubInfoValues(uint8_t *buffer, size_t begin, size_t end, const IInfoValueRule &rule)
{
	char *text = reinterpret_cast<char *>(buffer);
	size_t position = begin;

	while (position < end)
	{
		if (text[position] == '\\')
			position++;

		const size_t keyStart = position;
		while (position < end && text[position] != '\\')
			position++;

		if (position >= end)
			break;

		const TextSpan key = { text + keyStart, position - keyStart };
		position++;

		const size_t valueStart = position;
		while (position < end && text[position] != '\\')
			position++;

		const TextSpan value = { text + valueStart, position - valueStart };
		const char replacement = rule.GetReplacement(key, value);
		if (replacement)
			std::memset(text + valueStart, replacement, value.length);
	}
}

} // namespace NetInspector
