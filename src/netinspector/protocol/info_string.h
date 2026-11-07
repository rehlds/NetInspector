//=============================================================================//
//
// GoldSrc info strings, "\key\value\key\value": userinfo, server info and the
// protocol info of connect requests
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>

#include "netinspector/common/strtools.h"

namespace NetInspector
{

class IInfoValueRule
{
public:
	virtual ~IInfoValueRule() = default;

	// The character every byte of the value becomes, or 0 to keep it
	virtual char GetReplacement(const TextSpan &key, const TextSpan &value) const = 0;
};

//-----------------------------------------------------------------------------
// Overwrites the values of the info string between begin and end that the rule
// asks for, keeping their lengths
//-----------------------------------------------------------------------------
void ScrubInfoValues(uint8_t *buffer, size_t begin, size_t end, const IInfoValueRule &rule);

} // namespace NetInspector
