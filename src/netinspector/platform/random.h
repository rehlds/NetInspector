//=============================================================================//
//
// The system's cryptographic random source
//
//=============================================================================//

#pragma once

#include <cstddef>

namespace NetInspector
{

class CRandom
{
public:
	static bool Fill(void *data, size_t size);
};

} // namespace NetInspector
