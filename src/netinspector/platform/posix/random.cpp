//=============================================================================//
//
// Random bytes on POSIX systems: /dev/urandom
//
//=============================================================================//

#include "netinspector/platform/random.h"

#include <cstdio>

namespace NetInspector
{

bool CRandom::Fill(void *data, size_t size)
{
	std::FILE *source = std::fopen("/dev/urandom", "rb");
	if (!source)
		return false;

	const bool filled = std::fread(data, 1, size, source) == size;
	std::fclose(source);
	return filled;
}

} // namespace NetInspector
