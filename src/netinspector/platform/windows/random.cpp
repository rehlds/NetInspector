//=============================================================================//
//
// Random bytes on Windows: RtlGenRandom
//
//=============================================================================//

#include "netinspector/platform/random.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

// RtlGenRandom, exported by advapi32 under this name
extern "C" BOOLEAN NTAPI SystemFunction036(PVOID buffer, ULONG length);
#pragma comment(lib, "advapi32.lib")

namespace NetInspector
{

bool CRandom::Fill(void *data, size_t size)
{
	return SystemFunction036(data, ULONG(size)) != FALSE;
}

} // namespace NetInspector
