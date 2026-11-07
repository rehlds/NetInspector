//=============================================================================//
//
// The OS mutex on Windows, shared by the mutex and the condition variable
// that waits on it
//
//=============================================================================//

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "netinspector/platform/mutex.h"

namespace NetInspector
{

struct CMutex::CNative
{
	CRITICAL_SECTION section;
};

} // namespace NetInspector
