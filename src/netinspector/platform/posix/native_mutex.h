//=============================================================================//
//
// The OS mutex on POSIX systems, shared by the mutex and the condition variable
// that waits on it
//
//=============================================================================//

#pragma once

#include <pthread.h>

#include "netinspector/platform/mutex.h"

namespace NetInspector
{

struct CMutex::CNative
{
	pthread_mutex_t mutex;
};

} // namespace NetInspector
