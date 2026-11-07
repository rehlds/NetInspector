//=============================================================================//
//
// Clocks on POSIX systems
//
//=============================================================================//

#include "netinspector/platform/clock.h"

#include <sys/time.h>
#include <time.h>

#ifdef __linux__
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace NetInspector
{

//-----------------------------------------------------------------------------
// On Linux the system call itself: glibc moved its clock_gettime from librt
// into libc in 2.17, and a binary that calls it needs that glibc
//-----------------------------------------------------------------------------
uint64_t CClock::GetMonotonicMicroseconds()
{
	timespec now = {};
#ifdef __linux__
	syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now);
#else
	clock_gettime(CLOCK_MONOTONIC, &now);
#endif
	return uint64_t(now.tv_sec) * 1000000 + uint64_t(now.tv_nsec) / 1000;
}

uint64_t CClock::GetUtcMicroseconds()
{
	timeval now;
	gettimeofday(&now, nullptr);
	return uint64_t(now.tv_sec) * 1000000 + uint64_t(now.tv_usec);
}

} // namespace NetInspector
