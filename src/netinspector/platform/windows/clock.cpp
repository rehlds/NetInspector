//=============================================================================//
//
// Clocks on Windows: the performance counter and the system file time
//
//=============================================================================//

#include "netinspector/platform/clock.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace NetInspector
{

uint64_t CClock::GetMonotonicMicroseconds()
{
	// The frequency is fixed at boot and read from shared memory
	LARGE_INTEGER frequencyValue;
	QueryPerformanceFrequency(&frequencyValue);

	LARGE_INTEGER counter;
	QueryPerformanceCounter(&counter);

	// Seconds and the remainder apart, so the multiplication stays inside 64 bits
	const uint64_t frequency = uint64_t(frequencyValue.QuadPart);
	const uint64_t ticks = uint64_t(counter.QuadPart);
	return ticks / frequency * 1000000 + ticks % frequency * 1000000 / frequency;
}

uint64_t CClock::GetUtcMicroseconds()
{
	// FILETIME counts 100 ns intervals since 1601-01-01
	constexpr uint64_t UNIX_EPOCH = 116444736000000000ULL;

	FILETIME fileTime;
	GetSystemTimeAsFileTime(&fileTime);

	const uint64_t intervals = (uint64_t(fileTime.dwHighDateTime) << 32) | fileTime.dwLowDateTime;
	return (intervals - UNIX_EPOCH) / 10;
}

} // namespace NetInspector
