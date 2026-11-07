//=============================================================================//
//
// The two clocks of a recording: a monotonic one for entry times and the wall
// clock for the time the recording started
//
//=============================================================================//

#pragma once

#include <cstdint>

namespace NetInspector
{

class CClock
{
public:
	// Microseconds from an arbitrary start, never going back
	static uint64_t GetMonotonicMicroseconds();

	// Microseconds since 1970-01-01 UTC
	static uint64_t GetUtcMicroseconds();
};

} // namespace NetInspector
