//=============================================================================//
//
// A condition variable over CMutex. Wakes may be spurious: the waiter checks
// its condition under the mutex before and after every Wait.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <memory>

#include "netinspector/platform/mutex.h"

namespace NetInspector
{

class CConditionVariable
{
public:
	CConditionVariable();
	~CConditionVariable();

	CConditionVariable(const CConditionVariable &) = delete;
	CConditionVariable &operator=(const CConditionVariable &) = delete;

	// With the mutex locked; returns with it locked, after a notify or the timeout
	void Wait(CMutex &mutex, uint32_t timeoutMilliseconds);
	void NotifyAll();

private:
	// The OS condition variable, defined by the platform
	struct CNative;

	std::unique_ptr<CNative> m_Native;
};

} // namespace NetInspector
