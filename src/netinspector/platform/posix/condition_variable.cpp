//=============================================================================//
//
// CConditionVariable on POSIX systems: a pthread condition
//
//=============================================================================//

#include "netinspector/platform/condition_variable.h"

#include <time.h>

#include "netinspector/platform/clock.h"
#include "netinspector/platform/posix/native_mutex.h"

namespace NetInspector
{

struct CConditionVariable::CNative
{
	pthread_cond_t condition;
};

CConditionVariable::CConditionVariable() : m_Native(std::make_unique<CNative>())
{
	pthread_cond_init(&m_Native->condition, nullptr);
}

CConditionVariable::~CConditionVariable()
{
	pthread_cond_destroy(&m_Native->condition);
}

void CConditionVariable::Wait(CMutex &mutex, uint32_t timeoutMilliseconds)
{
	// pthread_cond_timedwait takes a deadline on the realtime clock
	const uint64_t deadline = CClock::GetUtcMicroseconds() + uint64_t(timeoutMilliseconds) * 1000;

	timespec until;
	until.tv_sec = time_t(deadline / 1000000);
	until.tv_nsec = long(deadline % 1000000 * 1000);

	pthread_cond_timedwait(&m_Native->condition, &mutex.m_Native->mutex, &until);
}

void CConditionVariable::NotifyAll()
{
	pthread_cond_broadcast(&m_Native->condition);
}

} // namespace NetInspector
