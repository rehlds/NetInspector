//=============================================================================//
//
// CConditionVariable on Windows: a condition variable over a critical section
//
//=============================================================================//

#include "netinspector/platform/condition_variable.h"
#include "netinspector/platform/windows/native_mutex.h"

namespace NetInspector
{

struct CConditionVariable::CNative
{
	CONDITION_VARIABLE condition;
};

CConditionVariable::CConditionVariable() : m_Native(std::make_unique<CNative>())
{
	InitializeConditionVariable(&m_Native->condition);
}

// A Windows condition variable holds no resources to release
CConditionVariable::~CConditionVariable() = default;

void CConditionVariable::Wait(CMutex &mutex, uint32_t timeoutMilliseconds)
{
	SleepConditionVariableCS(&m_Native->condition, &mutex.m_Native->section, timeoutMilliseconds);
}

void CConditionVariable::NotifyAll()
{
	WakeAllConditionVariable(&m_Native->condition);
}

} // namespace NetInspector
