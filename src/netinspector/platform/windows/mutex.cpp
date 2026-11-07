//=============================================================================//
//
// CMutex on Windows: a critical section
//
//=============================================================================//

#include "netinspector/platform/windows/native_mutex.h"

namespace NetInspector
{

CMutex::CMutex() : m_Native(std::make_unique<CNative>())
{
	InitializeCriticalSection(&m_Native->section);
}

CMutex::~CMutex()
{
	DeleteCriticalSection(&m_Native->section);
}

void CMutex::Lock()
{
	EnterCriticalSection(&m_Native->section);
}

void CMutex::Unlock()
{
	LeaveCriticalSection(&m_Native->section);
}

} // namespace NetInspector
