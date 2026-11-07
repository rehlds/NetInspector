//=============================================================================//
//
// CMutex on POSIX systems: a pthread mutex
//
//=============================================================================//

#include "netinspector/platform/posix/native_mutex.h"

namespace NetInspector
{

CMutex::CMutex() : m_Native(std::make_unique<CNative>())
{
	pthread_mutex_init(&m_Native->mutex, nullptr);
}

CMutex::~CMutex()
{
	pthread_mutex_destroy(&m_Native->mutex);
}

void CMutex::Lock()
{
	pthread_mutex_lock(&m_Native->mutex);
}

void CMutex::Unlock()
{
	pthread_mutex_unlock(&m_Native->mutex);
}

} // namespace NetInspector
