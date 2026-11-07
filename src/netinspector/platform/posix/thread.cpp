//=============================================================================//
//
// CThread on POSIX systems
//
//=============================================================================//

#include "netinspector/platform/thread.h"

#include <pthread.h>

namespace NetInspector
{

struct CThread::CNative
{
	pthread_t thread;
};

namespace
{

void *ThreadEntry(void *context)
{
	static_cast<CThread *>(context)->RunTask();
	return nullptr;
}

} // namespace

CThread::CThread() : m_Native(std::make_unique<CNative>())
{
}

CThread::~CThread()
{
	Join();
}

bool CThread::Start(IThreadTask &task)
{
	if (m_Running)
		return false;

	m_Task = &task;
	m_Running = pthread_create(&m_Native->thread, nullptr, &ThreadEntry, this) == 0;
	return m_Running;
}

void CThread::Join()
{
	if (!m_Running)
		return;

	pthread_join(m_Native->thread, nullptr);
	m_Running = false;
}

void CThread::RunTask()
{
	m_Task->Run();
}

} // namespace NetInspector
