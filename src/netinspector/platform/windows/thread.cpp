//=============================================================================//
//
// CThread on Windows
//
//=============================================================================//

#include "netinspector/platform/thread.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace NetInspector
{

struct CThread::CNative
{
	HANDLE handle = nullptr;
};

namespace
{

DWORD WINAPI ThreadEntry(LPVOID context)
{
	static_cast<CThread *>(context)->RunTask();
	return 0;
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
	m_Native->handle = CreateThread(nullptr, 0, &ThreadEntry, this, 0, nullptr);
	m_Running = m_Native->handle != nullptr;
	return m_Running;
}

void CThread::Join()
{
	if (!m_Running)
		return;

	WaitForSingleObject(m_Native->handle, INFINITE);
	CloseHandle(m_Native->handle);
	m_Native->handle = nullptr;
	m_Running = false;
}

void CThread::RunTask()
{
	m_Task->Run();
}

} // namespace NetInspector
