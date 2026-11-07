//=============================================================================//
//
// A thread that runs one task until the task returns
//
//=============================================================================//

#pragma once

#include <memory>

namespace NetInspector
{

class IThreadTask
{
public:
	virtual ~IThreadTask() = default;
	virtual void Run() = 0;
};

class CThread
{
public:
	CThread();
	~CThread();

	CThread(const CThread &) = delete;
	CThread &operator=(const CThread &) = delete;

	bool Start(IThreadTask &task);

	// Waits for the task to return; nothing if the thread is not running
	void Join();

	// The OS entry point of the new thread calls it
	void RunTask();

private:
	// The OS thread, defined by the platform
	struct CNative;

	std::unique_ptr<CNative> m_Native;
	IThreadTask *m_Task = nullptr;
	bool m_Running = false;
};

} // namespace NetInspector
