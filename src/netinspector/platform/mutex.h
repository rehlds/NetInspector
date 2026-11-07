//=============================================================================//
//
// A mutex and its scope guard. The OS object is defined by the platform's
// implementation, so the header pulls in no OS headers. Not std::mutex: the
// recorder supports libstdc++ 3.4.15, and std::condition_variable, which has
// to wait on it, is newer than that.
//
//=============================================================================//

#pragma once

#include <memory>

namespace NetInspector
{

class CMutex
{
public:
	CMutex();
	~CMutex();

	CMutex(const CMutex &) = delete;
	CMutex &operator=(const CMutex &) = delete;

	void Lock();
	void Unlock();

private:
	friend class CConditionVariable;

	// The OS mutex, defined by the platform
	struct CNative;

	std::unique_ptr<CNative> m_Native;
};

class CLockGuard
{
public:
	explicit CLockGuard(CMutex &mutex) : m_Mutex(mutex) { m_Mutex.Lock(); }
	~CLockGuard() { m_Mutex.Unlock(); }

	CLockGuard(const CLockGuard &) = delete;
	CLockGuard &operator=(const CLockGuard &) = delete;

private:
	CMutex &m_Mutex;
};

} // namespace NetInspector
