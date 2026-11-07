//=============================================================================//
//
// Hands entries from the threads that record to the writer thread. A
// recording thread stamps the time and copies the body under one short lock; the
// writer swaps the whole batch out.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "netinspector/format.h"
#include "netinspector/platform/condition_variable.h"
#include "netinspector/platform/mutex.h"

namespace NetInspector
{

#pragma pack(push, 1)

// An entry on its way to the writer, with the real endpoint
struct QueuedEntry
{
	Entry		type;
	uint8_t		flags;
	uint8_t		hasEndpoint;
	uint8_t		reserved;
	uint32_t	length;		// body bytes that follow
	uint64_t	time;
	Endpoint	endpoint;
};

#pragma pack(pop)

class CEntryQueue
{
public:
	// Entry times count from startMicroseconds of the monotonic clock
	void Open(size_t limitBytes, uint64_t startMicroseconds);

	// Recording threads are refused from here on; the writer still takes what is queued
	void Close();

	//-----------------------------------------------------------------------------
	// The body is head followed by tail, either may be empty. False if the queue
	// is closed, or full and the entry was counted as lost.
	//-----------------------------------------------------------------------------
	bool Push(const QueuedEntry &entry, const void *head, size_t headLength, const void *tail, size_t tailLength);

	//-----------------------------------------------------------------------------
	// Waits up to the timeout for entries and swaps them into batch. False once
	// the queue is closed and empty.
	//-----------------------------------------------------------------------------
	bool Take(std::vector<uint8_t> &batch, uint32_t timeoutMilliseconds);

	// Entries lost since the last call
	void TakeLosses(uint32_t &entries, uint64_t &bytes);

private:
	CMutex					m_Mutex;
	CConditionVariable		m_Ready;
	std::vector<uint8_t>	m_Pending;
	size_t					m_LimitBytes = 0;
	uint64_t				m_StartMicroseconds = 0;
	uint64_t				m_LastTime = 0;
	bool					m_Open = false;
	uint32_t				m_LostEntries = 0;
	uint64_t				m_LostBytes = 0;
};

} // namespace NetInspector
