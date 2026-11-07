//=============================================================================//
//
// The queue between the recording threads and the writer thread
//
//=============================================================================//

#include "netinspector/recorder/entry_queue.h"

#include <cstring>

#include "netinspector/platform/clock.h"

namespace NetInspector
{

void CEntryQueue::Open(size_t limitBytes, uint64_t startMicroseconds)
{
	CLockGuard lock(m_Mutex);

	m_Pending.clear();
	m_Pending.reserve(limitBytes / 4);
	m_LimitBytes = limitBytes;
	m_StartMicroseconds = startMicroseconds;
	m_LastTime = 0;
	m_LostEntries = 0;
	m_LostBytes = 0;
	m_Open = true;
}

void CEntryQueue::Close()
{
	CLockGuard lock(m_Mutex);

	m_Open = false;
	m_Ready.NotifyAll();
}

bool CEntryQueue::Push(const QueuedEntry &entry, const void *head, size_t headLength, const void *tail, size_t tailLength)
{
	const size_t bodyLength = headLength + tailLength;
	const size_t totalLength = sizeof(QueuedEntry) + bodyLength;

	CLockGuard lock(m_Mutex);

	if (!m_Open)
		return false;

	if (bodyLength > MAX_ENTRY_BODY || m_Pending.size() + totalLength > m_LimitBytes)
	{
		m_LostEntries++;
		m_LostBytes += bodyLength;
		return false;
	}

	// Stamped under the lock, so times never decrease in queue order
	const uint64_t now = CClock::GetMonotonicMicroseconds();
	if (now > m_StartMicroseconds && now - m_StartMicroseconds > m_LastTime)
		m_LastTime = now - m_StartMicroseconds;

	QueuedEntry stamped = entry;
	stamped.length = uint32_t(bodyLength);
	stamped.time = m_LastTime;

	const size_t offset = m_Pending.size();
	m_Pending.resize(offset + totalLength);

	uint8_t *out = &m_Pending[offset];
	std::memcpy(out, &stamped, sizeof(stamped));
	out += sizeof(stamped);

	if (headLength)
	{
		std::memcpy(out, head, headLength);
		out += headLength;
	}

	if (tailLength)
		std::memcpy(out, tail, tailLength);

	m_Ready.NotifyAll();
	return true;
}

bool CEntryQueue::Take(std::vector<uint8_t> &batch, uint32_t timeoutMilliseconds)
{
	batch.clear();

	CLockGuard lock(m_Mutex);

	if (m_Pending.empty() && m_Open)
		m_Ready.Wait(m_Mutex, timeoutMilliseconds);

	// The capacities travel with the swap, so neither buffer reallocates once warmed up
	batch.swap(m_Pending);
	return m_Open || !batch.empty();
}

void CEntryQueue::TakeLosses(uint32_t &entries, uint64_t &bytes)
{
	CLockGuard lock(m_Mutex);

	entries = m_LostEntries;
	bytes = m_LostBytes;
	m_LostEntries = 0;
	m_LostBytes = 0;
}

} // namespace NetInspector
