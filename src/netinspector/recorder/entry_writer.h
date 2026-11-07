//=============================================================================//
//
// The writer thread's work: take queued entries, give endpoints their ids,
// scrub what the file's flags promise, and write the entries out, all of it
// off the threads that record
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <vector>

#include "netinspector/anonymizer.h"
#include "netinspector/recorder/endpoint_registry.h"
#include "netinspector/recorder/entry_queue.h"
#include "netinspector/recorder/output_file.h"
#include "netinspector/platform/thread.h"

namespace NetInspector
{

class CEntryWriter final : public IThreadTask
{
public:
	CEntryWriter(CEntryQueue &queue, COutputFile &file, const CAnonymizer &anonymizer);

	// Before the thread starts a new recording
	void Reset(bool anonymizeAddresses);

	// Until the queue is closed and drained
	void Run() override;

private:
	void WriteQueued(const QueuedEntry &entry, const uint8_t *body);
	void WriteDatagram(EntryHeader &header, const uint8_t *body, size_t length);
	EndpointId RegisterEndpoint(const Endpoint &endpoint, uint64_t time);
	void WriteLosses();

	CEntryQueue &m_Queue;
	COutputFile &m_File;
	const CAnonymizer &m_Anonymizer;

	CEndpointRegistry m_Endpoints;
	bool m_AnonymizeAddresses = true;
	uint64_t m_LastTime = 0;

	std::vector<uint8_t> m_Batch;
	std::vector<uint8_t> m_Scrubbed;
};

} // namespace NetInspector
