//=============================================================================//
//
// The writer thread of a recording
//
//=============================================================================//

#include "netinspector/recorder/entry_writer.h"

#include <cstring>

namespace NetInspector
{

namespace
{

// The longest a recorded entry waits before it reaches the file
constexpr uint32_t FLUSH_INTERVAL_MILLISECONDS = 100;

} // namespace

CEntryWriter::CEntryWriter(CEntryQueue &queue, COutputFile &file, const CAnonymizer &anonymizer) :
	m_Queue(queue),
	m_File(file),
	m_Anonymizer(anonymizer)
{
}

void CEntryWriter::Reset(bool anonymizeAddresses)
{
	m_Endpoints.Clear();
	m_AnonymizeAddresses = anonymizeAddresses;
	m_LastTime = 0;
}

void CEntryWriter::Run()
{
	bool open = true;
	while (open)
	{
		open = m_Queue.Take(m_Batch, FLUSH_INTERVAL_MILLISECONDS);

		size_t position = 0;
		while (position + sizeof(QueuedEntry) <= m_Batch.size())
		{
			QueuedEntry entry;
			std::memcpy(&entry, &m_Batch[position], sizeof(entry));
			position += sizeof(entry);

			WriteQueued(entry, m_Batch.data() + position);
			position += entry.length;
		}

		WriteLosses();
		m_File.Flush();
	}
}

void CEntryWriter::WriteQueued(const QueuedEntry &entry, const uint8_t *body)
{
	m_LastTime = entry.time;

	EntryHeader header = {};
	header.type = entry.type;
	header.flags = entry.flags;
	header.time = entry.time;
	header.endpoint = entry.hasEndpoint ? RegisterEndpoint(entry.endpoint, entry.time) : NO_ENDPOINT;

	if (entry.type == Entry::Datagram)
		WriteDatagram(header, body, entry.length);
	else
		m_File.Write(header, body, entry.length, nullptr, 0);
}

void CEntryWriter::WriteDatagram(EntryHeader &header, const uint8_t *body, size_t length)
{
	if (length < sizeof(DatagramEntry))
		return;

	DatagramEntry datagram;
	std::memcpy(&datagram, body, sizeof(datagram));

	const uint8_t *bytes = body + sizeof(datagram);
	const size_t byteCount = length - sizeof(datagram);

	if (datagram.type == Datagram::Connectionless && m_Anonymizer.ScrubConnectionless(bytes, byteCount, m_AnonymizeAddresses, m_Scrubbed))
	{
		header.flags |= uint8_t(DatagramFlags::Scrubbed);
		m_File.Write(header, &datagram, sizeof(datagram), m_Scrubbed.data(), m_Scrubbed.size());
		return;
	}

	if (datagram.type == Datagram::Channel && m_Anonymizer.ScrubChannel(bytes, byteCount, m_Scrubbed))
	{
		header.flags |= uint8_t(DatagramFlags::Scrubbed);
		m_File.Write(header, &datagram, sizeof(datagram), m_Scrubbed.data(), m_Scrubbed.size());
		return;
	}

	m_File.Write(header, &datagram, sizeof(datagram), bytes, byteCount);
}

EndpointId CEntryWriter::RegisterEndpoint(const Endpoint &endpoint, uint64_t time)
{
	bool added = false;
	const EndpointId id = m_Endpoints.Register(endpoint, added);
	if (!added)
		return id;

	const Endpoint stored = m_AnonymizeAddresses ? m_Anonymizer.Map(endpoint) : endpoint;

	EndpointEntry entry = {};
	std::memcpy(entry.ip, stored.ip, sizeof(entry.ip));
	entry.port = stored.port;
	entry.flags = m_AnonymizeAddresses ? EndpointFlags::Anonymized : EndpointFlags::None;

	EntryHeader header = {};
	header.type = Entry::Endpoint;
	header.time = time;
	header.endpoint = id;

	m_File.Write(header, &entry, sizeof(entry), nullptr, 0);
	return id;
}

void CEntryWriter::WriteLosses()
{
	RecorderLossEntry loss = {};
	m_Queue.TakeLosses(loss.entries, loss.bytes);
	if (loss.entries == 0)
		return;

	EntryHeader header = {};
	header.type = Entry::RecorderLoss;
	header.time = m_LastTime;

	m_File.Write(header, &loss, sizeof(loss), nullptr, 0);
}

} // namespace NetInspector
