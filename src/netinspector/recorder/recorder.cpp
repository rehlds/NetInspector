//=============================================================================//
//
// CRecorder and what it owns: the queue, the file, the anonymizer and the
// writer thread
//
//=============================================================================//

#include "netinspector/recorder.h"

#include <algorithm>
#include <cstring>

#include "netinspector/anonymizer.h"
#include "netinspector/common/strtools.h"
#include "netinspector/recorder/entry_queue.h"
#include "netinspector/recorder/entry_writer.h"
#include "netinspector/recorder/output_file.h"
#include "netinspector/platform/clock.h"
#include "netinspector/platform/thread.h"

namespace NetInspector
{

namespace
{

void Append(std::vector<uint8_t> &body, const void *data, size_t length)
{
	const uint8_t *bytes = static_cast<const uint8_t *>(data);
	body.insert(body.end(), bytes, bytes + length);
}

void AppendString(std::vector<uint8_t> &body, const char *text)
{
	const char *value = text ? text : "";
	Append(body, value, std::strlen(value) + 1);
}

} // namespace

class CRecorder::CImpl
{
public:
	CImpl() : writer(queue, file, anonymizer) {}

	void Push(Entry type, const Endpoint *endpoint, const void *head, size_t headLength, const void *tail, size_t tailLength)
	{
		QueuedEntry entry = {};
		entry.type = type;
		if (endpoint)
		{
			entry.hasEndpoint = 1;
			entry.endpoint = *endpoint;
		}

		queue.Push(entry, head, headLength, tail, tailLength);
	}

	CEntryQueue queue;
	COutputFile file;
	CAnonymizer anonymizer;
	CEntryWriter writer;
	CThread thread;

	uint64_t startMicroseconds = 0;
	uint64_t lastFrameStart = 0;
};

CRecorder::CRecorder() : m_Impl(std::make_unique<CImpl>()), m_Recording(false)
{
}

CRecorder::~CRecorder()
{
	Stop();
}

bool CRecorder::Start(const char *path, const Settings &settings)
{
	if (IsRecording())
		return false;

	// Only the address mapping needs a key; secrets are scrubbed without one
	if (!m_Impl->anonymizer.GenerateKey() && settings.anonymizeAddresses)
		return false;

	m_Impl->anonymizer.SetPrivateUserInfoKeys(settings.privateUserInfoKeys);
	m_Impl->anonymizer.SetPrivateCommands(settings.privateCommands);

	FileHeader header = {};
	std::memcpy(header.magic, FILE_MAGIC, sizeof(header.magic));
	header.version = FORMAT_VERSION;
	header.role = settings.role;
	header.flags = settings.anonymizeAddresses ? FileFlags::EndpointsAnonymized : FileFlags::None;
	header.headerSize = sizeof(header);
	header.protocol = settings.protocol;
	std::memcpy(header.application, settings.application.data(), std::min(settings.application.size(), sizeof(header.application) - 1));

	m_Impl->startMicroseconds = CClock::GetMonotonicMicroseconds();
	header.startUtcMicroseconds = CClock::GetUtcMicroseconds();

	if (!m_Impl->file.Open(path, header))
		return false;

	m_Impl->writer.Reset(settings.anonymizeAddresses);
	m_Impl->queue.Open(settings.queueBytes, m_Impl->startMicroseconds);
	m_Impl->lastFrameStart = 0;

	if (!m_Impl->thread.Start(m_Impl->writer))
	{
		m_Impl->queue.Close();
		m_Impl->file.Close();
		return false;
	}

	m_Recording.store(true);
	RecordEvent(Event::RecordingStarted, nullptr, nullptr);
	return true;
}

void CRecorder::Stop()
{
	if (!IsRecording())
		return;

	RecordEvent(Event::RecordingStopped, nullptr, nullptr);

	m_Recording.store(false);
	m_Impl->queue.Close();
	m_Impl->thread.Join();
	m_Impl->file.Close();
}

uint64_t CRecorder::GetTime() const
{
	const uint64_t now = CClock::GetMonotonicMicroseconds();
	return now > m_Impl->startMicroseconds ? now - m_Impl->startMicroseconds : 0;
}

uint64_t CRecorder::GetBytesWritten() const
{
	return m_Impl->file.GetBytesWritten();
}

bool CRecorder::HasFailed() const
{
	return m_Impl->file.HasFailed();
}

void CRecorder::RecordDatagram(Direction direction, const Endpoint &endpoint, const void *data, size_t length)
{
	if (!IsRecording())
		return;

	DatagramEntry datagram = {};
	datagram.direction = direction;
	datagram.type = ClassifyDatagram(static_cast<const uint8_t *>(data), length);

	m_Impl->Push(Entry::Datagram, &endpoint, &datagram, sizeof(datagram), data, length);
}

void CRecorder::RecordFrame(uint64_t frameNumber)
{
	if (!IsRecording())
		return;

	const uint64_t now = GetTime();

	// The first frame has no start before it to measure from
	FrameEntry frame = {};
	frame.frameNumber = frameNumber;
	frame.durationMicroseconds = m_Impl->lastFrameStart ? uint32_t(std::min<uint64_t>(now - m_Impl->lastFrameStart, UINT32_MAX)) : 0;
	m_Impl->lastFrameStart = now;

	m_Impl->Push(Entry::Frame, nullptr, &frame, sizeof(frame), nullptr, 0);
}

void CRecorder::RecordServerInfo(int maxClients, int instancedBaselines, const char *map, const char *gameDirectory)
{
	if (!IsRecording())
		return;

	ServerInfoEntry info = {};
	info.maxClients = uint8_t(maxClients);
	info.instancedBaselines = uint8_t(instancedBaselines);

	std::vector<uint8_t> strings;
	AppendString(strings, map);
	AppendString(strings, gameDirectory);

	m_Impl->Push(Entry::ServerInfo, nullptr, &info, sizeof(info), strings.data(), strings.size());
}

void CRecorder::RecordUserMessages(const UserMessage *messages, size_t count)
{
	if (!IsRecording())
		return;

	UserMessagesEntry list = {};
	std::vector<uint8_t> records;

	for (size_t i = 0; i < count && list.count < UINT16_MAX; i++)
	{
		const size_t length = sizeof(UserMessageRecord) + std::strlen(messages[i].name ? messages[i].name : "") + 1;
		if (sizeof(list) + records.size() + length > MAX_ENTRY_BODY)
			break;

		UserMessageRecord record = {};
		record.id = uint8_t(messages[i].id);
		record.size = int8_t(messages[i].size < 0 ? -1 : messages[i].size);

		Append(records, &record, sizeof(record));
		AppendString(records, messages[i].name);
		list.count++;
	}

	m_Impl->Push(Entry::UserMessages, nullptr, &list, sizeof(list), records.data(), records.size());
}

void CRecorder::RecordDeltaDescription(const char *name, const DeltaField *fields, size_t count)
{
	if (!IsRecording())
		return;

	DeltaDescriptionEntry description = {};
	CopyString(description.name, sizeof(description.name), name);

	std::vector<uint8_t> records;
	for (size_t i = 0; i < count && description.fieldCount < UINT16_MAX; i++)
	{
		if (sizeof(description) + records.size() + sizeof(DeltaFieldRecord) > MAX_ENTRY_BODY)
			break;

		DeltaFieldRecord record = {};
		record.type = fields[i].type;
		record.bits = uint16_t(fields[i].bits);
		record.preMultiplier = fields[i].preMultiplier;
		record.postMultiplier = fields[i].postMultiplier;
		CopyString(record.name, sizeof(record.name), fields[i].name);

		Append(records, &record, sizeof(record));
		description.fieldCount++;
	}

	m_Impl->Push(Entry::DeltaDescription, nullptr, &description, sizeof(description), records.data(), records.size());
}

void CRecorder::RecordPrecache(PrecacheKind kind, const PrecacheItem *items, size_t count)
{
	if (!IsRecording())
		return;

	PrecacheEntry list = {};
	list.kind = kind;

	std::vector<uint8_t> records;
	for (size_t i = 0; i < count && list.count < UINT16_MAX; i++)
	{
		const size_t length = sizeof(uint16_t) + std::strlen(items[i].name ? items[i].name : "") + 1;
		if (sizeof(list) + records.size() + length > MAX_ENTRY_BODY)
			break;

		const uint16_t index = uint16_t(items[i].index);
		Append(records, &index, sizeof(index));
		AppendString(records, items[i].name);
		list.count++;
	}

	m_Impl->Push(Entry::Precache, nullptr, &list, sizeof(list), records.data(), records.size());
}

void CRecorder::RecordOverflow(const Endpoint &client, const OverflowCaptureEntry &state, const void *queued, const void *inFlight)
{
	if (!IsRecording())
		return;

	OverflowCaptureEntry kept = state;
	const size_t room = MAX_ENTRY_BODY - sizeof(kept);
	kept.queuedBytes = uint32_t(std::min<size_t>(state.queuedBytes, room));
	kept.reliableInFlightBytes = uint32_t(std::min<size_t>(state.reliableInFlightBytes, room - kept.queuedBytes));

	std::vector<uint8_t> bytes;
	Append(bytes, queued, kept.queuedBytes);
	Append(bytes, inFlight, kept.reliableInFlightBytes);

	m_Impl->Push(Entry::OverflowCapture, &client, &kept, sizeof(kept), bytes.data(), bytes.size());
}

void CRecorder::RecordProcessTime(const Endpoint &client, uint32_t microseconds)
{
	if (!IsRecording())
		return;

	ProcessTimeEntry entry = {};
	entry.microseconds = microseconds;
	m_Impl->Push(Entry::ProcessTime, &client, &entry, sizeof(entry), nullptr, 0);
}

void CRecorder::RecordEvent(Event event, const Endpoint *endpoint, const char *text)
{
	if (!IsRecording())
		return;

	EventEntry entry = {};
	entry.event = event;

	const char *body = text ? text : "";
	m_Impl->Push(Entry::Event, endpoint, &entry, sizeof(entry), body, std::strlen(body) + 1);
}

} // namespace NetInspector
