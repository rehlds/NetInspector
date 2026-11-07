//=============================================================================//
//
// Reliable buffer overflows and what led to them
//
//=============================================================================//

#include "overflow_report.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include <CLI/CLI.hpp>

#include "netinspector/channel.h"

namespace NetInspector
{

namespace
{

// How far back the server's sending is summed up
constexpr uint64_t SENT_WINDOW_MICROSECONDS = 2000000;

// A drop this soon after an overflow is taken as its consequence
constexpr uint64_t DROP_WINDOW_MICROSECONDS = 5000000;

// A message cut this short at the end of a buffer is the write that did not fit, not damage
constexpr size_t CUT_SHORT_BYTES = 16;

bool ByBytes(const std::pair<std::string, std::pair<uint32_t, uint32_t>> &left, const std::pair<std::string, std::pair<uint32_t, uint32_t>> &right)
{
	return left.second.second > right.second.second;
}

double Seconds(uint64_t microseconds)
{
	return (double)microseconds / 1000000.0;
}

} // namespace

COverflowReport::COverflowReport() :
	CCommand("overflow", "every reliable buffer that overflowed: what filled it, what was in flight, how the client's channel stood"),
	m_Decoder(m_Tables)
{
}

void COverflowReport::AddOptions(CLI::App &subcommand)
{
	subcommand.add_flag("--list", m_List, "every message in the buffers as well, not only the sums");
}

int COverflowReport::Run(CReader &reader)
{
	const FileHeader &file = reader.GetHeader();
	const CReportClock clock(file);
	m_Clock = &clock;

	if (file.role != Role::Server)
	{
		std::fprintf(stderr, "netinspector: overflow captures are a server's; this file was recorded by a client\n");
		return 2;
	}

	EntryHeader header;
	const uint8_t *body = nullptr;
	while (reader.Next(header, body))
	{
		switch (header.type)
		{
		case Entry::Endpoint:
			if (header.length >= sizeof(EndpointEntry))
			{
				EndpointEntry address;
				std::memcpy(&address, body, sizeof(address));
				m_Endpoints.Add(header.endpoint, address);
			}
			break;

		case Entry::Datagram:			OnDatagram(header, body);	break;
		case Entry::OverflowCapture:	OnOverflow(header, body);	break;
		case Entry::Event:				OnEvent(header, body);		break;
		default:						m_Tables.Apply(header, body);	break;
		}
	}

	if (!IsJson())
		std::printf("%u overflows\n", m_Overflows);

	return 0;
}

void COverflowReport::OnDatagram(const EntryHeader &header, const uint8_t *body)
{
	if (header.length < sizeof(DatagramEntry))
		return;

	DatagramEntry datagram;
	std::memcpy(&datagram, body, sizeof(datagram));
	const uint8_t *data = body + sizeof(datagram);
	const size_t length = header.length - sizeof(datagram);

	ClientChannel &client = m_Clients[header.endpoint];

	if (datagram.direction == Direction::Out)
	{
		client.sent.push_back(std::make_pair(header.time, (uint32_t)length));
		while (!client.sent.empty() && client.sent.front().first + SENT_WINDOW_MICROSECONDS < header.time)
			client.sent.pop_front();
		return;
	}

	if (datagram.type != Datagram::Channel || length < CHANNEL_HEADER_SIZE)
		return;

	client.heard = true;
	client.lastHeard = header.time;

	// The acknowledgement word is not munged
	uint32_t acknowledgedWord;
	std::memcpy(&acknowledgedWord, data + 4, sizeof(acknowledgedWord));
	const uint32_t acknowledged = acknowledgedWord & 0x3FFFFFFF;
	if (acknowledged != client.acknowledged)
	{
		client.acknowledged = acknowledged;
		client.acknowledgedSince = header.time;
	}
}

void COverflowReport::Summarize(const uint8_t *data, size_t length, std::vector<MessageTotal> &totals)
{
	totals.clear();
	m_Decoder.Decode(MessageSource::Server, data, length, 0, m_Decoded);

	std::map<std::string, std::pair<uint32_t, uint32_t>> sums;
	for (const DecodedMessage &message : m_Decoded.messages)
	{
		std::pair<uint32_t, uint32_t> &sum = sums[message.name];
		sum.first++;
		sum.second += (uint32_t)message.length;
	}

	std::vector<std::pair<std::string, std::pair<uint32_t, uint32_t>>> sorted(sums.begin(), sums.end());
	std::sort(sorted.begin(), sorted.end(), ByBytes);

	for (const std::pair<std::string, std::pair<uint32_t, uint32_t>> &sum : sorted)
		totals.push_back(MessageTotal{ sum.first, sum.second.first, sum.second.second });
}

// The write that overflowed the buffer may have put its first bytes in before the rest did not fit
bool COverflowReport::IsCutShort(size_t length) const
{
	return !m_Decoded.complete && m_Decoded.error.find("past the end") != std::string::npos && length - m_Decoded.stoppedAt < CUT_SHORT_BYTES;
}

std::string COverflowReport::CutMessageName() const
{
	return m_Decoded.error.substr(0, m_Decoded.error.find(':'));
}

void COverflowReport::PrintStream(const char *title, size_t length, const std::vector<MessageTotal> &totals) const
{
	std::printf("  %s, %zu bytes, by message:\n", title, length);
	for (const MessageTotal &total : totals)
		std::printf("    %-28s %6u x %8u bytes\n", total.name.c_str(), total.count, total.bytes);

	if (IsCutShort(length))
		std::printf("    the last %zu bytes: the start of the write that did not fit, %s\n", length - m_Decoded.stoppedAt, CutMessageName().c_str());
	else if (!m_Decoded.complete)
		std::printf("    STOPPED at byte %zu: %s\n", m_Decoded.stoppedAt, m_Decoded.error.c_str());

	if (!m_List)
		return;

	for (const DecodedMessage &message : m_Decoded.messages)
		std::printf("      %6zu %-24s %4zu %s\n", message.offset, message.name.c_str(), message.length, message.text.c_str());
}

void COverflowReport::WriteStream(const char *name, size_t length, const std::vector<MessageTotal> &totals)
{
	m_Json.Key(name);
	m_Json.BeginObject();
	m_Json.Field("bytes", (uint64_t)length);
	if (IsCutShort(length))
	{
		m_Json.Field("decoded", true);
		m_Json.Field("cutShortBytes", (uint64_t)(length - m_Decoded.stoppedAt));
		m_Json.Field("cutShortMessage", CutMessageName());
	}
	else
	{
		m_Json.Field("decoded", m_Decoded.complete);
		if (!m_Decoded.complete)
		{
			m_Json.Field("stoppedAt", (uint64_t)m_Decoded.stoppedAt);
			m_Json.Field("error", m_Decoded.error);
		}
	}

	m_Json.Key("byMessage");
	m_Json.BeginArray();
	for (const MessageTotal &total : totals)
	{
		m_Json.BeginObject();
		m_Json.Field("name", total.name);
		m_Json.Field("count", total.count);
		m_Json.Field("bytes", total.bytes);
		m_Json.EndObject();
	}
	m_Json.EndArray();

	if (m_List)
	{
		m_Json.Key("messages");
		m_Json.BeginArray();
		for (const DecodedMessage &message : m_Decoded.messages)
		{
			m_Json.BeginObject();
			m_Json.Field("offset", (uint64_t)message.offset);
			m_Json.Field("name", message.name);
			m_Json.Field("length", (uint64_t)message.length);
			m_Json.Field("text", message.text);
			m_Json.EndObject();
		}
		m_Json.EndArray();
	}

	m_Json.EndObject();
}

void COverflowReport::OnOverflow(const EntryHeader &header, const uint8_t *body)
{
	OverflowCaptureEntry state;
	if (header.length < sizeof(state))
		return;

	std::memcpy(&state, body, sizeof(state));
	const uint8_t *queued = body + sizeof(state);
	const size_t queuedLength = std::min<size_t>(state.queuedBytes, header.length - sizeof(state));
	const uint8_t *inFlight = queued + queuedLength;
	const size_t inFlightLength = std::min<size_t>(state.reliableInFlightBytes, header.length - sizeof(state) - queuedLength);

	m_Overflows++;

	ClientChannel &client = m_Clients[header.endpoint];
	client.overflowTime = header.time;
	client.awaitingDrop = true;

	uint32_t sentPackets = 0;
	uint64_t sentBytes = 0;
	for (const std::pair<uint64_t, uint32_t> &packet : client.sent)
	{
		sentPackets++;
		sentBytes += packet.second;
	}

	const double heardAgo = client.heard ? Seconds(header.time - client.lastHeard) : -1.0;
	const double acknowledgementStill = client.heard ? Seconds(header.time - client.acknowledgedSince) : -1.0;

	std::vector<MessageTotal> queuedTotals;
	std::vector<MessageTotal> inFlightTotals;

	if (IsJson())
	{
		m_Json.BeginObject();
		m_Json.Field("type", "overflow");
		m_Json.Field("time", Seconds(header.time));
		m_Json.Field("endpoint", m_Endpoints.Describe(header.endpoint));
		m_Json.Field("bufferBytes", state.bufferBytes);
		m_Json.Field("requestedBytes", state.requestedBytes);
		m_Json.Field("reliableInFlightBytes", state.reliableInFlightBytes);
		m_Json.Field("queuedFragmentBuffers", state.queuedFragmentBuffers);
		m_Json.Field("unacknowledgedPackets", state.unacknowledgedPackets);
		m_Json.Field("clientSilentMilliseconds", state.silentMilliseconds);
		m_Json.Field("lastClientPacketSecondsAgo", heardAgo);
		m_Json.Field("acknowledgementStillSeconds", acknowledgementStill);
		m_Json.Field("sentPacketsLast2s", sentPackets);
		m_Json.Field("sentBytesLast2s", sentBytes);

		Summarize(queued, queuedLength, queuedTotals);
		WriteStream("queued", queuedLength, queuedTotals);
		Summarize(inFlight, inFlightLength, inFlightTotals);
		WriteStream("inFlight", inFlightLength, inFlightTotals);

		m_Json.EndObject();
		m_Json.EndLine();
		return;
	}

	std::printf("%s %s %s RELIABLE BUFFER OVERFLOWED\n", m_Clock->Relative(header.time).c_str(), m_Clock->LocalTime(header.time).c_str(),
		m_Endpoints.Describe(header.endpoint).c_str());
	std::printf("  buffer: %zu of %u bytes queued, a write of %u more did not fit\n", queuedLength, state.bufferBytes, state.requestedBytes);
	std::printf("  in flight: %u bytes of reliable data unacknowledged, %u fragment buffers waiting, %u packets since the last acknowledged\n",
		state.reliableInFlightBytes, state.queuedFragmentBuffers, state.unacknowledgedPackets);
	std::printf("  client: silent for %u ms as the engine saw it", state.silentMilliseconds);
	if (client.heard)
		std::printf("; its last packet in the recording %.3f s before, its acknowledgement unchanged for %.3f s", heardAgo, acknowledgementStill);
	std::printf("\n");
	std::printf("  the server sent it %u packets, %llu bytes in the 2 s before\n", sentPackets, (unsigned long long)sentBytes);

	Summarize(queued, queuedLength, queuedTotals);
	PrintStream("queued", queuedLength, queuedTotals);

	if (inFlightLength)
	{
		Summarize(inFlight, inFlightLength, inFlightTotals);
		PrintStream("in flight", inFlightLength, inFlightTotals);
	}
}

void COverflowReport::OnEvent(const EntryHeader &header, const uint8_t *body)
{
	if (header.length < sizeof(EventEntry) || !header.endpoint.IsValid())
		return;

	EventEntry event;
	std::memcpy(&event, body, sizeof(event));
	if (event.event != Event::ClientDropped)
		return;

	ClientChannel &client = m_Clients[header.endpoint];
	if (!client.awaitingDrop || header.time - client.overflowTime > DROP_WINDOW_MICROSECONDS)
		return;

	client.awaitingDrop = false;
	const std::string text = reinterpret_cast<const char *>(body + sizeof(event));
	const double after = Seconds(header.time - client.overflowTime);

	if (IsJson())
	{
		m_Json.BeginObject();
		m_Json.Field("type", "drop");
		m_Json.Field("time", Seconds(header.time));
		m_Json.Field("endpoint", m_Endpoints.Describe(header.endpoint));
		m_Json.Field("secondsAfterOverflow", after);
		m_Json.Field("event", text);
		m_Json.EndObject();
		m_Json.EndLine();
		return;
	}

	std::printf("  dropped %.3f s later: %s\n\n", after, text.c_str());
}

} // namespace NetInspector
