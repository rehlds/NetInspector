//=============================================================================//
//
// The channel-level timeline of a recording
//
//=============================================================================//

#include "timeline_report.h"

#include <cinttypes>
#include <cstdio>
#include <cstring>

#include <CLI/CLI.hpp>

namespace NetInspector
{

namespace
{

// Sent sequences kept for round trips; older ones were lost or acknowledged long ago
constexpr uint32_t SENT_SEQUENCE_WINDOW = 1024;

constexpr size_t CONNECTIONLESS_PREVIEW = 96;

// Where the second line of a packet starts, under the packet's description
constexpr int CONTINUATION_INDENT = 58;

int Index(Direction direction)
{
	return direction == Direction::In ? 0 : 1;
}

Direction Opposite(Direction direction)
{
	return direction == Direction::In ? Direction::Out : Direction::In;
}

const char *FragmentResultName(CFragmentAssembler::Result result)
{
	switch (result)
	{
	case CFragmentAssembler::Result::Repeated:	return " resent";
	case CFragmentAssembler::Result::Malformed:	return " MALFORMED";
	default:									return "";
	}
}

} // namespace

void CTimelineReport::AddOptions(CLI::App &subcommand)
{
	subcommand.add_option("--address", m_Filter.address, "only this endpoint: #id or ip:port, as info lists them");
	subcommand.add_option("--from", m_Filter.fromSeconds, "seconds since the recording started");
	subcommand.add_option("--to", m_Filter.toSeconds, "seconds since the recording started");
	subcommand.add_option("--slow-frame", m_Filter.slowFrameMilliseconds, "frames this long or longer are shown, in milliseconds; 0 shows every frame");
}

int CTimelineReport::Run(CReader &reader)
{
	const FileHeader &file = reader.GetHeader();
	const CReportClock clock(file);
	m_Clock = &clock;

	std::printf("# %s as %s, started %s UTC; \"in\" is what the %s received\n",
		file.application, ToString(file.role), clock.UtcDateTime(0).c_str(), ToString(file.role));

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

		case Entry::Datagram:			OnDatagram(header, body);		break;
		case Entry::Event:				OnEvent(header, body);			break;
		case Entry::Frame:				OnFrame(header, body);			break;
		case Entry::ServerInfo:
		case Entry::UserMessages:
		case Entry::DeltaDescription:
		case Entry::Precache:			OnSessionTable(header, body);	break;
		case Entry::OverflowCapture:	OnOverflow(header, body);		break;
		case Entry::RecorderLoss:		OnLoss(header, body);			break;
		default:														break;
		}
	}

	if (reader.IsTruncated())
		std::printf("# the file ends inside an entry\n");

	return 0;
}

bool CTimelineReport::IsVisible(const EntryHeader &header) const
{
	const double seconds = double(header.time) / 1000000.0;
	const bool inWindow = seconds >= m_Filter.fromSeconds && (m_Filter.toSeconds < 0.0 || seconds <= m_Filter.toSeconds);
	const bool addressMatches = !header.endpoint.IsValid() || m_Endpoints.Matches(header.endpoint, m_Filter.address);
	return inWindow && addressMatches;
}

void CTimelineReport::PrintLineStart(const EntryHeader &header, const char *direction) const
{
	std::printf("%s %s %-3s %-26s ", m_Clock->Relative(header.time).c_str(), m_Clock->LocalTime(header.time).c_str(),
		direction, header.endpoint.IsValid() ? m_Endpoints.Describe(header.endpoint).c_str() : "");
}

void CTimelineReport::OnDatagram(const EntryHeader &header, const uint8_t *body)
{
	if (header.length < sizeof(DatagramEntry))
		return;

	DatagramEntry datagram;
	std::memcpy(&datagram, body, sizeof(datagram));

	const uint8_t *data = body + sizeof(datagram);
	const size_t length = header.length - sizeof(datagram);
	const bool print = IsVisible(header);
	const char *direction = ToString(datagram.direction);

	if (datagram.type == Datagram::Channel)
	{
		if (print)
			PrintLineStart(header, direction);
		OnChannelPacket(header, datagram.direction, data, length, print, "");
		return;
	}

	if (datagram.type == Datagram::Connectionless)
	{
		if (!print)
			return;

		PrintLineStart(header, direction);
		const bool scrubbed = HasAny(DatagramFlags(header.flags), DatagramFlags::Scrubbed);
		std::printf("connectionless len=%zu%s ", length, scrubbed ? " scrubbed" : "");
		PrintConnectionless(data, length);
		std::printf("\n");
		return;
	}

	if (datagram.type != Datagram::Split && datagram.type != Datagram::SplitExtended)
	{
		if (print)
		{
			PrintLineStart(header, direction);
			std::printf("%s len=%zu\n", ToString(datagram.type), length);
		}
		return;
	}

	CSplitAssembler::Part part = {};
	CSplitAssembler &splits = m_Channels[header.endpoint].splits[Index(datagram.direction)];
	const CSplitAssembler::Result result = splits.Add(data, length, datagram.type == Datagram::SplitExtended, part, m_Joined);

	if (print)
	{
		PrintLineStart(header, direction);
		if (result == CSplitAssembler::Result::Malformed)
			std::printf("%s len=%zu MALFORMED\n", ToString(datagram.type), length);
		else
			std::printf("%s part %u/%u len=%zu\n", ToString(datagram.type), part.number + 1, part.count, length);
	}

	if (result != CSplitAssembler::Result::Complete)
		return;

	// The joined packet is copied: decoding it reuses the assembler's buffer
	const std::vector<uint8_t> joined(m_Joined);
	const Datagram joinedType = ClassifyDatagram(joined.data(), joined.size());

	if (print)
		PrintLineStart(header, direction);

	if (joinedType == Datagram::Channel)
	{
		OnChannelPacket(header, datagram.direction, joined.data(), joined.size(), print, "joined ");
	}
	else if (print)
	{
		std::printf("joined %s len=%zu ", ToString(joinedType), joined.size());
		if (joinedType == Datagram::Connectionless)
			PrintConnectionless(joined.data(), joined.size());
		std::printf("\n");
	}
}

void CTimelineReport::OnChannelPacket(const EntryHeader &header, Direction direction, const uint8_t *data, size_t length, bool print, const char *prefix)
{
	ChannelPacket packet;
	if (!DecodeChannelPacket(data, length, m_Demunged, packet))
	{
		if (print)
			std::printf("%schannel len=%zu MALFORMED\n", prefix, length);
		return;
	}

	ChannelState &channel = m_Channels[header.endpoint];
	const int own = Index(direction);
	const int peer = Index(Opposite(direction));

	std::map<uint32_t, uint64_t> &sent = channel.sentAt[own];
	sent[packet.sequence] = header.time;
	while (!sent.empty() && sent.begin()->first + SENT_SEQUENCE_WINDOW < packet.sequence)
		sent.erase(sent.begin());

	// A packet acknowledges the newest packet it has seen from the other end
	double roundTripMilliseconds = -1.0;
	if (!channel.acknowledgedSeen[own] || packet.acknowledged > channel.newestAcknowledged[own])
	{
		const std::map<uint32_t, uint64_t> &other = channel.sentAt[peer];
		const std::map<uint32_t, uint64_t>::const_iterator acknowledged = other.find(packet.acknowledged);
		if (acknowledged != other.end())
			roundTripMilliseconds = double(header.time - acknowledged->second) / 1000.0;

		channel.newestAcknowledged[own] = packet.acknowledged;
		channel.acknowledgedSeen[own] = true;
	}

	std::string fragments;
	std::string completions[CHANNEL_STREAMS];

	for (int stream = 0; stream < CHANNEL_STREAMS; stream++)
	{
		const FragmentHeader &fragment = packet.fragments[stream];
		if (!fragment.present)
			continue;

		CFragmentAssembler &assembler = channel.streams[own][stream];
		const CFragmentAssembler::Result result = assembler.Add(fragment, &m_Demunged[packet.payloadOffset + fragment.offset]);

		char text[96];
		std::snprintf(text, sizeof(text), " %s=%u/%u @%u+%u%s", stream ? "file" : "frag",
			fragment.index, fragment.count, fragment.offset, fragment.length, FragmentResultName(result));
		fragments += text;

		if (result == CFragmentAssembler::Result::Completed)
			completions[stream] = DescribeCompletedStream(stream, assembler);
	}

	if (!print)
		return;

	std::printf("%schannel seq=%u ack=%u rel=%d relack=%d len=%zu%s", prefix, packet.sequence, packet.acknowledged,
		packet.reliable ? 1 : 0, packet.reliableAcknowledged ? 1 : 0, length, fragments.c_str());

	if (packet.security)
		std::printf(" security");
	if (roundTripMilliseconds >= 0.0)
		std::printf(" rtt=%.1fms", roundTripMilliseconds);
	std::printf("\n");

	for (const std::string &completion : completions)
	{
		if (!completion.empty())
			std::printf("%*s%s\n", CONTINUATION_INDENT, "", completion.c_str());
	}
}

//-----------------------------------------------------------------------------
// A compressed normal stream is shown with its size after decompression; the
// file stream carries a file name before its data and is shown as sent
//-----------------------------------------------------------------------------
std::string CTimelineReport::DescribeCompletedStream(int stream, const CFragmentAssembler &assembler)
{
	const std::vector<uint8_t> &message = assembler.GetMessage();

	char line[160];
	std::snprintf(line, sizeof(line), "%s stream complete: %u fragments, %zu bytes", stream ? "file" : "normal", assembler.GetCount(), message.size());
	std::string description = line;

	if (stream != 0 || !assembler.IsCompressed())
		return description;

	const CStreamDecompressor::Result result = m_Decompressor.Decompress(message, m_Decompressed);
	if (result == CStreamDecompressor::Result::Decompressed)
		std::snprintf(line, sizeof(line), ", bzip2 to %zu bytes", m_Decompressed.size());
	else
		std::snprintf(line, sizeof(line), ", bzip2 %s", CStreamDecompressor::ToString(result));

	return description + line;
}

void CTimelineReport::PrintConnectionless(const uint8_t *data, size_t length)
{
	const size_t end = length < 4 + CONNECTIONLESS_PREVIEW ? length : 4 + CONNECTIONLESS_PREVIEW;

	std::printf("\"");
	for (size_t i = 4; i < end; i++)
	{
		const uint8_t c = data[i];
		if (c == '\n')
			std::printf("\\n");
		else if (c == '"')
			std::printf("\\\"");
		else if (c >= 32 && c < 127)
			std::printf("%c", c);
		else
			std::printf(".");
	}
	std::printf("\"%s", end < length ? "..." : "");
}

//-----------------------------------------------------------------------------
// A connect opens a new session with that endpoint: its channel starts over at
// sequence 1, so nothing of the previous session's channel carries over
//-----------------------------------------------------------------------------
void CTimelineReport::OnEvent(const EntryHeader &header, const uint8_t *body)
{
	if (header.length < sizeof(EventEntry))
		return;

	EventEntry event;
	std::memcpy(&event, body, sizeof(event));

	int session = 0;
	if (event.event == Event::Connect && header.endpoint.IsValid())
	{
		m_Channels.erase(header.endpoint);
		session = ++m_Sessions[header.endpoint];
	}

	if (!IsVisible(header))
		return;

	PrintLineStart(header, "");
	if (session)
		std::printf("event %s, session %d: %s\n", ToString(event.event), session, reinterpret_cast<const char *>(body + sizeof(event)));
	else
		std::printf("event %s %s\n", ToString(event.event), reinterpret_cast<const char *>(body + sizeof(event)));
}

void CTimelineReport::OnFrame(const EntryHeader &header, const uint8_t *body)
{
	if (header.length < sizeof(FrameEntry) || !IsVisible(header))
		return;

	FrameEntry frame;
	std::memcpy(&frame, body, sizeof(frame));

	// The entry closes the frame before it
	const double milliseconds = frame.durationMicroseconds / 1000.0;
	if (frame.durationMicroseconds == 0 || milliseconds < m_Filter.slowFrameMilliseconds)
		return;

	PrintLineStart(header, "");
	std::printf("frame %" PRIu64 " took %.1f ms\n", frame.frameNumber - 1, milliseconds);
}

void CTimelineReport::OnSessionTable(const EntryHeader &header, const uint8_t *body)
{
	if (!IsVisible(header))
		return;

	char text[160] = "damaged";
	if (header.type == Entry::ServerInfo && header.length > sizeof(ServerInfoEntry))
	{
		ServerInfoEntry info;
		std::memcpy(&info, body, sizeof(info));

		// A map name that does not end inside the body is a damaged entry
		const char *map = reinterpret_cast<const char *>(body + sizeof(info));
		if (std::memchr(map, 0, header.length - sizeof(info)))
			std::snprintf(text, sizeof(text), "%s, %d players", map, info.maxClients);
	}
	else if (header.type == Entry::UserMessages && header.length >= sizeof(UserMessagesEntry))
	{
		UserMessagesEntry list;
		std::memcpy(&list, body, sizeof(list));
		std::snprintf(text, sizeof(text), "%u", list.count);
	}
	else if (header.type == Entry::DeltaDescription && header.length >= sizeof(DeltaDescriptionEntry))
	{
		DeltaDescriptionEntry description;
		std::memcpy(&description, body, sizeof(description));
		description.name[sizeof(description.name) - 1] = '\0';
		std::snprintf(text, sizeof(text), "%s, %u fields", description.name, description.fieldCount);
	}
	else if (header.type == Entry::Precache && header.length >= sizeof(PrecacheEntry))
	{
		PrecacheEntry list;
		std::memcpy(&list, body, sizeof(list));
		std::snprintf(text, sizeof(text), "%u %ss", list.count, ToString(list.kind));
	}

	PrintLineStart(header, "");
	std::printf("%s: %s\n", ToString(header.type), text);
}

void CTimelineReport::OnOverflow(const EntryHeader &header, const uint8_t *body)
{
	if (header.length < sizeof(OverflowCaptureEntry) || !IsVisible(header))
		return;

	OverflowCaptureEntry state;
	std::memcpy(&state, body, sizeof(state));

	PrintLineStart(header, "");
	std::printf("RELIABLE BUFFER OVERFLOWED: %u of %u bytes queued, %u more asked; %u bytes in flight, client silent %u ms (see overflow)\n",
		state.queuedBytes, state.bufferBytes, state.requestedBytes, state.reliableInFlightBytes, state.silentMilliseconds);
}

void CTimelineReport::OnLoss(const EntryHeader &header, const uint8_t *body)
{
	if (header.length < sizeof(RecorderLossEntry))
		return;

	RecorderLossEntry loss;
	std::memcpy(&loss, body, sizeof(loss));

	PrintLineStart(header, "");
	std::printf("RECORDER LOST %u entries, %" PRIu64 " bytes: its queue was full\n", loss.entries, loss.bytes);
}

} // namespace NetInspector
