//=============================================================================//
//
// The message-level view of a recording
//
//=============================================================================//

#include "messages_report.h"

#include <cinttypes>
#include <cstdio>

#include <CLI/CLI.hpp>

namespace NetInspector
{

namespace
{

const char *VerdictName(CChannelReceiver::Verdict verdict)
{
	switch (verdict)
	{
	case CChannelReceiver::Verdict::Accepted:	return "accepted";
	case CChannelReceiver::Verdict::Stale:		return "DROPPED: not newer than the last accepted sequence";
	case CChannelReceiver::Verdict::Security:	return "DROPPED: security bit";
	case CChannelReceiver::Verdict::Malformed:	return "MALFORMED";
	}

	return "unknown";
}

double Seconds(uint64_t microseconds)
{
	return (double)microseconds / 1000000.0;
}

} // namespace

void CMessagesReport::AddOptions(CLI::App &subcommand)
{
	subcommand.add_option("--address", m_Filter.address, "only this endpoint: #id or ip:port, as info lists them");
	subcommand.add_option("--message", m_Filter.message, "only messages whose name holds this, such as svc_stufftext or SayText");
	subcommand.add_option("--from", m_Filter.fromSeconds, "seconds since the recording started");
	subcommand.add_option("--to", m_Filter.toSeconds, "seconds since the recording started");
	subcommand.add_flag("--dropped", m_Filter.dropped, "the packets the receiving end dropped as well");
}

int CMessagesReport::Run(CReader &reader)
{
	const FileHeader &file = reader.GetHeader();
	const CReportClock clock(file);
	m_Clock = &clock;

	if (IsJson())
	{
		m_Json.BeginObject();
		m_Json.Field("type", "file");
		m_Json.Field("application", file.application);
		m_Json.Field("role", ToString(file.role));
		m_Json.Field("startedUtc", clock.UtcDateTime(0));
		m_Json.Field("note", "\"in\" is what the recording program received");
		m_Json.EndObject();
		m_Json.EndLine();
	}
	else
	{
		std::printf("# %s as %s, started %s UTC; \"in\" is what the %s received\n",
			file.application, ToString(file.role), clock.UtcDateTime(0).c_str(), ToString(file.role));
	}

	m_Walker.Walk(reader, *this);

	if (IsJson())
	{
		m_Json.BeginObject();
		m_Json.Field("type", "summary");
		m_Json.Field("streamsDecoded", m_Walker.GetStreamCount());
		m_Json.Field("streamsStopped", m_Walker.GetStoppedCount());
		m_Json.Field("truncated", reader.IsTruncated());
		m_Json.EndObject();
		m_Json.EndLine();
		return 0;
	}

	std::printf("# %" PRIu64 " message streams decoded, %" PRIu64 " stopped before their end\n", m_Walker.GetStreamCount(), m_Walker.GetStoppedCount());
	if (reader.IsTruncated())
		std::printf("# the file ends inside an entry\n");

	return 0;
}

bool CMessagesReport::IsVisible(const EntryHeader &header) const
{
	const double seconds = Seconds(header.time);
	const bool inWindow = seconds >= m_Filter.fromSeconds && (m_Filter.toSeconds < 0.0 || seconds <= m_Filter.toSeconds);
	const bool addressMatches = !header.endpoint.IsValid() || m_Walker.GetEndpoints().Matches(header.endpoint, m_Filter.address);
	return inWindow && addressMatches;
}

bool CMessagesReport::Shows(const DecodedMessage &message) const
{
	return m_Filter.message.empty() || message.name.find(m_Filter.message) != std::string::npos;
}

void CMessagesReport::PrintLineStart(const EntryHeader &header, const char *direction) const
{
	std::printf("%s %s %-3s %-26s ", m_Clock->Relative(header.time).c_str(), m_Clock->LocalTime(header.time).c_str(),
		direction, header.endpoint.IsValid() ? m_Walker.GetEndpoints().Describe(header.endpoint).c_str() : "");
}

std::string CMessagesReport::DescribePacket(const ReceivedPacket &packet, const PacketStream &stream) const
{
	const ChannelPacket &channel = packet.received.packet;

	char text[128];
	if (stream.fragmented)
	{
		std::snprintf(text, sizeof(text), "seq=%u fragmented stream complete, %zu bytes%s", channel.sequence, stream.bytes.size(),
			stream.decompressed ? " after bzip2" : "");
	}
	else
	{
		std::snprintf(text, sizeof(text), "seq=%u ack=%u%s%s len=%zu", channel.sequence, channel.acknowledged,
			channel.reliable ? " rel" : "", packet.received.skipped ? " after a gap" : "", packet.length);
	}

	return text;
}

void CMessagesReport::OnEvent(const EntryHeader &header, const EventEntry &event, const char *)
{
	if (event.event != Event::Connect || !header.endpoint.IsValid() || !IsVisible(header) || !m_Filter.message.empty())
		return;

	if (IsJson())
	{
		m_Json.BeginObject();
		m_Json.Field("type", "connect");
		m_Json.Field("time", Seconds(header.time));
		m_Json.Field("endpoint", m_Walker.GetEndpoints().Describe(header.endpoint));
		m_Json.EndObject();
		m_Json.EndLine();
		return;
	}

	PrintLineStart(header, "");
	std::printf("connect: a new session\n");
}

void CMessagesReport::OnChannelPacket(const ReceivedPacket &packet)
{
	const CChannelReceiver::Verdict verdict = packet.received.verdict;
	if (verdict == CChannelReceiver::Verdict::Accepted || !m_Filter.dropped || !m_Filter.message.empty() || !IsVisible(packet.header))
		return;

	if (IsJson())
	{
		m_Json.BeginObject();
		m_Json.Field("type", "dropped");
		m_Json.Field("time", Seconds(packet.header.time));
		m_Json.Field("endpoint", m_Walker.GetEndpoints().Describe(packet.header.endpoint));
		m_Json.Field("direction", ToString(packet.direction));
		m_Json.Field("sequence", packet.received.packet.sequence);
		m_Json.Field("reason", VerdictName(verdict));
		m_Json.EndObject();
		m_Json.EndLine();
		return;
	}

	PrintLineStart(packet.header, ToString(packet.direction));
	std::printf("seq=%u %s\n", packet.received.packet.sequence, VerdictName(verdict));
}

void CMessagesReport::OnFileStream(const ReceivedPacket &packet)
{
	if (!IsVisible(packet.header) || !m_Filter.message.empty() || IsJson())
		return;

	PrintLineStart(packet.header, ToString(packet.direction));
	std::printf("seq=%u file stream complete, %zu bytes\n", packet.received.packet.sequence, packet.received.streams[1].size());
}

void CMessagesReport::OnStream(const ReceivedPacket &packet, const PacketStream &stream)
{
	if (!IsVisible(packet.header))
		return;

	bool any = m_Filter.message.empty();
	for (const DecodedMessage &message : stream.decoded.messages)
		any = any || Shows(message);

	if (!any)
		return;

	if (IsJson())
		WriteStream(packet, stream);
	else
		PrintStream(packet, stream);
}

void CMessagesReport::PrintStream(const ReceivedPacket &packet, const PacketStream &stream)
{
	PrintLineStart(packet.header, ToString(packet.direction));
	std::printf("%s\n", DescribePacket(packet, stream).c_str());

	const std::vector<DecodedMessage> &messages = stream.decoded.messages;
	for (size_t i = 0; i < messages.size(); i++)
	{
		const DecodedMessage &message = messages[i];
		if (!Shows(message))
			continue;

		// The padding a short packet gets is a run of nops: one line for the run
		size_t repeats = 1;
		while (message.text.empty() && i + repeats < messages.size() && messages[i + repeats].id == message.id && messages[i + repeats].text.empty())
			repeats++;

		if (repeats > 1)
		{
			std::printf("    %-24s %4zu x%zu\n", message.name.c_str(), message.length * repeats, repeats);
			i += repeats - 1;
			continue;
		}

		std::printf("    %-24s %4zu %s\n", message.name.c_str(), message.length, message.text.c_str());
	}

	if (!stream.decoded.complete && m_Filter.message.empty())
		std::printf("    STOPPED at byte %zu of %zu: %s\n", stream.decoded.stoppedAt, stream.bytes.size(), stream.decoded.error.c_str());
}

void CMessagesReport::WriteStream(const ReceivedPacket &packet, const PacketStream &stream)
{
	const ChannelPacket &channel = packet.received.packet;

	m_Json.BeginObject();
	m_Json.Field("type", stream.fragmented ? "fragmented" : "packet");
	m_Json.Field("time", Seconds(packet.header.time));
	m_Json.Field("endpoint", m_Walker.GetEndpoints().Describe(packet.header.endpoint));
	m_Json.Field("direction", ToString(packet.direction));
	m_Json.Field("summary", DescribePacket(packet, stream));
	m_Json.Field("sequence", channel.sequence);
	m_Json.Field("acknowledged", channel.acknowledged);
	m_Json.Field("reliable", channel.reliable);
	m_Json.Field("skipped", packet.received.skipped);
	m_Json.Field("streamBytes", (uint64_t)stream.bytes.size());
	m_Json.Field("decompressed", stream.decompressed);
	m_Json.Field("decoded", stream.decoded.complete);
	if (!stream.decoded.complete)
	{
		m_Json.Field("stoppedAt", (uint64_t)stream.decoded.stoppedAt);
		m_Json.Field("error", stream.decoded.error);
	}

	m_Json.Key("messages");
	m_Json.BeginArray();
	for (const DecodedMessage &message : stream.decoded.messages)
	{
		if (!Shows(message))
			continue;

		m_Json.BeginObject();
		m_Json.Field("name", message.name);
		m_Json.Field("offset", (uint64_t)message.offset);
		m_Json.Field("length", (uint64_t)message.length);
		if (!message.text.empty())
			m_Json.Field("text", message.text);
		m_Json.EndObject();
	}
	m_Json.EndArray();

	m_Json.EndObject();
	m_Json.EndLine();
}

} // namespace NetInspector
