//=============================================================================//
//
// The health of the traffic in a recording
//
//=============================================================================//

#include "health_report.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace NetInspector
{

namespace
{

constexpr uint64_t SECOND = 1000000;

// Reliable data acknowledged later than this, with the other end answering all along, was stuck
constexpr uint64_t STUCK_MICROSECONDS = 1000000;
constexpr uint64_t LONG_STUCK_MICROSECONDS = 3000000;
constexpr uint32_t STUCK_ANSWERS = 10;

// Bytes of messages the server wrote to one player in one second
constexpr uint32_t FLOOD_BYTES = 32 * 1024;
constexpr uint32_t HEAVY_FLOOD_BYTES = 64 * 1024;

constexpr uint32_t HANG_MICROSECONDS = 50000;
constexpr uint32_t LONG_HANG_MICROSECONDS = 200000;
constexpr uint32_t SLOW_PARSING_MICROSECONDS = 20000;
constexpr uint32_t VERY_SLOW_PARSING_MICROSECONDS = 100000;
constexpr uint32_t HANG_PATTERN_MINIMUM = 3;
constexpr double HANG_PATTERN_RATIO = 3.0;		// as much likelier during a hang than in any frame

// A second with this share of the packets lost, and at least this many
constexpr double LOSS_SHARE = 0.05;
constexpr double HEAVY_LOSS_SHARE = 0.20;
constexpr uint32_t LOSS_MINIMUM = 5;

constexpr uint64_t SILENCE_MICROSECONDS = 2000000;

constexpr size_t LISTED_MESSAGES = 6;

std::string Format(const char *format, ...)
{
	char text[512];
	va_list arguments;
	va_start(arguments, format);
	std::vsnprintf(text, sizeof(text), format, arguments);
	va_end(arguments);
	return text;
}

double Seconds(uint64_t microseconds)
{
	return (double)microseconds / 1000000.0;
}

bool ByValue(const std::pair<std::string, uint32_t> &left, const std::pair<std::string, uint32_t> &right)
{
	return left.second > right.second;
}

// "name 1234, name 567, ..." of the largest values
std::string Largest(const std::map<std::string, uint32_t> &values, const char *unit)
{
	std::vector<std::pair<std::string, uint32_t>> sorted(values.begin(), values.end());
	std::sort(sorted.begin(), sorted.end(), ByValue);

	std::string text;
	for (size_t i = 0; i < sorted.size() && i < LISTED_MESSAGES; i++)
		text += Format("%s%s %u%s", i ? ", " : "", sorted[i].first.c_str(), sorted[i].second, unit);
	return text;
}

// The command of a clc_stringcmd as the decoder quotes it: its first word
std::string CommandName(const std::string &quoted)
{
	const size_t start = quoted.empty() || quoted[0] != '"' ? 0 : 1;
	const size_t end = quoted.find_first_of(" \"\\", start);
	return quoted.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

// The commands clc_move held back on the client before this packet, each of which took a sequence number
uint32_t HeldBackCommands(const DecodedStream &decoded)
{
	for (const DecodedMessage &message : decoded.messages)
	{
		int commands = 0;
		if (message.name == "clc_move" && std::sscanf(message.text.c_str(), "%d new", &commands) == 1 && commands > 1)
			return (uint32_t)(commands - 1);
	}

	return 0;
}

} // namespace

int CHealthReport::Run(CReader &reader)
{
	const CReportClock clock(reader.GetHeader());
	m_Clock = &clock;

	m_Walker.Walk(reader, *this);

	// What was still in flight when the recording ended
	for (std::pair<const EndpointId, EndpointHealth> &endpoint : m_Endpoints)
	{
		EndpointHealth &health = endpoint.second;
		const uint64_t end = health.lastHeard;
		if (health.toRemote.pending && end > health.toRemote.since + STUCK_MICROSECONDS && health.toRemote.answers >= STUCK_ANSWERS)
			ReportStuck(health.toRemote, endpoint.first, ToString(m_Walker.GetRole()), end, Severity::High, "still not acknowledged when the recording ends");
		CloseFloodSecond(health, endpoint.first);
		CountLoss(health, endpoint.first, UINT64_MAX, 0, 0);
	}

	ReportHangPatterns();

	if (IsJson())
	{
		m_Findings.Write(m_Walker.GetEndpoints(), GetPath(), m_Json);
		return 0;
	}

	if (m_Findings.IsEmpty())
		std::printf("nothing went wrong with the traffic\n");
	else
		m_Findings.Print(m_Walker.GetEndpoints(), clock, GetPath());
	return 0;
}

void CHealthReport::OnDatagram(const EntryHeader &header, const DatagramEntry &datagram, const uint8_t *, size_t)
{
	if (datagram.direction != Direction::In)
		return;

	if (datagram.type == Datagram::Connectionless)
		m_Frame.connectionless++;
	else
		m_Frame.packets[header.endpoint]++;

	EndpointHealth &health = m_Endpoints[header.endpoint];
	if (health.heard && datagram.type != Datagram::Connectionless && header.time - health.lastHeard > SILENCE_MICROSECONDS)
	{
		m_Findings.Add(Severity::Medium, header.endpoint, "sent nothing for a while", header.time,
			Format("nothing from it for %.3f s before %s", Seconds(header.time - health.lastHeard), m_Clock->Relative(header.time).c_str()));
	}

	if (datagram.type != Datagram::Connectionless)
	{
		health.heard = true;
		health.lastHeard = header.time;
	}
}

void CHealthReport::Send(ReliableFlow &flow, uint32_t sequence, uint64_t time)
{
	if (!flow.known)
		return;

	if (flow.pending)
	{
		flow.lastSequence = sequence;
		flow.sends++;
		return;
	}

	flow.bit = !flow.bit;
	flow.pending = true;
	flow.since = time;
	flow.firstSequence = sequence;
	flow.lastSequence = sequence;
	flow.sends = 1;
	flow.answers = 0;
	flow.acknowledged = 0;
	flow.content.clear();
}

void CHealthReport::Answer(ReliableFlow &flow, EndpointId endpoint, const char *sender, uint32_t acknowledged, bool echo, uint64_t time)
{
	// With nothing in flight the echo is the sender's bit
	if (!flow.known)
	{
		if (!flow.pending)
		{
			flow.known = true;
			flow.bit = echo;
		}
		return;
	}

	if (!flow.pending)
		return;

	flow.answers++;
	flow.acknowledged = std::max(flow.acknowledged, acknowledged);

	if (echo != flow.bit || acknowledged < flow.lastSequence)
		return;

	const uint64_t duration = time - flow.since;
	if (duration > STUCK_MICROSECONDS && flow.answers >= STUCK_ANSWERS)
	{
		const Severity severity = duration > LONG_STUCK_MICROSECONDS ? Severity::High : Severity::Medium;
		ReportStuck(flow, endpoint, sender, time, severity, Format("acknowledged after %.3f s", Seconds(duration)).c_str());
	}

	flow.pending = false;
}

void CHealthReport::ReportStuck(const ReliableFlow &flow, EndpointId endpoint, const char *sender, uint64_t time, Severity severity, const char *ending)
{
	const char *kind = severity == Severity::Critical ? "reliable data never acknowledged, the player went" : "reliable data stuck while the other end answered";
	m_Findings.Add(severity, endpoint, Format("%s (%s's)", kind, sender), time,
		Format("first sent in seq %u at %s, sent %u times; the other end sent %u packets meanwhile, acknowledging up to seq %u, "
			"but not this reliable data; %s; it carried: %s", flow.firstSequence, m_Clock->Relative(flow.since).c_str(), flow.sends,
			flow.answers, flow.acknowledged, ending, flow.content.empty() ? "fragments only" : flow.content.c_str()));
}

void CHealthReport::OnChannelPacket(const ReceivedPacket &packet)
{
	if (packet.received.verdict != CChannelReceiver::Verdict::Accepted)
		return;

	EndpointHealth &health = m_Endpoints[packet.header.endpoint];
	const ChannelPacket &channel = packet.received.packet;
	const char *local = ToString(m_Walker.GetRole());
	const char *remote = m_Walker.GetRole() == Role::Server ? "client" : "server";

	// A packet of one end carries its own reliable data and acknowledges the other end's
	if (packet.direction == Direction::Out)
	{
		if (channel.reliable)
			Send(health.toRemote, channel.sequence, packet.header.time);
		Answer(health.fromRemote, packet.header.endpoint, remote, channel.acknowledged, channel.reliableAcknowledged, packet.header.time);
		return;
	}

	if (channel.reliable)
		Send(health.fromRemote, channel.sequence, packet.header.time);
	Answer(health.toRemote, packet.header.endpoint, local, channel.acknowledged, channel.reliableAcknowledged, packet.header.time);

	if (!packet.received.processed)
		CountLoss(health, packet.header.endpoint, packet.header.time, 1, packet.received.skipped);
}

void CHealthReport::OnStream(const ReceivedPacket &packet, const PacketStream &stream)
{
	EndpointHealth &health = m_Endpoints[packet.header.endpoint];
	const ChannelPacket &channel = packet.received.packet;

	// What the first packet of a reliable message carried
	ReliableFlow &flow = packet.direction == Direction::Out ? health.toRemote : health.fromRemote;
	if (!stream.fragmented && flow.pending && flow.firstSequence == channel.sequence && flow.content.empty())
	{
		std::map<std::string, uint32_t> names;
		for (const DecodedMessage &message : stream.decoded.messages)
		{
			if (message.name != "svc_nop" && message.name != "clc_nop")
				names[message.name]++;
		}
		flow.content = Largest(names, "x");
	}

	if (packet.source == MessageSource::Server)
	{
		// A client plays once entities come
		for (const DecodedMessage &message : stream.decoded.messages)
		{
			if (message.name == "svc_packetentities" || message.name == "svc_deltapacketentities")
				m_Loading = false;
		}

		CountFlood(health, packet.header.endpoint, packet.header.time, stream.decoded);
		if (packet.direction == Direction::In && !stream.fragmented)
			CountLoss(health, packet.header.endpoint, packet.header.time, 1, packet.received.skipped);
		return;
	}

	// The client's messages: what reached the server in this frame, and what was really lost before them
	if (packet.direction != Direction::In)
		return;

	for (const DecodedMessage &message : stream.decoded.messages)
	{
		m_Frame.messages[message.name]++;
		if (message.name == "clc_stringcmd")
			m_Frame.commands[packet.header.endpoint].insert(CommandName(message.text));
	}

	if (!stream.fragmented)
	{
		const uint32_t heldBack = HeldBackCommands(stream.decoded);
		const uint32_t skipped = packet.received.skipped;
		CountLoss(health, packet.header.endpoint, packet.header.time, 1, skipped > heldBack ? skipped - heldBack : 0);
	}
}

void CHealthReport::CountFlood(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded)
{
	if (time / SECOND != health.second)
	{
		CloseFloodSecond(health, endpoint);
		health.second = time / SECOND;
	}

	for (const DecodedMessage &message : decoded.messages)
	{
		health.bytes += (uint32_t)message.length;
		health.bytesByMessage[message.name] += (uint32_t)message.length;
	}
}

void CHealthReport::CloseFloodSecond(EndpointHealth &health, EndpointId endpoint)
{
	if (health.bytes >= FLOOD_BYTES)
	{
		const Severity severity = health.bytes >= HEAVY_FLOOD_BYTES ? Severity::High : Severity::Medium;
		m_Findings.Add(severity, endpoint, "the server flooded the player", health.second * SECOND,
			Format("%u bytes of messages in the second from %s: %s", health.bytes, m_Clock->Relative(health.second * SECOND).c_str(),
				Largest(health.bytesByMessage, " bytes").c_str()));
	}

	health.bytes = 0;
	health.bytesByMessage.clear();
}

void CHealthReport::CountLoss(EndpointHealth &health, EndpointId endpoint, uint64_t time, uint32_t received, uint32_t lost)
{
	const uint64_t second = time == UINT64_MAX ? UINT64_MAX : time / SECOND;
	if (second != health.lossSecond)
	{
		const uint32_t sent = health.received + health.lost;
		const double share = sent ? (double)health.lost / (double)sent : 0.0;
		if (health.lost >= LOSS_MINIMUM && share >= LOSS_SHARE)
		{
			const char *from = m_Walker.GetRole() == Role::Server ? "the client" : "the server";
			m_Findings.Add(share >= HEAVY_LOSS_SHARE ? Severity::High : Severity::Medium, endpoint, Format("packets from %s lost on the way", from),
				health.lossSecond * SECOND, Format("%u of %u lost in the second from %s (%.0f%%)", health.lost, sent,
					m_Clock->Relative(health.lossSecond * SECOND).c_str(), share * 100.0));
		}

		health.lossSecond = second;
		health.received = 0;
		health.lost = 0;
	}

	health.received += received;
	health.lost += lost;
}

void CHealthReport::OnEvent(const EntryHeader &header, const EventEntry &event, const char *text)
{
	if (!header.endpoint.IsValid())
		return;

	EndpointHealth &health = m_Endpoints[header.endpoint];
	if (event.event == Event::Connect)
	{
		if (m_Walker.GetRole() == Role::Client)
			m_Loading = true;

		health.toRemote = ReliableFlow();
		health.fromRemote = ReliableFlow();
		health.heard = false;
		return;
	}

	if (event.event != Event::ClientDropped && event.event != Event::Disconnect)
		return;

	if (health.toRemote.pending && header.time > health.toRemote.since + STUCK_MICROSECONDS && health.toRemote.answers >= STUCK_ANSWERS)
		ReportStuck(health.toRemote, header.endpoint, ToString(m_Walker.GetRole()), header.time, Severity::Critical, (std::string("then dropped: ") + text).c_str());

	health.toRemote.pending = false;
	health.heard = false;
}

void CHealthReport::OnOverflow(const EntryHeader &header, const OverflowCaptureEntry &)
{
	EndpointHealth &health = m_Endpoints[header.endpoint];
	if (health.toRemote.pending && header.time > health.toRemote.since + STUCK_MICROSECONDS && health.toRemote.answers >= STUCK_ANSWERS)
		ReportStuck(health.toRemote, header.endpoint, ToString(m_Walker.GetRole()), header.time, Severity::Critical, "then the reliable buffer overflowed");
	health.toRemote.pending = false;
}

void CHealthReport::OnSessionTable(const EntryHeader &header)
{
	if (header.type == Entry::ServerInfo && m_Walker.GetRole() == Role::Server)
		m_Frame.mapLoaded = true;
}

void CHealthReport::OnProcessTime(const EntryHeader &header, const ProcessTimeEntry &entry)
{
	m_Frame.parsing[header.endpoint] += entry.microseconds;
	if (entry.microseconds < SLOW_PARSING_MICROSECONDS)
		return;

	std::string commands;
	for (const std::string &command : m_Frame.commands[header.endpoint])
		commands += (commands.empty() ? "" : ", ") + command;

	const Severity severity = entry.microseconds >= VERY_SLOW_PARSING_MICROSECONDS ? Severity::High : Severity::Medium;
	m_Findings.Add(severity, header.endpoint, "the server took long over its messages", header.time,
		Format("%.1f ms over its messages at %s; string commands in that frame: %s", entry.microseconds / 1000.0,
			m_Clock->Relative(header.time).c_str(), commands.empty() ? "none" : commands.c_str()));
}

// A frame entry closes the frame before it: what came in since the last entry came in during that frame
void CHealthReport::OnFrame(const EntryHeader &header, const FrameEntry &frame)
{
	if (frame.durationMicroseconds == 0)
		return;

	m_Frames++;
	for (const std::string &name : SeenInFrame())
		m_FrameMessages[name]++;

	if (frame.durationMicroseconds >= HANG_MICROSECONDS && !m_Loading && !m_Frame.mapLoaded)
		ReportHang(header, frame);

	m_Frame = FrameTraffic();
}

// The client messages and string commands that came in during the frame, each once
std::set<std::string> CHealthReport::SeenInFrame() const
{
	std::set<std::string> seen;
	for (const std::pair<const std::string, uint32_t> &message : m_Frame.messages)
	{
		if (message.first != "clc_stringcmd")
			seen.insert(message.first);
	}

	for (const std::pair<const EndpointId, std::set<std::string>> &client : m_Frame.commands)
	{
		for (const std::string &command : client.second)
			seen.insert("stringcmd " + command);
	}

	return seen;
}

void CHealthReport::ReportHang(const EntryHeader &header, const FrameEntry &frame)
{
	m_Hangs++;

	uint32_t packets = 0;
	for (const std::pair<const EndpointId, uint32_t> &endpoint : m_Frame.packets)
		packets += endpoint.second;

	EndpointId slowest = NO_ENDPOINT;
	uint32_t parsing = 0;
	for (const std::pair<const EndpointId, uint32_t> &endpoint : m_Frame.parsing)
	{
		if (endpoint.second > parsing)
		{
			parsing = endpoint.second;
			slowest = endpoint.first;
		}
	}

	for (const std::string &name : SeenInFrame())
		m_HangMessages[name]++;

	std::string commands;
	for (const std::pair<const EndpointId, std::set<std::string>> &client : m_Frame.commands)
	{
		for (const std::string &command : client.second)
			commands += Format("%s%s from %s", commands.empty() ? "" : ", ", command.c_str(), m_Walker.GetEndpoints().Describe(client.first).c_str());
	}

	const Severity severity = frame.durationMicroseconds >= LONG_HANG_MICROSECONDS ? Severity::High : Severity::Medium;
	const std::string detail = Format("frame %llu took %.1f ms; during it %u packets from %zu endpoints, %u connectionless; ",
		(unsigned long long)(frame.frameNumber - 1), frame.durationMicroseconds / 1000.0, packets, m_Frame.packets.size(), m_Frame.connectionless)
		+ (parsing ? Format("the longest parsing %.1f ms, of %s's messages; ", parsing / 1000.0, m_Walker.GetEndpoints().Describe(slowest).c_str()) : std::string())
		+ "string commands: " + (commands.empty() ? std::string("none") : commands);

	// A hang mostly spent over one client's messages is that client's
	if (parsing * 2 >= frame.durationMicroseconds)
		m_Findings.Add(severity, slowest, "the server hung over its messages", header.time, detail);
	else
		m_Findings.Add(severity, NO_ENDPOINT, "the recording program hung", header.time, detail);
}

void CHealthReport::ReportHangPatterns()
{
	if (m_Hangs < HANG_PATTERN_MINIMUM)
		return;

	// What comes in during most hangs and far more rarely in other frames
	for (const std::pair<const std::string, uint32_t> &message : m_HangMessages)
	{
		const double hangShare = (double)message.second / (double)m_Hangs;
		const double frameShare = m_Frames ? (double)m_FrameMessages[message.first] / (double)m_Frames : 1.0;
		if (message.second < HANG_PATTERN_MINIMUM || hangShare < 0.5 || hangShare < frameShare * HANG_PATTERN_RATIO)
			continue;

		m_Findings.Add(Severity::Medium, NO_ENDPOINT, "came in during most hangs: " + message.first, 0,
			Format("%s came in during %u of %u hangs, and during %.1f%% of all frames", message.first.c_str(), message.second, m_Hangs, frameShare * 100.0));
	}
}

} // namespace NetInspector
