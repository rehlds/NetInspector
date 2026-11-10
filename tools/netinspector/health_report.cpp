//=============================================================================//
//
// The health of the traffic in a recording
//
//=============================================================================//

#include "health_report.h"

#include "netinspector/decoder/protocol.h"
#include "netinspector/decoder/server_packet.h"

#include <algorithm>
#include <cmath>
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

// A reliable message of the server carrying this share of MAX_MSGLEN or more is a batch worth naming.
// Past the whole of it HLDS drops the client and ReHLDS sends fragments.
constexpr double RELIABLE_BURST_SHARE = 0.5;

// The pace of reliable data over this window, and how late acknowledgements may come at that pace
// before netchan.message fills. A stretch shorter than the window is a batch, not a pace.
constexpr uint64_t LAG_WINDOW_MICROSECONDS = 1000000;
constexpr double LAG_TOLERANCE_MEDIUM_SECONDS = 1.0;
constexpr double LAG_TOLERANCE_HIGH_SECONDS = 0.3;

// A silence is the other end's when answers were this unlikely to all go missing by chance
constexpr double SILENCE_CHANCE = 0.001;

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

bool ByBytes(const std::pair<std::string, MessageTally> &left, const std::pair<std::string, MessageTally> &right)
{
	return left.second.bytes > right.second.bytes;
}

// "name 12x 345 bytes, ..." of the heaviest
std::string Heaviest(const std::map<std::string, MessageTally> &messages)
{
	std::vector<std::pair<std::string, MessageTally>> sorted(messages.begin(), messages.end());
	std::sort(sorted.begin(), sorted.end(), ByBytes);

	std::string text;
	for (size_t i = 0; i < sorted.size() && i < LISTED_MESSAGES; i++)
		text += Format("%s%s %ux %u bytes", i ? ", " : "", sorted[i].first.c_str(), sorted[i].second.count, sorted[i].second.bytes);
	return text;
}

// The first count messages of decoded, by name
void Tally(std::map<std::string, MessageTally> &tallies, const DecodedStream &decoded, size_t count)
{
	for (size_t i = 0; i < count && i < decoded.messages.size(); i++)
	{
		MessageTally &tally = tallies[decoded.messages[i].name];
		tally.count++;
		tally.bytes += (uint32_t)decoded.messages[i].length;
	}
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
		CloseLagTolerance(health, endpoint.first);
		ReportReliableBursts(health, endpoint.first);
		ReportServerLayout(health, endpoint.first);
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
	EndpointHealth &health = m_Endpoints[header.endpoint];
	if (datagram.direction != Direction::In)
	{
		if (datagram.type != Datagram::Connectionless)
		{
			health.sentTotal++;
			health.sentSinceHeard++;
		}
		return;
	}

	if (datagram.type == Datagram::Connectionless)
	{
		m_Frame.connectionless++;
		return;
	}
	m_Frame.packets[header.endpoint]++;

	// The answers due over the silence, at the rate it answered before; none of them coming by chance
	// is e^-due. A silence the recording program kept as well has none due: it is its own.
	if (health.heard && header.time - health.lastHeard > SILENCE_MICROSECONDS)
	{
		const uint64_t sentBefore = health.sentTotal - health.sentSinceHeard;
		const double due = sentBefore ? (double)health.sentSinceHeard * (double)health.heardTotal / (double)sentBefore : 0.0;
		if (due > -std::log(SILENCE_CHANCE))
		{
			m_Findings.Add(Severity::Medium, header.endpoint, "sent nothing for a while", header.time,
				Format("nothing from it for %.3f s before %s; %u packets went to it, about %.0f answers were due", Seconds(header.time - health.lastHeard),
					m_Clock->Relative(header.time).c_str(), health.sentSinceHeard, due));
		}
	}

	health.heard = true;
	health.lastHeard = header.time;
	health.heardTotal++;
	health.sentSinceHeard = 0;
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
		CountSignon(health, packet.header.endpoint, packet.header.time, stream.decoded);
		if (stream.fragmented)
		{
			MeasureFragmentedMessage(health, packet.header.endpoint, packet.header.time, stream.decoded);
			return;
		}

		MeasureServerPacket(health, packet, stream.decoded);
		if (packet.direction == Direction::In)
			CountLoss(health, packet.header.endpoint, packet.header.time, 1, packet.received.skipped);
		return;
	}

	CountResourceRequests(health, stream.decoded);

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

// The sign-on tables a server sends once a map: the resource list again without a new svc_serverinfo is odd
void CHealthReport::CountSignon(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded)
{
	for (const DecodedMessage &message : decoded.messages)
	{
		if (message.id == svc_packetentities || message.id == svc_deltapacketentities)
		{
			// A client plays once entities come
			if (m_Loading)
				m_PlayingSince = time;
			m_Loading = false;
			health.playing = true;
		}
		else if (message.id == svc_serverinfo)
		{
			health.playing = false;
			health.resourceLists = 0;
			health.resourceRequests = 0;
		}
		else if (message.id == svc_resourcelist)
		{
			if (health.resourceLists++ > 0)
			{
				m_Findings.Add(Severity::Medium, endpoint, "the server sent its resource list again in one sign-on", time,
					Format("list %u at %s, the first at %s, no svc_serverinfo between; the client asked with sendres %u more times; "
						"%s; %u bytes", health.resourceLists, m_Clock->Relative(time).c_str(), m_Clock->Relative(health.resourceListTime).c_str(),
						health.resourceRequests, health.playing ? "while the client played" : "before the client played", (uint32_t)message.length));
			}
			else
			{
				health.resourceListTime = time;
			}
			health.resourceRequests = 0;
		}
	}
}

// The client's own sendres after the server's first resource list
void CHealthReport::CountResourceRequests(EndpointHealth &health, const DecodedStream &decoded)
{
	if (health.resourceLists == 0)
		return;

	for (const DecodedMessage &message : decoded.messages)
	{
		if (message.id == clc_stringcmd && CommandName(message.text) == "sendres")
			health.resourceRequests++;
	}
}

// A server packet's own stream: the reliable message it starts, and whether the server choked the client
void CHealthReport::MeasureServerPacket(EndpointHealth &health, const ReceivedPacket &packet, const DecodedStream &decoded)
{
	const ChannelPacket &channel = packet.received.packet;
	const EndpointId endpoint = packet.header.endpoint;
	const uint64_t time = packet.header.time;

	const ServerPacketParts parts = SplitServerPacket(decoded, channel.reliable);
	if (parts.layout == ServerPacketParts::Layout::Unknown)
	{
		if (health.unsplit++ == 0)
			health.firstUnsplit = time;
		return;
	}

	if (parts.choked)
	{
		if (health.choked++ == 0)
			health.firstChoked = time;
	}

	if (!channel.reliable || parts.reliableMessages == 0)
		return;

	// A resend carries the same buffer again; before the first acknowledgement a resend cannot be told apart
	const ReliableFlow &flow = packet.direction == Direction::In ? health.fromRemote : health.toRemote;
	if (flow.known && flow.firstSequence != channel.sequence)
		return;

	AddReliableDemand(health, endpoint, time, decoded, parts.reliableMessages, parts.reliableBytes, false);
}

// What the server queued for one reliable message, as a batch and as part of its pace
void CHealthReport::AddReliableDemand(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded, size_t messages, size_t bytes, bool fragmented)
{
	ReliableBursts &bursts = health.bursts;
	if ((double)bytes >= RELIABLE_BURST_SHARE * (double)MAX_MSGLEN)
	{
		bursts.count++;
		if (bytes > bursts.largestBytes)
		{
			bursts.largestBytes = bytes;
			bursts.largestTime = time;
			bursts.largestFragmented = fragmented;
			bursts.largestContents.clear();
			Tally(bursts.largestContents, decoded, messages);
		}
	}

	LagTolerance &tolerance = health.tolerance;
	tolerance.window.push_back(std::make_pair(time, bytes));
	tolerance.windowBytes += bytes;
	while (tolerance.window.front().first + LAG_WINDOW_MICROSECONDS <= time)
	{
		tolerance.windowBytes -= tolerance.window.front().second;
		tolerance.window.pop_front();
	}

	const double rate = (double)tolerance.windowBytes / Seconds(LAG_WINDOW_MICROSECONDS);
	const double seconds = rate > 0.0 ? (double)MAX_MSGLEN / rate : HUGE_VAL;
	if (seconds >= LAG_TOLERANCE_MEDIUM_SECONDS)
	{
		CloseLagTolerance(health, endpoint);
		return;
	}

	if (!tolerance.open)
	{
		tolerance.open = true;
		tolerance.since = time;
		tolerance.leastSeconds = seconds;
		tolerance.leastTime = time;
		tolerance.contents.clear();
	}

	tolerance.until = time;
	if (seconds < tolerance.leastSeconds)
	{
		tolerance.leastSeconds = seconds;
		tolerance.leastTime = time;
	}
	Tally(tolerance.contents, decoded, messages);
}

// A fragmented message to a playing client: more than one message carries, queued in one go.
// Before it plays, fragments are the sign-on's own transfers, not what netchan.message held.
void CHealthReport::MeasureFragmentedMessage(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded)
{
	if (!health.playing)
		return;

	size_t bytes = 0;
	for (const DecodedMessage &message : decoded.messages)
		bytes += message.length;

	AddReliableDemand(health, endpoint, time, decoded, decoded.messages.size(), bytes, true);
}

void CHealthReport::CloseLagTolerance(EndpointHealth &health, EndpointId endpoint)
{
	LagTolerance &tolerance = health.tolerance;
	if (!tolerance.open)
		return;

	// A stretch shorter than the window is one batch, which the bursts name
	tolerance.open = false;
	if (tolerance.until - tolerance.since < LAG_WINDOW_MICROSECONDS)
		return;

	const Severity severity = tolerance.leastSeconds < LAG_TOLERANCE_HIGH_SECONDS ? Severity::High : Severity::Medium;
	m_Findings.Add(severity, endpoint, "the server's reliable data leaves little room for lag", tolerance.since,
		Format("from %s to %s the server queued so much reliable data a second that netchan.message fills in under %.1f s, "
			"in %.0f ms at %s: acknowledgements late by that much drop the client on HLDS and pile up fragments on ReHLDS; "
			"what it queued: %s", m_Clock->Relative(tolerance.since).c_str(), m_Clock->Relative(tolerance.until).c_str(),
			LAG_TOLERANCE_MEDIUM_SECONDS, tolerance.leastSeconds * 1000.0, m_Clock->Relative(tolerance.leastTime).c_str(),
			Heaviest(tolerance.contents).c_str()));
}

// The batches of one session, by the largest
void CHealthReport::ReportReliableBursts(EndpointHealth &health, EndpointId endpoint)
{
	ReliableBursts &bursts = health.bursts;
	if (bursts.count)
	{
		// One reliable message never holds more on HLDS: a larger one went out as fragments of ReHLDS
		const double share = (double)bursts.largestBytes / (double)MAX_MSGLEN;
		const Severity severity = share >= 1.0 ? Severity::Medium : Severity::Info;
		m_Findings.Add(severity, endpoint, "the server sent reliable data in large batches", bursts.largestTime,
			Format("%u reliable messages carried %.0f%% or more of the %zu bytes one holds; the largest %zu bytes (%.0f%%) at %s%s; "
				"it carried: %s", bursts.count, RELIABLE_BURST_SHARE * 100.0, MAX_MSGLEN, bursts.largestBytes, share * 100.0,
				m_Clock->Relative(bursts.largestTime).c_str(), bursts.largestFragmented ? ", sent as fragments" : "",
				Heaviest(bursts.largestContents).c_str()));
	}

	bursts = ReliableBursts();
}

// What the split of the server's packets found besides the reliable messages
void CHealthReport::ReportServerLayout(const EndpointHealth &health, EndpointId endpoint)
{
	if (health.choked)
	{
		m_Findings.Add(Severity::Info, endpoint, "the server held packets back for the client's rate", health.firstChoked,
			Format("%u of its datagrams said so with svc_choke, the first at %s", health.choked, m_Clock->Relative(health.firstChoked).c_str()));
	}

	// Its reliable data is not measured there: the report says so instead of guessing
	if (health.unsplit)
	{
		m_Findings.Add(Severity::Info, endpoint, "server packets not laid out as HLDS writes them", health.firstUnsplit,
			Format("%u packets, the first at %s, could not be split into reliable data and datagram", health.unsplit,
				m_Clock->Relative(health.firstUnsplit).c_str()));
	}
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

		CloseLagTolerance(health, header.endpoint);
		ReportReliableBursts(health, header.endpoint);
		health.tolerance = LagTolerance();
		health.toRemote = ReliableFlow();
		health.fromRemote = ReliableFlow();
		health.heard = false;
		health.sentSinceHeard = 0;
		health.playing = false;
		health.resourceLists = 0;
		health.resourceRequests = 0;
		return;
	}

	if (event.event != Event::ClientDropped && event.event != Event::Disconnect)
		return;

	if (health.toRemote.pending && header.time > health.toRemote.since + STUCK_MICROSECONDS && health.toRemote.answers >= STUCK_ANSWERS)
		ReportStuck(health.toRemote, header.endpoint, ToString(m_Walker.GetRole()), header.time, Severity::Critical, (std::string("then dropped: ") + text).c_str());

	health.toRemote.pending = false;
	health.heard = false;
}

void CHealthReport::OnOverflow(const EntryHeader &header, const OverflowCaptureEntry &state)
{
	EndpointHealth &health = m_Endpoints[header.endpoint];
	CloseLagTolerance(health, header.endpoint);

	// What the server had at the moment: why the channel did not empty the buffer in time
	m_Findings.Add(Severity::Critical, header.endpoint, "the reliable buffer overflowed, the client was dropped", header.time,
		Format("%u of %u bytes queued, %u more asked; %u bytes in flight, %u fragment buffers waiting, %u packets unacknowledged, "
			"the client silent for %u ms; netinspector overflow lists what filled it", state.queuedBytes, state.bufferBytes, state.requestedBytes, state.reliableInFlightBytes,
			state.queuedFragmentBuffers, state.unacknowledgedPackets, state.silentMilliseconds));

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

	// The first frame measured holds what the program did as the recording began: its start, a map load
	const bool first = m_Frames == 0;

	m_Frames++;
	for (const std::string &name : SeenInFrame())
		m_FrameMessages[name]++;

	if (frame.durationMicroseconds >= HANG_MICROSECONDS && !first && !m_Loading && !m_Frame.mapLoaded)
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

	// Where in its session a client was: the first frames of play load what the game shows first
	const std::string entered = m_Walker.GetRole() == Role::Client && m_PlayingSince && !m_Loading
		? Format("%.1f s after entering the game; ", Seconds(header.time - m_PlayingSince)) : std::string();

	const Severity severity = frame.durationMicroseconds >= LONG_HANG_MICROSECONDS ? Severity::High : Severity::Medium;
	const std::string detail = Format("frame %llu took %.1f ms; ", (unsigned long long)(frame.frameNumber - 1), frame.durationMicroseconds / 1000.0)
		+ entered + Format("during it %u packets from %zu endpoints, %u connectionless; ", packets, m_Frame.packets.size(), m_Frame.connectionless)
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
