//=============================================================================//
//
// Threats in the traffic a server received
//
//=============================================================================//

#include "threats_report.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace NetInspector
{

namespace
{

constexpr uint64_t SECOND = 1000000;

constexpr uint32_t COMMANDS_A_SECOND = 20;
constexpr uint32_t CONNECTIONLESS_A_SECOND = 10;
constexpr uint32_t VOICE_BYTES_A_SECOND = 8192;
constexpr uint32_t RCON_FAILURES = 3;
constexpr uint32_t SESSIONS_FROM_ONE_ADDRESS = 5;
constexpr size_t OVERSIZED_DATAGRAM = 1400;		// past a routable packet that was not split
constexpr size_t COMMAND_PREVIEW = 120;

// Commands of the signon: a client sends each once a session
const char *const SIGNON_COMMANDS[] = { "new", "sendres", "sendents", "spawn", "prespawn" };

// What a command never needs and an attack on paths or format strings does
const char *const SUSPICIOUS_TEXT[] = { "../", "..\\", "%n", "%s", "%x" };

std::string Format(const char *format, ...)
{
	char text[512];
	va_list arguments;
	va_start(arguments, format);
	std::vsnprintf(text, sizeof(text), format, arguments);
	va_end(arguments);
	return text;
}

// The command of a clc_stringcmd as the decoder quotes it: its first word
std::string CommandName(const std::string &quoted)
{
	const size_t start = quoted.empty() || quoted[0] != '"' ? 0 : 1;
	const size_t end = quoted.find_first_of(" \"\\", start);
	return quoted.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

bool StartsWith(const uint8_t *data, size_t length, const char *text)
{
	const size_t textLength = std::strlen(text);
	return length >= textLength && std::memcmp(data, text, textLength) == 0;
}

} // namespace

uint32_t CThreatsReport::Rate::Add(uint64_t time, uint32_t amount)
{
	if (time / SECOND != second)
	{
		second = time / SECOND;
		count = 0;
	}

	count += amount;
	return count;
}

int CThreatsReport::Run(CReader &reader)
{
	const CReportClock clock(reader.GetHeader());
	m_Clock = &clock;

	if (reader.GetHeader().role != Role::Server)
	{
		std::fprintf(stderr, "netinspector: threats are what a server received; this file was recorded by a client\n");
		return 2;
	}

	m_Walker.Walk(reader, *this);

	for (const std::pair<const EndpointId, ClientThreats> &client : m_Clients)
	{
		if (client.second.sessions > SESSIONS_FROM_ONE_ADDRESS)
			m_Findings.Add(Severity::Info, client.first, "many sessions", 0, Format("%u connects from it", client.second.sessions));
	}

	if (IsJson())
	{
		m_Findings.Write(m_Walker.GetEndpoints(), GetPath(), m_Json);
		return 0;
	}

	if (m_Findings.IsEmpty())
		std::printf("nothing a client sent looks like an attack\n");
	else
		m_Findings.Print(m_Walker.GetEndpoints(), clock, GetPath());
	return 0;
}

void CThreatsReport::OnDatagram(const EntryHeader &header, const DatagramEntry &datagram, const uint8_t *data, size_t length)
{
	ClientThreats &client = m_Clients[header.endpoint];
	const bool connectionless = datagram.type == Datagram::Connectionless && length > 4;

	if (datagram.direction == Direction::Out)
	{
		// The server's answer to a wrong rcon password
		if (connectionless && StartsWith(data + 4, length - 4, "lBad rcon_password"))
		{
			// "#2 1.2.3.4:27005" is counted as 1.2.3.4
			const std::string endpoint = m_Walker.GetEndpoints().Describe(header.endpoint);
			const size_t space = endpoint.find(' ');
			const size_t start = space == std::string::npos ? 0 : space + 1;
			const size_t port = endpoint.rfind(':');
			const std::string address = endpoint.substr(start, port == std::string::npos || port < start ? std::string::npos : port - start);
			const uint32_t failures = ++m_RconFailures[address];
			if (failures >= RCON_FAILURES)
				m_Findings.Add(Severity::High, header.endpoint, "rcon password guessing", header.time, Format("%u wrong rcon passwords from its address so far", failures));
		}
		return;
	}

	if (datagram.type == Datagram::Split || datagram.type == Datagram::SplitExtended)
	{
		m_Findings.Add(Severity::Critical, header.endpoint, "split datagrams to the server", header.time,
			Format("%s datagram of %zu bytes: clients do not split what they send", ToString(datagram.type), length));
	}

	if (length > OVERSIZED_DATAGRAM && datagram.type != Datagram::Split && datagram.type != Datagram::SplitExtended)
		m_Findings.Add(Severity::Medium, header.endpoint, "oversized datagrams", header.time, Format("a %s datagram of %zu bytes", ToString(datagram.type), length));

	if (connectionless)
	{
		const uint32_t count = client.connectionless.Add(header.time, 1);
		if (count > CONNECTIONLESS_A_SECOND)
			m_Findings.Add(Severity::Medium, header.endpoint, "connectionless flood", header.time, Format("%u connectionless datagrams in one second", count));
	}
}

void CThreatsReport::OnChannelPacket(const ReceivedPacket &packet)
{
	if (packet.received.verdict != CChannelReceiver::Verdict::Accepted)
		return;

	ClientThreats &client = m_Clients[packet.header.endpoint];
	const ChannelPacket &channel = packet.received.packet;

	if (packet.direction == Direction::Out)
	{
		client.newestSent = channel.sequence;
		client.sentAny = true;
		return;
	}

	// An acknowledgement of a packet the server never sent is made up
	if (client.sentAny && channel.acknowledged > client.newestSent)
	{
		m_Findings.Add(Severity::Critical, packet.header.endpoint, "acknowledges packets never sent", packet.header.time,
			Format("seq %u acknowledges %u, the server had sent up to %u", channel.sequence, channel.acknowledged, client.newestSent));
	}

	// A newer packet acknowledging less makes the server think its ping is higher: lag compensation reaches further back
	if (client.acknowledgedAny && channel.acknowledged < client.newestAcknowledged)
	{
		m_Findings.Add(Severity::High, packet.header.endpoint, "acknowledgement went back", packet.header.time,
			Format("seq %u acknowledges %u after %u was acknowledged", channel.sequence, channel.acknowledged, client.newestAcknowledged));
	}

	if (!client.acknowledgedAny || channel.acknowledged > client.newestAcknowledged)
		client.newestAcknowledged = channel.acknowledged;
	client.acknowledgedAny = true;
}

void CThreatsReport::OnStream(const ReceivedPacket &packet, const PacketStream &stream)
{
	ClientThreats &client = m_Clients[packet.header.endpoint];

	// A map change signs the client on again over the same channel
	if (packet.source == MessageSource::Server)
	{
		for (const DecodedMessage &message : stream.decoded.messages)
		{
			if (message.name == "svc_serverinfo")
			{
				client.signon.clear();
				client.resourceLists = 0;
				client.consistencyAnswers = 0;
			}
		}
		return;
	}

	if (!stream.decoded.complete)
	{
		m_Findings.Add(Severity::Critical, packet.header.endpoint, "messages an honest client does not send", packet.header.time,
			Format("seq %u stops at byte %zu of %zu: %s", packet.received.packet.sequence, stream.decoded.stoppedAt, stream.bytes.size(), stream.decoded.error.c_str()));
	}

	for (const DecodedMessage &message : stream.decoded.messages)
	{
		if (message.name == "clc_stringcmd")
		{
			CheckCommand(packet.header.endpoint, client, packet.header.time, message);
		}
		else if (message.name == "clc_resourcelist")
		{
			// A client sends its list once, at the signon; each one makes the server look for every file in it
			if (++client.resourceLists > 1)
				m_Findings.Add(Severity::High, packet.header.endpoint, "resource list sent again", packet.header.time, Format("list %u of this sign-on: %s", client.resourceLists, message.text.substr(0, COMMAND_PREVIEW).c_str()));
		}
		else if (message.name == "clc_fileconsistency")
		{
			if (++client.consistencyAnswers > 1)
				m_Findings.Add(Severity::High, packet.header.endpoint, "consistency answer sent again", packet.header.time, Format("answer %u of this sign-on, %s", client.consistencyAnswers, message.text.c_str()));
		}
		else if (message.name == "clc_voicedata")
		{
			const uint32_t bytes = client.voiceBytes.Add(packet.header.time, (uint32_t)message.length);
			if (bytes > VOICE_BYTES_A_SECOND)
				m_Findings.Add(Severity::Medium, packet.header.endpoint, "voice flood", packet.header.time, Format("%u bytes of voice in one second", bytes));
		}
	}
}

void CThreatsReport::CheckCommand(EndpointId endpoint, ClientThreats &client, uint64_t time, const DecodedMessage &message)
{
	const std::string name = CommandName(message.text);
	const std::string preview = message.text.substr(0, COMMAND_PREVIEW);

	const uint32_t count = client.commands.Add(time, 1);
	if (count > COMMANDS_A_SECOND)
		m_Findings.Add(Severity::Medium, endpoint, "string command flood", time, Format("%u string commands in one second, the last %s", count, preview.c_str()));

	// Each makes the server send the signon data again: repeated, the classic lag exploits
	for (const char *signon : SIGNON_COMMANDS)
	{
		if (name == signon && ++client.signon[name] > 1)
			m_Findings.Add(Severity::High, endpoint, "signon command repeated: " + name, time, Format("%s, %u times this sign-on", preview.c_str(), client.signon[name]));
	}

	for (const char *text : SUSPICIOUS_TEXT)
	{
		if (message.text.find(text) != std::string::npos)
			m_Findings.Add(Severity::High, endpoint, "path or format string in a command", time, preview);
	}
}

void CThreatsReport::OnEvent(const EntryHeader &header, const EventEntry &event, const char *)
{
	if (event.event != Event::Connect || !header.endpoint.IsValid())
		return;

	// A new session starts its channel and its signon over
	ClientThreats &client = m_Clients[header.endpoint];
	const uint32_t sessions = client.sessions + 1;
	client = ClientThreats();
	client.sessions = sessions;
}

} // namespace NetInspector
