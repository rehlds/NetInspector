//=============================================================================//
//
// "netinspector threats": what a client sent that hurts or probes a server,
// by how sure it is: what an honest client cannot send, known ways to hurt a
// server, floods, and what is only odd
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "command.h"
#include "findings.h"
#include "json_writer.h"
#include "report_clock.h"
#include "traffic_walker.h"

namespace NetInspector
{

class CThreatsReport : public CCommand, private ITrafficListener
{
public:
	CThreatsReport() : CCommand("threats", "what clients sent that hurts or probes a server, by how sure it is") {}

protected:
	int Run(CReader &reader) override;
	bool WritesJson() const override { return true; }

private:
	// Counts by the second, for floods
	struct Rate
	{
		uint64_t	second = UINT64_MAX;
		uint32_t	count = 0;

		// The count of the second time falls in, after adding amount
		uint32_t Add(uint64_t time, uint32_t amount);
	};

	struct ClientThreats
	{
		std::map<std::string, uint32_t> signon;	// signon commands this session
		uint32_t	newestAcknowledged = 0;
		bool		acknowledgedAny = false;
		uint32_t	newestSent = 0;			// the server's newest packet to it
		bool		sentAny = false;
		uint32_t	resourceLists = 0;
		uint32_t	consistencyAnswers = 0;
		uint32_t	sessions = 0;
		Rate		commands;
		Rate		connectionless;
		Rate		voiceBytes;
	};

	void OnDatagram(const EntryHeader &header, const DatagramEntry &datagram, const uint8_t *data, size_t length) override;
	void OnChannelPacket(const ReceivedPacket &packet) override;
	void OnStream(const ReceivedPacket &packet, const PacketStream &stream) override;
	void OnEvent(const EntryHeader &header, const EventEntry &event, const char *text) override;

	void CheckCommand(EndpointId endpoint, ClientThreats &client, uint64_t time, const DecodedMessage &message);

	const CReportClock						*m_Clock = nullptr;
	CTrafficWalker							m_Walker;
	CJsonWriter								m_Json;
	CFindings								m_Findings;
	std::map<EndpointId, ClientThreats>		m_Clients;
	std::map<std::string, uint32_t>			m_RconFailures;		// by address: a guesser takes a new port for each try
};

} // namespace NetInspector
