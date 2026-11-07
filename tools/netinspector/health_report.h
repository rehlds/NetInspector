//=============================================================================//
//
// "netinspector health": what went wrong with honest traffic. Reliable data
// the other end answered around without acknowledging, seconds a player was
// flooded and with what, frames the recording program hung in and what came
// in during them, clients whose messages took long to parse, packets lost on
// the way, silences.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "command.h"
#include "findings.h"
#include "json_writer.h"
#include "report_clock.h"
#include "traffic_walker.h"

namespace NetInspector
{

class CHealthReport : public CCommand, private ITrafficListener
{
public:
	CHealthReport() : CCommand("health", "what went wrong with honest traffic: stuck reliable data, floods, hangs, slow parsing, loss, silences") {}

protected:
	int Run(CReader &reader) override;
	bool WritesJson() const override { return true; }

private:
	//-----------------------------------------------------------------------------
	// Reliable data one end sends and the other acknowledges, as the sender's
	// Netchan_Transmit and Netchan_Process keep it: a new reliable message flips
	// the sender's bit, the receiver's echo of it acknowledges the message once
	// it acknowledges the last packet that carried it
	//-----------------------------------------------------------------------------
	struct ReliableFlow
	{
		bool		known = false;		// the sender's bit, learned from an echo with nothing in flight
		bool		bit = false;
		bool		pending = false;
		uint64_t	since = 0;
		uint32_t	firstSequence = 0;
		uint32_t	lastSequence = 0;
		uint32_t	sends = 0;
		uint32_t	answers = 0;		// the receiver's packets while it was in flight
		uint32_t	acknowledged = 0;	// the newest the receiver acknowledged meanwhile
		std::string	content;			// the messages of its first packet
	};

	// What came in during one frame of the recording program
	struct FrameTraffic
	{
		std::map<EndpointId, uint32_t>			packets;
		uint32_t								connectionless = 0;
		std::map<EndpointId, uint32_t>			parsing;	// microseconds a client's messages took
		std::map<std::string, uint32_t>			messages;	// from clients, by name
		std::map<EndpointId, std::set<std::string>>	commands;	// string commands, by client
		bool									mapLoaded = false;	// a server that loads a map hangs by design
	};

	struct EndpointHealth
	{
		ReliableFlow	toRemote;		// the recording program's reliable data
		ReliableFlow	fromRemote;		// the endpoint's

		uint64_t		second = UINT64_MAX;	// what the server wrote to the player in this second
		uint32_t		bytes = 0;
		std::map<std::string, uint32_t>	bytesByMessage;

		uint64_t		lossSecond = UINT64_MAX;
		uint32_t		received = 0;
		uint32_t		lost = 0;

		bool			heard = false;
		uint64_t		lastHeard = 0;
	};

	void OnDatagram(const EntryHeader &header, const DatagramEntry &datagram, const uint8_t *data, size_t length) override;
	void OnChannelPacket(const ReceivedPacket &packet) override;
	void OnStream(const ReceivedPacket &packet, const PacketStream &stream) override;
	void OnEvent(const EntryHeader &header, const EventEntry &event, const char *text) override;
	void OnFrame(const EntryHeader &header, const FrameEntry &frame) override;
	void OnOverflow(const EntryHeader &header, const OverflowCaptureEntry &state) override;
	void OnProcessTime(const EntryHeader &header, const ProcessTimeEntry &entry) override;
	void OnSessionTable(const EntryHeader &header) override;

	void Send(ReliableFlow &flow, uint32_t sequence, uint64_t time);
	void Answer(ReliableFlow &flow, EndpointId endpoint, const char *sender, uint32_t acknowledged, bool echo, uint64_t time);
	void ReportStuck(const ReliableFlow &flow, EndpointId endpoint, const char *sender, uint64_t time, Severity severity, const char *ending);

	void CountFlood(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded);
	void CloseFloodSecond(EndpointHealth &health, EndpointId endpoint);
	void CountLoss(EndpointHealth &health, EndpointId endpoint, uint64_t time, uint32_t received, uint32_t lost);
	void ReportHang(const EntryHeader &header, const FrameEntry &frame);
	std::set<std::string> SeenInFrame() const;
	void ReportHangPatterns();

	const CReportClock					*m_Clock = nullptr;
	CTrafficWalker						m_Walker;
	CJsonWriter							m_Json;
	CFindings							m_Findings;
	std::map<EndpointId, EndpointHealth>	m_Endpoints;

	FrameTraffic						m_Frame;
	bool								m_Loading = false;	// a client between connect and the first entities hangs by design
	uint32_t							m_Frames = 0;
	uint32_t							m_Hangs = 0;
	std::map<std::string, uint32_t>		m_FrameMessages;	// frames a message name came in during
	std::map<std::string, uint32_t>		m_HangMessages;		// hangs a message name came in during
};

} // namespace NetInspector
