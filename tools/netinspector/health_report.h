//=============================================================================//
//
// "netinspector health": what went wrong with honest traffic. Reliable data
// the other end answered around without acknowledging, the server's reliable
// buffer running full and what filled it, packets it held back for the
// client's rate, a resource list sent again in one sign-on, frames the
// recording program hung in and what came in during them, clients whose
// messages took long to parse, packets lost on the way, and silences the
// other end kept although its answers were due.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <deque>
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

struct MessageTally
{
	uint32_t	count = 0;
	uint32_t	bytes = 0;
};

class CHealthReport : public CCommand, private ITrafficListener
{
public:
	CHealthReport() : CCommand("health", "what went wrong with honest traffic: stuck reliable data, a full reliable buffer, hangs, slow parsing, loss, silences") {}

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

	//-----------------------------------------------------------------------------
	// Reliable messages of the server that took half or more of what one holds:
	// a game writes a MOTD or every player's userinfo in one frame, and the
	// largest such batch is how close it came to the limit
	//-----------------------------------------------------------------------------
	struct ReliableBursts
	{
		uint32_t	count = 0;
		size_t		largestBytes = 0;
		uint64_t	largestTime = 0;
		bool		largestFragmented = false;
		std::map<std::string, MessageTally>	largestContents;
	};

	//-----------------------------------------------------------------------------
	// The reliable data the server queued in the last second. At that pace
	// netchan.message fills in MAX_MSGLEN / rate: acknowledgements late by that
	// much drop the client on HLDS. A stretch where that time stays short.
	//-----------------------------------------------------------------------------
	struct LagTolerance
	{
		std::deque<std::pair<uint64_t, size_t>>	window;	// time, bytes of each reliable message
		size_t		windowBytes = 0;

		bool		open = false;
		uint64_t	since = 0;
		uint64_t	until = 0;
		double		leastSeconds = 0.0;
		uint64_t	leastTime = 0;
		std::map<std::string, MessageTally>	contents;
	};

	struct EndpointHealth
	{
		ReliableFlow	toRemote;		// the recording program's reliable data
		ReliableFlow	fromRemote;		// the endpoint's

		ReliableBursts	bursts;
		LagTolerance	tolerance;
		uint32_t		choked = 0;			// datagrams the server sent with svc_choke
		uint64_t		firstChoked = 0;
		uint32_t		unsplit = 0;		// server packets that do not follow its layout
		uint64_t		firstUnsplit = 0;

		// The player gets entities once it plays; the sign-on before that sends its tables once
		bool			playing = false;
		uint32_t		resourceLists = 0;	// since the server last sent svc_serverinfo
		uint64_t		resourceListTime = 0;
		uint32_t		resourceRequests = 0;	// the player's sendres since the first list

		uint64_t		lossSecond = UINT64_MAX;
		uint32_t		received = 0;
		uint32_t		lost = 0;

		// Channel packets each way: how often it answers is what makes its silence its own
		bool			heard = false;
		uint64_t		lastHeard = 0;
		uint64_t		heardTotal = 0;
		uint64_t		sentTotal = 0;
		uint32_t		sentSinceHeard = 0;
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

	void MeasureServerPacket(EndpointHealth &health, const ReceivedPacket &packet, const DecodedStream &decoded);
	void MeasureFragmentedMessage(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded);
	void AddReliableDemand(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded, size_t messages, size_t bytes, bool fragmented);
	void CloseLagTolerance(EndpointHealth &health, EndpointId endpoint);
	void ReportReliableBursts(EndpointHealth &health, EndpointId endpoint);
	void ReportServerLayout(const EndpointHealth &health, EndpointId endpoint);
	void CountSignon(EndpointHealth &health, EndpointId endpoint, uint64_t time, const DecodedStream &decoded);
	void CountResourceRequests(EndpointHealth &health, const DecodedStream &decoded);
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
	uint64_t							m_PlayingSince = 0;	// when a client got its first entities
	uint32_t							m_Frames = 0;
	uint32_t							m_Hangs = 0;
	std::map<std::string, uint32_t>		m_FrameMessages;	// frames a message name came in during
	std::map<std::string, uint32_t>		m_HangMessages;		// hangs a message name came in during
};

} // namespace NetInspector
