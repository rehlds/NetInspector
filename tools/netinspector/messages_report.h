//=============================================================================//
//
// "netinspector messages": every channel packet the receiving end accepted,
// down to the svc_ and clc_ messages in it, as the engine reads them
//
//=============================================================================//

#pragma once

#include <string>

#include "command.h"
#include "json_writer.h"
#include "report_clock.h"
#include "traffic_walker.h"

namespace NetInspector
{

struct MessagesFilter
{
	std::string address;		// see CEndpointDirectory::Matches
	std::string message;		// a part of the message names to show; empty shows all
	double fromSeconds = 0.0;
	double toSeconds = -1.0;	// negative: to the end
	bool dropped = false;		// the packets the receiving end dropped as well
};

class CMessagesReport : public CCommand, private ITrafficListener
{
public:
	CMessagesReport() : CCommand("messages", "every packet the receiving end accepted, down to the svc_ and clc_ messages in it") {}

protected:
	void AddOptions(CLI::App &subcommand) override;
	int Run(CReader &reader) override;
	bool WritesJson() const override { return true; }

private:
	void OnChannelPacket(const ReceivedPacket &packet) override;
	void OnStream(const ReceivedPacket &packet, const PacketStream &stream) override;
	void OnFileStream(const ReceivedPacket &packet) override;
	void OnEvent(const EntryHeader &header, const EventEntry &event, const char *text) override;

	void PrintStream(const ReceivedPacket &packet, const PacketStream &stream);
	void WriteStream(const ReceivedPacket &packet, const PacketStream &stream);

	bool IsVisible(const EntryHeader &header) const;
	bool Shows(const DecodedMessage &message) const;
	void PrintLineStart(const EntryHeader &header, const char *direction) const;
	std::string DescribePacket(const ReceivedPacket &packet, const PacketStream &stream) const;

	MessagesFilter		m_Filter;
	const CReportClock	*m_Clock = nullptr;
	CTrafficWalker		m_Walker;
	CJsonWriter			m_Json;
};

} // namespace NetInspector
