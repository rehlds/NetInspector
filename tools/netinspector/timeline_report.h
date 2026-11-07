//=============================================================================//
//
// "netinspector timeline": every entry in time order at the channel level. Sequences,
// acknowledgements, reliable bits, fragments and the messages they complete, round trips,
// slow frames, session tables and events, one line each.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "command.h"
#include "endpoint_directory.h"
#include "netinspector/channel.h"
#include "report_clock.h"
#include "stream_decompressor.h"

namespace NetInspector
{

struct TimelineFilter
{
	std::string address;		// see CEndpointDirectory::Matches
	double fromSeconds = 0.0;
	double toSeconds = -1.0;	// negative: to the end
	double slowFrameMilliseconds = 50.0;	// shorter frames are not shown
};

class CTimelineReport : public CCommand
{
public:
	CTimelineReport() : CCommand("timeline", "every datagram, slow frame, session table and event in time order at the channel level") {}

protected:
	void AddOptions(CLI::App &subcommand) override;
	int Run(CReader &reader) override;

private:
	// What follows one endpoint's channel across packets, per direction where it differs
	struct ChannelState
	{
		CSplitAssembler splits[2];
		CFragmentAssembler streams[2][CHANNEL_STREAMS];
		std::map<uint32_t, uint64_t> sentAt[2];		// sequence -> time
		uint32_t newestAcknowledged[2] = {};
		bool acknowledgedSeen[2] = {};
	};

	void OnDatagram(const EntryHeader &header, const uint8_t *body);
	void OnChannelPacket(const EntryHeader &header, Direction direction, const uint8_t *data, size_t length, bool print, const char *prefix);
	void OnEvent(const EntryHeader &header, const uint8_t *body);
	void OnFrame(const EntryHeader &header, const uint8_t *body);
	void OnSessionTable(const EntryHeader &header, const uint8_t *body);
	void OnOverflow(const EntryHeader &header, const uint8_t *body);
	void OnLoss(const EntryHeader &header, const uint8_t *body);

	bool IsVisible(const EntryHeader &header) const;
	void PrintLineStart(const EntryHeader &header, const char *direction) const;
	std::string DescribeCompletedStream(int stream, const CFragmentAssembler &assembler);
	static void PrintConnectionless(const uint8_t *data, size_t length);

	TimelineFilter m_Filter;
	const CReportClock *m_Clock = nullptr;
	CEndpointDirectory m_Endpoints;
	std::map<EndpointId, ChannelState> m_Channels;
	std::map<EndpointId, int> m_Sessions;		// connects seen so far
	CStreamDecompressor m_Decompressor;
	std::vector<uint8_t> m_Demunged;
	std::vector<uint8_t> m_Joined;
	std::vector<uint8_t> m_Decompressed;
};

} // namespace NetInspector
