//=============================================================================//
//
// Goes through a recording as the receiving ends saw it: every channel packet
// through its channel receiver, every message stream through the decoder,
// session tables and new sessions applied on the way. The reports listen to
// what it finds.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "endpoint_directory.h"
#include "netinspector/decoder/channel_receiver.h"
#include "netinspector/decoder/message_decoder.h"
#include "netinspector/decoder/session_tables.h"
#include "netinspector/reader.h"
#include "stream_decompressor.h"

namespace NetInspector
{

// A channel packet as its receiver took it, split ones joined
struct ReceivedPacket
{
	const EntryHeader				&header;
	Direction						direction;
	MessageSource					source;		// who wrote its messages
	size_t							length;
	const CChannelReceiver::Result	&received;
};

// A message stream of a packet: its own messages, or a fragmented message it completed
struct PacketStream
{
	bool						fragmented;
	bool						decompressed;
	const std::vector<uint8_t>	&bytes;
	const DecodedStream			&decoded;
};

class ITrafficListener
{
public:
	virtual ~ITrafficListener() = default;

	virtual void OnDatagram(const EntryHeader &, const DatagramEntry &, const uint8_t *, size_t) {}

	// Every channel packet, accepted or not; the streams of an accepted one follow
	virtual void OnChannelPacket(const ReceivedPacket &) {}
	virtual void OnStream(const ReceivedPacket &, const PacketStream &) {}
	virtual void OnFileStream(const ReceivedPacket &) {}

	// A connect reaches the listener after the channel and the tables started over
	virtual void OnEvent(const EntryHeader &, const EventEntry &, const char *) {}
	virtual void OnFrame(const EntryHeader &, const FrameEntry &) {}
	virtual void OnOverflow(const EntryHeader &, const OverflowCaptureEntry &) {}
	virtual void OnProcessTime(const EntryHeader &, const ProcessTimeEntry &) {}

	// A session table entry, after the walker took it
	virtual void OnSessionTable(const EntryHeader &) {}
};

class CTrafficWalker
{
public:
	CTrafficWalker() : m_Decoder(m_Tables) {}

	CTrafficWalker(const CTrafficWalker &) = delete;
	CTrafficWalker &operator=(const CTrafficWalker &) = delete;

	void Walk(CReader &reader, ITrafficListener &listener);

	Role GetRole() const { return m_Role; }
	const CEndpointDirectory &GetEndpoints() const { return m_Endpoints; }
	const CSessionTables &GetTables() const { return m_Tables; }

	uint64_t GetStreamCount() const { return m_Streams; }
	uint64_t GetStoppedCount() const { return m_Stopped; }

private:
	// What one endpoint's channel holds, per direction
	struct ChannelState
	{
		CSplitAssembler		splits[2];
		CChannelReceiver	receivers[2];
	};

	void OnDatagram(const EntryHeader &header, const uint8_t *body, ITrafficListener &listener);
	void OnChannelPacket(const EntryHeader &header, Direction direction, const uint8_t *data, size_t length, ITrafficListener &listener);
	void OnEvent(const EntryHeader &header, const uint8_t *body, ITrafficListener &listener);
	void DecodeStream(const ReceivedPacket &packet, bool fragmented, const std::vector<uint8_t> &bytes, ITrafficListener &listener);

	MessageSource SourceOf(Direction direction) const;

	Role								m_Role = Role::Client;
	CEndpointDirectory					m_Endpoints;
	CSessionTables						m_Tables;
	CMessageDecoder						m_Decoder;
	CStreamDecompressor					m_Decompressor;
	std::map<EndpointId, ChannelState>	m_Channels;
	CChannelReceiver::Result			m_Received;
	DecodedStream						m_Decoded;
	std::vector<uint8_t>				m_Joined;
	std::vector<uint8_t>				m_Decompressed;
	uint64_t							m_Streams = 0;
	uint64_t							m_Stopped = 0;
};

} // namespace NetInspector
