//=============================================================================//
//
// One direction of one endpoint's channel as the receiving end's
// Netchan_Process takes it: what it drops, what it keeps of a packet once the
// fragments are taken out, and the fragmented messages it completes
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "netinspector/channel.h"

namespace NetInspector
{

class CChannelReceiver
{
public:
	enum class Verdict
	{
		Accepted,
		Stale,		// the sequence is not newer than the last accepted one
		Security,	// the acknowledgement's bit 30: dropped unless a game module takes it
		Malformed,
	};

	struct Result
	{
		Verdict					verdict = Verdict::Malformed;
		ChannelPacket			packet = {};
		uint32_t				skipped = 0;	// sequences between the last accepted one and this
		bool					processed = false;	// enough was left after the fragments to read messages from
		std::vector<uint8_t>	messages;		// the packet's messages, fragments taken out
		bool					completed[CHANNEL_STREAMS] = {};
		std::vector<uint8_t>	streams[CHANNEL_STREAMS];	// a completed fragmented message, compressed if it was sent so
	};

	void Receive(const uint8_t *data, size_t length, Result &result);

	// A new session starts the channel over
	void Reset();

private:
	bool				m_Started = false;
	uint32_t			m_IncomingSequence = 0;
	CFragmentAssembler	m_Streams[CHANNEL_STREAMS];
	std::vector<uint8_t> m_Demunged;
};

} // namespace NetInspector
