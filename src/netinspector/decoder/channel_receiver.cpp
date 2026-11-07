//=============================================================================//
//
// The receiving end of a channel
//
//=============================================================================//

#include "netinspector/decoder/channel_receiver.h"

namespace NetInspector
{

namespace
{

// What Netchan_Process leaves for the messages must be more than this, headers included
constexpr size_t MIN_PROCESSED_SIZE = 16;

} // namespace

void CChannelReceiver::Reset()
{
	m_Started = false;
	m_IncomingSequence = 0;

	for (CFragmentAssembler &stream : m_Streams)
		stream = CFragmentAssembler();
}

void CChannelReceiver::Receive(const uint8_t *data, size_t length, Result &result)
{
	result = Result();

	ChannelPacket &packet = result.packet;
	if (!DecodeChannelPacket(data, length, m_Demunged, packet))
		return;

	if (packet.security)
	{
		result.verdict = Verdict::Security;
		return;
	}

	if (m_Started && packet.sequence <= m_IncomingSequence)
	{
		result.verdict = Verdict::Stale;
		return;
	}

	result.verdict = Verdict::Accepted;
	result.skipped = m_Started ? packet.sequence - m_IncomingSequence - 1 : 0;
	m_Started = true;
	m_IncomingSequence = packet.sequence;

	// The fragments come out of the payload; what is left between them is the messages
	const uint8_t *payload = &m_Demunged[packet.payloadOffset];
	size_t position = 0;
	size_t remaining = length;

	for (int stream = 0; stream < CHANNEL_STREAMS; stream++)
	{
		const FragmentHeader &fragment = packet.fragments[stream];
		if (!fragment.present)
			continue;

		if (fragment.id != 0 && m_Streams[stream].Add(fragment, payload + fragment.offset) == CFragmentAssembler::Result::Completed)
		{
			result.completed[stream] = true;
			result.streams[stream] = m_Streams[stream].GetMessage();
		}

		result.messages.insert(result.messages.end(), payload + position, payload + fragment.offset);
		position = fragment.offset + fragment.length;
		remaining -= fragment.length;
	}

	result.messages.insert(result.messages.end(), payload + position, payload + packet.payloadLength);
	result.processed = !packet.hasFragments || remaining > MIN_PROCESSED_SIZE;
}

} // namespace NetInspector
