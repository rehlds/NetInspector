//=============================================================================//
//
// SplitServerPacket
//
//=============================================================================//

#include "netinspector/decoder/server_packet.h"

#include "netinspector/decoder/protocol.h"

namespace NetInspector
{

namespace
{

constexpr size_t NO_DATAGRAM = ~size_t(0);

// The datagram's opening at index: svc_time [svc_choke] [svc_addangle | svc_setangle] svc_clientdata
bool OpensDatagram(const std::vector<DecodedMessage> &messages, size_t index, bool &choked)
{
	if (messages[index].id != svc_time)
		return false;

	size_t next = index + 1;
	const bool choke = next < messages.size() && messages[next].id == svc_choke;
	if (choke)
		next++;

	if (next < messages.size() && (messages[next].id == svc_addangle || messages[next].id == svc_setangle))
		next++;

	if (next >= messages.size() || messages[next].id != svc_clientdata)
		return false;

	choked = choke;
	return true;
}

// The messages before end, less the svc_nop that pads a short packet at its end
size_t CountReliable(const std::vector<DecodedMessage> &messages, size_t end, size_t &bytes)
{
	size_t count = end;
	while (count > 0 && messages[count - 1].id == svc_nop)
		count--;

	bytes = 0;
	for (size_t i = 0; i < count; i++)
		bytes += messages[i].length;
	return count;
}

// The last message that is not padding, or NO_DATAGRAM
size_t LastMessage(const std::vector<DecodedMessage> &messages)
{
	for (size_t i = messages.size(); i > 0; i--)
	{
		if (messages[i - 1].id != svc_nop)
			return i - 1;
	}
	return NO_DATAGRAM;
}

// SV_DropClient's svc_disconnect; a secure server's svc_print only alone, since in a reliable
// packet it reads as reliable text, and the client is gone with that packet either way
bool IsFinalWord(const DecodedMessage &message, bool reliable)
{
	return message.id == svc_disconnect || (!reliable && message.id == svc_print);
}

bool OnlyPadding(const std::vector<DecodedMessage> &messages, size_t end)
{
	for (size_t i = 0; i < end; i++)
	{
		if (messages[i].id != svc_nop)
			return false;
	}
	return true;
}

} // namespace

ServerPacketParts SplitServerPacket(const DecodedStream &stream, bool reliable)
{
	const std::vector<DecodedMessage> &messages = stream.messages;

	ServerPacketParts parts;

	// A datagram opens once; two openings leave the boundary unknown
	size_t datagram = NO_DATAGRAM;
	for (size_t i = 0; i < messages.size(); i++)
	{
		bool choked = false;
		if (!OpensDatagram(messages, i, choked))
			continue;

		if (datagram != NO_DATAGRAM)
			return ServerPacketParts();

		datagram = i;
		parts.choked = choked;
	}

	if (datagram == NO_DATAGRAM)
	{
		// What the decoder did not reach may hold the datagram
		if (!stream.complete)
			return ServerPacketParts();

		// The last word to a dropped client, after whatever reliable data rides along
		const size_t last = LastMessage(messages);
		if (last != NO_DATAGRAM && IsFinalWord(messages[last], reliable))
		{
			if (!reliable)
			{
				if (!OnlyPadding(messages, last))
					return ServerPacketParts();
			}
			else
			{
				parts.reliableMessages = CountReliable(messages, last, parts.reliableBytes);
			}

			parts.layout = ServerPacketParts::Layout::Final;
			return parts;
		}

		if (!reliable)
		{
			if (!OnlyPadding(messages, messages.size()))
				return ServerPacketParts();

			parts.layout = ServerPacketParts::Layout::DatagramOnly;
			return parts;
		}

		parts.layout = ServerPacketParts::Layout::ReliableOnly;
		parts.reliableMessages = CountReliable(messages, messages.size(), parts.reliableBytes);
		return parts;
	}

	if (!reliable)
	{
		// Unreliable data before the datagram is not what Netchan_Transmit writes
		if (!OnlyPadding(messages, datagram))
			return ServerPacketParts();

		parts.layout = ServerPacketParts::Layout::DatagramOnly;
		return parts;
	}

	parts.reliableMessages = CountReliable(messages, datagram, parts.reliableBytes);
	parts.layout = parts.reliableMessages ? ServerPacketParts::Layout::Both : ServerPacketParts::Layout::DatagramOnly;
	return parts;
}

} // namespace NetInspector
