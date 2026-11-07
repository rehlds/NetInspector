//=============================================================================//
//
// Channel decoding as Netchan_Process reads a packet, and the assemblers for
// what arrives in pieces
//
//=============================================================================//

#include "netinspector/channel.h"

#include <cstring>

#include "netinspector/common/byte_order.h"

namespace NetInspector
{

namespace
{

constexpr size_t FRAGMENT_HEADER_SIZE = 8;	// id, offset, length
constexpr size_t SPLIT_HEADER_SIZE = 9;		// netID, sequence, number << 4 | count
constexpr size_t SPLIT_EXTENDED_HEADER_SIZE = 12;	// netID, sequence, number << 8 | count, split size

} // namespace

bool DecodeChannelPacket(const uint8_t *data, size_t length, std::vector<uint8_t> &demunged, ChannelPacket &packet)
{
	packet = {};

	if (length < CHANNEL_HEADER_SIZE)
		return false;

	demunged.assign(data, data + length);

	const uint32_t sequenceWord = ReadUInt32LE(&demunged[0]);
	const uint32_t acknowledgedWord = ReadUInt32LE(&demunged[4]);

	UnmungeChannelPayload(&demunged[CHANNEL_HEADER_SIZE], length - CHANNEL_HEADER_SIZE, uint8_t(sequenceWord));

	packet.sequence = sequenceWord & 0x3FFFFFFF;
	packet.acknowledged = acknowledgedWord & 0x3FFFFFFF;
	packet.reliable = (sequenceWord & (1u << 31)) != 0;
	packet.hasFragments = (sequenceWord & (1u << 30)) != 0;
	packet.reliableAcknowledged = (acknowledgedWord & (1u << 31)) != 0;
	packet.security = (acknowledgedWord & (1u << 30)) != 0;

	size_t position = CHANNEL_HEADER_SIZE;

	if (packet.hasFragments)
	{
		for (FragmentHeader &fragment : packet.fragments)
		{
			if (position >= length)
				return false;

			fragment.present = demunged[position++] != 0;
			if (!fragment.present)
				continue;

			if (position + FRAGMENT_HEADER_SIZE > length)
				return false;

			fragment.id = ReadUInt32LE(&demunged[position]);
			fragment.offset = ReadUInt16LE(&demunged[position + 4]);
			fragment.length = ReadUInt16LE(&demunged[position + 6]);
			fragment.index = fragment.id >> 16;
			fragment.count = fragment.id & 0xFFFF;
			position += FRAGMENT_HEADER_SIZE;
		}
	}

	packet.payloadOffset = uint32_t(position);
	packet.payloadLength = uint32_t(length - position);

	// Inside the payload, the file stream's piece after the normal one's
	uint32_t previousEnd = 0;
	for (const FragmentHeader &fragment : packet.fragments)
	{
		if (!fragment.present)
			continue;

		if (fragment.offset < previousEnd || fragment.offset + fragment.length > packet.payloadLength)
			return false;

		previousEnd = fragment.offset + fragment.length;
	}

	return true;
}

CSplitAssembler::Result CSplitAssembler::Add(const uint8_t *data, size_t length, bool extended, Part &part, std::vector<uint8_t> &packet)
{
	const size_t headerSize = extended ? SPLIT_EXTENDED_HEADER_SIZE : SPLIT_HEADER_SIZE;
	if (length < headerSize)
		return Result::Malformed;

	const int32_t sequence = int32_t(ReadUInt32LE(data + 4));
	if (extended)
	{
		const uint32_t packetId = ReadUInt16LE(data + 8);
		part.number = packetId >> 8;
		part.count = packetId & 0xFF;
	}
	else
	{
		part.number = uint32_t(data[8] >> 4);
		part.count = uint32_t(data[8] & 0x0F);
	}

	if (part.count == 0 || part.number >= part.count)
		return Result::Malformed;

	if (sequence != m_Sequence || part.count != m_Count)
	{
		m_Sequence = sequence;
		m_Count = part.count;
		m_Received = 0;
		m_Parts.assign(part.count, {});
	}

	std::vector<uint8_t> &slot = m_Parts[part.number];
	if (slot.empty())
	{
		slot.assign(data + headerSize, data + length);
		m_Received++;
	}

	if (m_Received < m_Count)
		return Result::Incomplete;

	packet.clear();
	for (const std::vector<uint8_t> &piece : m_Parts)
		packet.insert(packet.end(), piece.begin(), piece.end());

	m_Sequence = -1;
	m_Count = 0;
	m_Received = 0;
	return Result::Complete;
}

void CFragmentAssembler::Reset(uint32_t count)
{
	m_Count = count;
	m_Received = 0;
	m_Fragments.assign(count, {});
	m_Held.assign(count, false);
}

CFragmentAssembler::Result CFragmentAssembler::Add(const FragmentHeader &fragment, const uint8_t *data)
{
	if (fragment.count == 0 || fragment.index == 0 || fragment.index > fragment.count)
		return Result::Malformed;

	// Another count starts the next message; so does any fragment after a completed one
	if (fragment.count != m_Count || m_Received == m_Count)
		Reset(fragment.count);

	const uint32_t slot = fragment.index - 1;
	if (m_Held[slot])
		return Result::Repeated;

	m_Fragments[slot].assign(data, data + fragment.length);
	m_Held[slot] = true;
	m_Received++;

	if (m_Received < m_Count)
		return Result::Added;

	m_Message.clear();
	for (const std::vector<uint8_t> &piece : m_Fragments)
		m_Message.insert(m_Message.end(), piece.begin(), piece.end());

	return Result::Completed;
}

bool CFragmentAssembler::IsCompressed() const
{
	return m_Message.size() >= 4 && std::memcmp(m_Message.data(), "BZ2", 4) == 0;
}

} // namespace NetInspector
