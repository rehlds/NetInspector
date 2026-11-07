//=============================================================================//
//
// The channel layer of GoldSrc datagrams: the sequence words, the munge over
// the payload, fragment headers, and the assemblers that join split datagrams
// and fragmented reliable streams back into what was sent
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace NetInspector
{

constexpr int CHANNEL_STREAMS = 2;	// normal, file
constexpr size_t CHANNEL_HEADER_SIZE = 8;	// the sequence and acknowledgement words

struct FragmentHeader
{
	bool		present;
	uint32_t	id;			// index << 16 | count, as sent
	uint32_t	index;		// 1-based
	uint32_t	count;
	uint32_t	offset;		// from the payload start
	uint32_t	length;
};

struct ChannelPacket
{
	uint32_t		sequence;
	uint32_t		acknowledged;
	bool			reliable;
	bool			reliableAcknowledged;	// the other end's reliable bit, echoed
	bool			hasFragments;
	bool			security;				// bit 30 of the acknowledgement word
	FragmentHeader	fragments[CHANNEL_STREAMS];
	uint32_t		payloadOffset;			// after the fragment headers, in the demunged bytes
	uint32_t		payloadLength;
};

//-----------------------------------------------------------------------------
// Demunges a channel datagram into demunged and reads its header. False if it
// is shorter than its header or its fragments point outside it.
//-----------------------------------------------------------------------------
bool DecodeChannelPacket(const uint8_t *data, size_t length, std::vector<uint8_t> &demunged, ChannelPacket &packet);

//-----------------------------------------------------------------------------
// COM_UnMunge2 and COM_Munge2 over whole 32-bit words; a shorter tail stays as
// it is. sequence is the low byte of the packet's sequence word.
//-----------------------------------------------------------------------------
void UnmungeChannelPayload(uint8_t *payload, size_t length, uint8_t sequence);
void MungeChannelPayload(uint8_t *payload, size_t length, uint8_t sequence);

//-----------------------------------------------------------------------------
// Joins the parts of -2 and -3 split datagrams from one endpoint in one
// direction
//-----------------------------------------------------------------------------
class CSplitAssembler
{
public:
	enum class Result
	{
		Incomplete,
		Complete,
		Malformed,
	};

	struct Part
	{
		uint32_t number;	// 0-based
		uint32_t count;
	};

	// On Complete the joined packet is in packet
	Result Add(const uint8_t *data, size_t length, bool extended, Part &part, std::vector<uint8_t> &packet);

private:
	int32_t m_Sequence = -1;
	uint32_t m_Count = 0;
	uint32_t m_Received = 0;
	std::vector<std::vector<uint8_t>> m_Parts;
};

//-----------------------------------------------------------------------------
// Collects the fragments of one stream in one direction into the message they
// carry
//-----------------------------------------------------------------------------
class CFragmentAssembler
{
public:
	enum class Result
	{
		Added,
		Repeated,	// held already: the resend of an unacknowledged reliable
		Completed,
		Malformed,
	};

	Result Add(const FragmentHeader &fragment, const uint8_t *data);

	// After Completed: the message as sent, compressed if it was
	const std::vector<uint8_t> &GetMessage() const { return m_Message; }
	bool IsCompressed() const;
	uint32_t GetCount() const { return m_Count; }

private:
	void Reset(uint32_t count);

	uint32_t m_Count = 0;
	uint32_t m_Received = 0;
	std::vector<std::vector<uint8_t>> m_Fragments;
	std::vector<bool> m_Held;
	std::vector<uint8_t> m_Message;
};

} // namespace NetInspector
