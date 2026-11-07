//=============================================================================//
//
// COM_Munge2 and COM_UnMunge2: what hides a channel packet's payload
//
//=============================================================================//

#include "netinspector/channel.h"

#include "netinspector/common/byte_order.h"

namespace NetInspector
{

namespace
{

// The key of a payload word, by its index modulo 16
constexpr uint32_t MUNGE_KEYS[16] =
{
	0xFFFFE7A5, 0xBFEFFFE5, 0xFFBFEFFF, 0xBFEFBFED,
	0xBFAFEFBF, 0xFFBFAFEF, 0xFFEFBFAD, 0xFFFFEFBF,
	0xFFEFF7EF, 0xBFEFE7F5, 0xBFBFE7E5, 0xFFAFB7E7,
	0xBFFFAFB5, 0xBFAFFFAF, 0xFFAFA7FF, 0xFFEFA7A5,
};

// The sequence byte goes in as an int, so its complement sets the upper bits too
uint32_t SequenceKey(uint8_t sequence)
{
	const int32_t value = sequence;
	return ByteSwap32(uint32_t(~value)) ^ uint32_t(value);
}

} // namespace

void UnmungeChannelPayload(uint8_t *payload, size_t length, uint8_t sequence)
{
	const uint32_t sequenceKey = SequenceKey(sequence);

	for (size_t word = 0; word < length / 4; word++)
	{
		uint8_t *bytes = payload + word * 4;
		WriteUInt32LE(bytes, ByteSwap32(ReadUInt32LE(bytes) ^ sequenceKey ^ MUNGE_KEYS[word & 15]));
	}
}

void MungeChannelPayload(uint8_t *payload, size_t length, uint8_t sequence)
{
	const uint32_t sequenceKey = SequenceKey(sequence);

	for (size_t word = 0; word < length / 4; word++)
	{
		uint8_t *bytes = payload + word * 4;
		WriteUInt32LE(bytes, ByteSwap32(ReadUInt32LE(bytes)) ^ sequenceKey ^ MUNGE_KEYS[word & 15]);
	}
}

} // namespace NetInspector
