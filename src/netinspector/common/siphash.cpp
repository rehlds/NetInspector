//=============================================================================//
//
// SipHash-2-4 over a single message word
//
//=============================================================================//

#include "netinspector/common/siphash.h"

namespace NetInspector
{

namespace
{

constexpr uint64_t RotateLeft(uint64_t value, int bits)
{
	return (value << bits) | (value >> (64 - bits));
}

void SipRound(uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3)
{
	v0 += v1; v1 = RotateLeft(v1, 13); v1 ^= v0; v0 = RotateLeft(v0, 32);
	v2 += v3; v3 = RotateLeft(v3, 16); v3 ^= v2;
	v0 += v3; v3 = RotateLeft(v3, 21); v3 ^= v0;
	v2 += v1; v1 = RotateLeft(v1, 17); v1 ^= v2; v2 = RotateLeft(v2, 32);
}

} // namespace

uint64_t CSipHash::Hash(uint64_t value) const
{
	uint64_t v0 = 0x736f6d6570736575ULL ^ m_Key[0];
	uint64_t v1 = 0x646f72616e646f6dULL ^ m_Key[1];
	uint64_t v2 = 0x6c7967656e657261ULL ^ m_Key[0];
	uint64_t v3 = 0x7465646279746573ULL ^ m_Key[1];

	v3 ^= value;
	SipRound(v0, v1, v2, v3);
	SipRound(v0, v1, v2, v3);
	v0 ^= value;

	// The final block holds only the message length, 8 bytes
	const uint64_t lengthBlock = 8ULL << 56;
	v3 ^= lengthBlock;
	SipRound(v0, v1, v2, v3);
	SipRound(v0, v1, v2, v3);
	v0 ^= lengthBlock;

	v2 ^= 0xFF;
	for (int round = 0; round < 4; round++)
		SipRound(v0, v1, v2, v3);

	return v0 ^ v1 ^ v2 ^ v3;
}

} // namespace NetInspector
