//=============================================================================//
//
// SipHash-2-4: a keyed hash, cheap enough to run per address bit and strong
// enough that its output says nothing about the key
//
//=============================================================================//

#pragma once

#include <cstdint>

namespace NetInspector
{

class CSipHash
{
public:
	static constexpr int KEY_WORDS = 2;

	explicit CSipHash(const uint64_t (&key)[KEY_WORDS]) : m_Key{ key[0], key[1] } {}

	// The hash of one 64-bit word
	uint64_t Hash(uint64_t value) const;

private:
	uint64_t m_Key[KEY_WORDS];
};

} // namespace NetInspector
