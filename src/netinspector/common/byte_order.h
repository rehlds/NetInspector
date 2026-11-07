//=============================================================================//
//
// Little-endian reads and writes over byte buffers, independent of the host
// order and of alignment
//
//=============================================================================//

#pragma once

#include <cstdint>

namespace NetInspector
{

inline uint32_t ReadUInt16LE(const uint8_t *data)
{
	return uint32_t(data[0]) | (uint32_t(data[1]) << 8);
}

inline uint32_t ReadUInt32LE(const uint8_t *data)
{
	return uint32_t(data[0]) | (uint32_t(data[1]) << 8) | (uint32_t(data[2]) << 16) | (uint32_t(data[3]) << 24);
}

inline void WriteUInt32LE(uint8_t *data, uint32_t value)
{
	data[0] = uint8_t(value);
	data[1] = uint8_t(value >> 8);
	data[2] = uint8_t(value >> 16);
	data[3] = uint8_t(value >> 24);
}

constexpr uint32_t ByteSwap32(uint32_t value)
{
	return (value >> 24) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | (value << 24);
}

} // namespace NetInspector
