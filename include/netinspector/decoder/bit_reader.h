//=============================================================================//
//
// Reads GoldSrc messages as the engine reads them: bytes, strings and the
// fixed-point encodings outside bit sections, bits lowest first inside them.
// A read past the end marks the reader overflowed and returns zeros.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace NetInspector
{

class CBitReader
{
public:
	CBitReader(const uint8_t *data, size_t length) : m_Data(data), m_Length(length) {}

	bool IsOverflowed() const { return m_Overflowed; }

	// Outside a bit section the position is on a byte
	size_t GetBytePosition() const { return (m_Position + 7) / 8; }
	size_t GetBytesLeft() const { return GetBytePosition() < m_Length ? m_Length - GetBytePosition() : 0; }
	const uint8_t *GetData() const { return m_Data; }

	uint8_t ReadByte();
	int8_t ReadChar();
	int16_t ReadShort();
	uint16_t ReadWord();
	int32_t ReadLong();
	float ReadFloat();
	void ReadBytes(uint8_t *destination, size_t count);
	void SkipBytes(size_t count);

	// To the terminator or the end; at most 8191 characters, as the engine keeps
	std::string ReadString();

	// A short of eighths; a byte of 360/256 degrees; a short of 360/65536 degrees
	float ReadCoord();
	float ReadAngle();
	float ReadHiresAngle();

	// 7 bits a byte, lowest first, the high bit set while more follow
	uint32_t ReadVarInt32();

	//-----------------------------------------------------------------------------
	// A bit section starts on a byte and ends on the byte after its last bit,
	// taking at least one byte even with no bit in it
	//-----------------------------------------------------------------------------
	void StartBitReading();
	void EndBitReading();

	// 0..32 bits
	uint32_t ReadBits(int count);
	uint32_t PeekBits(int count) const;
	bool ReadOneBit() { return ReadBits(1) != 0; }

	// A sign bit, then the magnitude in count - 1 bits
	int32_t ReadSBits(int count);

	float ReadBitAngle(int count);

	// Integer and fraction flags, a sign, 12 integer bits, 3 fraction bits
	float ReadBitCoord();
	void ReadBitVec3Coord(float (&value)[3]);

	// 8-bit characters to a zero one
	std::string ReadBitString();
	void ReadBitData(uint8_t *destination, size_t count);

private:
	bool Fits(size_t bits) const;

	const uint8_t	*m_Data;
	size_t			m_Length;
	size_t			m_Position = 0;		// in bits
	size_t			m_SectionStart = 0;	// in bytes
	bool			m_Overflowed = false;
};

} // namespace NetInspector
