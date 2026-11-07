//=============================================================================//
//
// The message reader
//
//=============================================================================//

#include "netinspector/decoder/bit_reader.h"

#include <cstring>

namespace NetInspector
{

namespace
{

constexpr size_t MAX_STRING_LENGTH = 8191;

} // namespace

bool CBitReader::Fits(size_t bits) const
{
	return !m_Overflowed && m_Position + bits <= m_Length * 8;
}

uint32_t CBitReader::ReadBits(int count)
{
	if (count <= 0)
		return 0;

	if (!Fits(count))
	{
		m_Overflowed = true;
		return 0;
	}

	uint32_t value = 0;
	for (int bit = 0; bit < count; bit++)
	{
		const size_t position = m_Position + (size_t)bit;
		if ((m_Data[position / 8] >> (position % 8)) & 1)
			value |= 1u << bit;
	}

	m_Position += (size_t)count;
	return value;
}

uint32_t CBitReader::PeekBits(int count) const
{
	CBitReader copy(*this);
	return copy.ReadBits(count);
}

int32_t CBitReader::ReadSBits(int count)
{
	const bool negative = ReadOneBit();
	const int32_t magnitude = (int32_t)ReadBits(count - 1);
	return negative ? -magnitude : magnitude;
}

uint8_t CBitReader::ReadByte()
{
	return (uint8_t)ReadBits(8);
}

int8_t CBitReader::ReadChar()
{
	return (int8_t)ReadBits(8);
}

int16_t CBitReader::ReadShort()
{
	return (int16_t)ReadBits(16);
}

uint16_t CBitReader::ReadWord()
{
	return (uint16_t)ReadBits(16);
}

int32_t CBitReader::ReadLong()
{
	return (int32_t)ReadBits(32);
}

float CBitReader::ReadFloat()
{
	const uint32_t bits = ReadBits(32);
	float value;
	std::memcpy(&value, &bits, sizeof(value));
	return value;
}

void CBitReader::ReadBytes(uint8_t *destination, size_t count)
{
	for (size_t i = 0; i < count; i++)
		destination[i] = ReadByte();
}

void CBitReader::SkipBytes(size_t count)
{
	if (!Fits(count * 8))
	{
		m_Overflowed = true;
		return;
	}

	m_Position += count * 8;
}

std::string CBitReader::ReadString()
{
	std::string text;
	while (text.size() < MAX_STRING_LENGTH)
	{
		const uint8_t c = ReadByte();
		if (c == 0 || m_Overflowed)
			break;

		text += (char)c;
	}

	return text;
}

float CBitReader::ReadCoord()
{
	return (float)ReadShort() * (1.0f / 8.0f);
}

float CBitReader::ReadAngle()
{
	return (float)ReadChar() * (360.0f / 256.0f);
}

float CBitReader::ReadHiresAngle()
{
	return (float)ReadShort() * (360.0f / 65536.0f);
}

uint32_t CBitReader::ReadVarInt32()
{
	uint32_t value = 0;
	for (int shift = 0; shift < 35; shift += 7)
	{
		const uint8_t c = ReadByte();
		value |= (uint32_t)(c & 0x7F) << shift;
		if (!(c & 0x80) || m_Overflowed)
			return value;
	}

	m_Overflowed = true;
	return value;
}

void CBitReader::StartBitReading()
{
	m_SectionStart = GetBytePosition();
	m_Position = m_SectionStart * 8;

	if (m_SectionStart + 1 > m_Length)
		m_Overflowed = true;
}

void CBitReader::EndBitReading()
{
	const size_t bitsRead = m_Position - m_SectionStart * 8;
	size_t bytes = (bitsRead + 7) / 8;
	if (bytes == 0)
		bytes = 1;

	m_Position = (m_SectionStart + bytes) * 8;

	if (m_SectionStart + bytes > m_Length)
	{
		m_Overflowed = true;
		m_Position = m_Length * 8;
	}
}

float CBitReader::ReadBitAngle(int count)
{
	const double steps = (double)((uint64_t)(1) << (count < 32 ? count : 32));
	return (float)((double)ReadBits(count) * 360.0 / steps);
}

float CBitReader::ReadBitCoord()
{
	const bool hasInteger = ReadOneBit();
	const bool hasFraction = ReadOneBit();
	if (!hasInteger && !hasFraction)
		return 0.0f;

	const bool negative = ReadOneBit();
	const uint32_t integer = hasInteger ? ReadBits(12) : 0;
	const uint32_t fraction = hasFraction ? ReadBits(3) : 0;

	const float value = (float)integer + (float)fraction / 8.0f;
	return negative ? -value : value;
}

void CBitReader::ReadBitVec3Coord(float (&value)[3])
{
	bool present[3];
	for (bool &axis : present)
		axis = ReadOneBit();

	for (int axis = 0; axis < 3; axis++)
		value[axis] = present[axis] ? ReadBitCoord() : 0.0f;
}

std::string CBitReader::ReadBitString()
{
	std::string text;
	while (!m_Overflowed)
	{
		const char c = (char)ReadBits(8);
		if (c == 0)
			break;

		text += c;
	}

	return text;
}

void CBitReader::ReadBitData(uint8_t *destination, size_t count)
{
	for (size_t i = 0; i < count; i++)
		destination[i] = (uint8_t)ReadBits(8);
}

} // namespace NetInspector
