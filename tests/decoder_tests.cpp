//=============================================================================//
//
// Messages read back the way the engine wrote them
//
//=============================================================================//

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "netinspector/decoder/bit_reader.h"
#include "netinspector/decoder/channel_receiver.h"
#include "netinspector/decoder/delta_reader.h"
#include "netinspector/decoder/message_decoder.h"

namespace NetInspector
{

namespace
{

// Writes bits lowest first, as MSG_WriteBits does
class CBitWriter
{
public:
	void WriteBits(uint32_t value, int count)
	{
		for (int bit = 0; bit < count; bit++)
		{
			if (m_Bits % 8 == 0)
				m_Bytes.push_back(0);
			if ((value >> bit) & 1)
				m_Bytes.back() |= (uint8_t)(1u << (m_Bits % 8));
			m_Bits++;
		}
	}

	void WriteByte(uint8_t value) { WriteBits(value, 8); }

	void WriteString(const char *text)
	{
		for (const char *c = text; *c; c++)
			WriteByte((uint8_t)*c);
		WriteByte(0);
	}

	void WriteFloat(float value)
	{
		uint32_t bits;
		std::memcpy(&bits, &value, sizeof(bits));
		WriteBits(bits, 32);
	}

	// A bit section ends on the next byte
	void Align() { m_Bits = m_Bytes.size() * 8; }

	const std::vector<uint8_t> &GetBytes() const { return m_Bytes; }

private:
	std::vector<uint8_t> m_Bytes;
	size_t m_Bits = 0;
};

DeltaFieldRecord Field(uint32_t type, int bits, float preMultiplier, const char *name)
{
	DeltaFieldRecord field = {};
	field.type = type;
	field.bits = (uint16_t)bits;
	field.preMultiplier = preMultiplier;
	field.postMultiplier = 1.0f;
	std::strncpy(field.name, name, sizeof(field.name) - 1);
	return field;
}

} // namespace

TEST(BitReader, ReadsBitsLowestFirst)
{
	const uint8_t data[] = { 0xB5, 0x01 };	// 1011 0101, then 1
	CBitReader reader(data, sizeof(data));

	EXPECT_EQ(reader.ReadBits(1), 1u);
	EXPECT_EQ(reader.ReadBits(3), 2u);
	EXPECT_EQ(reader.ReadBits(5), 0x1Bu);
	EXPECT_FALSE(reader.IsOverflowed());

	reader.ReadBits(8);
	EXPECT_TRUE(reader.IsOverflowed());
}

TEST(BitReader, EndsASectionOnTheNextByteAndTakesAtLeastOne)
{
	const uint8_t data[] = { 0xFF, 0xFF, 0x2A };
	CBitReader reader(data, sizeof(data));

	reader.StartBitReading();
	reader.EndBitReading();
	EXPECT_EQ(reader.GetBytePosition(), 1u);

	reader.StartBitReading();
	reader.ReadBits(3);
	reader.EndBitReading();
	EXPECT_EQ(reader.GetBytePosition(), 2u);

	EXPECT_EQ(reader.ReadByte(), 0x2A);
}

TEST(BitReader, ReadsSignedBitsAndCoords)
{
	CBitWriter writer;
	writer.WriteBits(1, 1);		// negative
	writer.WriteBits(5, 4);
	writer.WriteBits(1, 1);		// integer part
	writer.WriteBits(1, 1);		// fraction part
	writer.WriteBits(0, 1);		// positive
	writer.WriteBits(12, 12);
	writer.WriteBits(4, 3);

	CBitReader reader(writer.GetBytes().data(), writer.GetBytes().size());
	EXPECT_EQ(reader.ReadSBits(5), -5);
	EXPECT_FLOAT_EQ(reader.ReadBitCoord(), 12.5f);
}

TEST(Delta, ReadsOnlyTheFieldsTheMaskNames)
{
	DeltaDescription description;
	description.name = "test_t";
	description.fields.push_back(Field(DT_INTEGER, 8, 1.0f, "health"));
	description.fields.push_back(Field(DT_FLOAT | DT_SIGNED, 16, 8.0f, "origin[0]"));
	description.fields.push_back(Field(DT_STRING, 1, 1.0f, "model"));

	CBitWriter writer;
	writer.WriteBits(1, 3);			// one mask byte
	writer.WriteBits(0x06, 8);		// origin[0] and model
	writer.WriteBits(1, 1);			// negative
	writer.WriteBits(100, 15);		// 100 / 8
	writer.WriteBits('a', 8);
	writer.WriteBits(0, 8);

	CBitReader reader(writer.GetBytes().data(), writer.GetBytes().size());
	std::vector<DeltaValue> values;
	ASSERT_TRUE(ReadDelta(reader, description, values));
	EXPECT_EQ(FormatDelta(values), "origin[0]=-12.500 model=\"a\"");
}

TEST(MessageDecoder, ReadsServerMessagesAndUserMessages)
{
	CSessionTables tables;
	tables.SetUserMessage(64, -1, "SayText");
	tables.SetUserMessage(65, 2, "Health");

	CBitWriter writer;
	writer.WriteByte(7);		// svc_time
	writer.WriteFloat(12.5f);
	writer.WriteByte(8);		// svc_print
	writer.WriteString("hello\n");
	writer.WriteByte(64);		// SayText, sized by itself
	writer.WriteByte(3);
	writer.WriteString("hi");
	writer.WriteByte(65);		// Health, two bytes
	writer.WriteByte(100);
	writer.WriteByte(0);
	writer.WriteByte(1);		// svc_nop

	CMessageDecoder decoder(tables);
	DecodedStream stream;
	decoder.Decode(MessageSource::Server, writer.GetBytes().data(), writer.GetBytes().size(), 0, stream);

	ASSERT_TRUE(stream.complete) << stream.error;
	ASSERT_EQ(stream.messages.size(), 5u);
	EXPECT_EQ(stream.messages[0].name, "svc_time");
	EXPECT_EQ(stream.messages[0].text, "12.500");
	EXPECT_EQ(stream.messages[1].text, "\"hello\\n\"");
	EXPECT_EQ(stream.messages[2].name, "SayText");
	EXPECT_EQ(stream.messages[2].length, 5u);
	EXPECT_EQ(stream.messages[3].name, "Health");
	EXPECT_EQ(stream.messages[3].length, 3u);
}

TEST(MessageDecoder, LearnsUserMessagesFromTheWire)
{
	CSessionTables tables;

	CBitWriter writer;
	writer.WriteByte(39);		// svc_newusermsg
	writer.WriteByte(70);
	writer.WriteByte(255);
	const char name[16] = "TextMsg";
	for (char c : name)
		writer.WriteByte((uint8_t)c);
	writer.WriteByte(70);
	writer.WriteByte(1);
	writer.WriteByte(0x41);

	CMessageDecoder decoder(tables);
	DecodedStream stream;
	decoder.Decode(MessageSource::Server, writer.GetBytes().data(), writer.GetBytes().size(), 0, stream);

	ASSERT_TRUE(stream.complete) << stream.error;
	ASSERT_EQ(stream.messages.size(), 2u);
	EXPECT_EQ(stream.messages[1].name, "TextMsg");
}

TEST(MessageDecoder, StopsWhereItCannotGoOn)
{
	CSessionTables tables;

	CBitWriter writer;
	writer.WriteByte(1);		// svc_nop
	writer.WriteByte(90);		// a user message the recording never registered
	writer.WriteByte(0);

	CMessageDecoder decoder(tables);
	DecodedStream stream;
	decoder.Decode(MessageSource::Server, writer.GetBytes().data(), writer.GetBytes().size(), 0, stream);

	EXPECT_FALSE(stream.complete);
	EXPECT_EQ(stream.messages.size(), 1u);
	EXPECT_EQ(stream.stoppedAt, 1u);
	EXPECT_NE(stream.error.find("not registered"), std::string::npos);
}

TEST(ChannelReceiver, DropsWhatIsNotNewer)
{
	uint8_t packet[16] = {};
	packet[0] = 5;	// sequence 5, acknowledging 0

	CChannelReceiver receiver;
	CChannelReceiver::Result result;
	receiver.Receive(packet, sizeof(packet), result);
	EXPECT_EQ(result.verdict, CChannelReceiver::Verdict::Accepted);

	receiver.Receive(packet, sizeof(packet), result);
	EXPECT_EQ(result.verdict, CChannelReceiver::Verdict::Stale);

	packet[0] = 8;
	receiver.Receive(packet, sizeof(packet), result);
	EXPECT_EQ(result.verdict, CChannelReceiver::Verdict::Accepted);
	EXPECT_EQ(result.skipped, 2u);
	EXPECT_EQ(result.messages.size(), 8u);
}

} // namespace NetInspector
