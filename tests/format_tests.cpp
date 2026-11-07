//=============================================================================//
//
// The file format's helpers: datagram classification and bit sets over enum class
//
//=============================================================================//

#include <cstring>

#include <gtest/gtest.h>

#include "netinspector/format.h"

namespace NetInspector
{

namespace
{

Datagram Classify(int32_t netId)
{
	uint8_t bytes[8] = {};
	std::memcpy(bytes, &netId, sizeof(netId));
	return ClassifyDatagram(bytes, sizeof(bytes));
}

} // namespace

TEST(Format, ClassifiesByTheFirstWord)
{
	EXPECT_EQ(Classify(-1), Datagram::Connectionless);
	EXPECT_EQ(Classify(-2), Datagram::Split);
	EXPECT_EQ(Classify(-3), Datagram::SplitExtended);
	EXPECT_EQ(Classify(1), Datagram::Channel);

	// A reliable channel packet has bit 31 set and is still a channel packet
	EXPECT_EQ(Classify(int32_t(0xC0000001)), Datagram::Channel);
}

TEST(Format, ShortDatagramIsUnknown)
{
	const uint8_t bytes[3] = { 0xFF, 0xFF, 0xFF };
	EXPECT_EQ(ClassifyDatagram(bytes, sizeof(bytes)), Datagram::Unknown);
	EXPECT_EQ(ClassifyDatagram(nullptr, 0), Datagram::Unknown);
}

TEST(Format, FlagsCombine)
{
	DatagramFlags flags = DatagramFlags::None;
	EXPECT_FALSE(HasAny(flags, DatagramFlags::Scrubbed));

	flags |= DatagramFlags::Scrubbed;
	EXPECT_TRUE(HasAny(flags, DatagramFlags::Scrubbed));
}

TEST(Format, NamesEveryEntryType)
{
	EXPECT_STREQ(ToString(Entry::Datagram), "datagram");
	EXPECT_STREQ(ToString(Entry::RecorderLoss), "recorder loss");
	EXPECT_STREQ(ToString(static_cast<Entry>(200)), "unknown");
}

} // namespace NetInspector
