//=============================================================================//
//
// Channel decoding against a packet munged the way a server munges one, and the assemblers on
// the orders and faults the network produces
//
//=============================================================================//

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "netinspector/channel.h"

namespace NetInspector
{

namespace
{

// A server's first channel packet after "connect": reliable, one fragment of the normal
// stream carrying 103 bytes (an svc_print), sequence 1, acknowledging 3. Munged by a separate
// implementation of COM_Munge2, so the decoder is checked against the engine's algorithm and
// not against itself; its headers munge to the same bytes a real server sent.
const std::vector<uint8_t> SERVER_PACKET =
{
	0x01, 0x00, 0x00, 0xC0, 0x03, 0x00, 0x00, 0x80, 0x5A, 0x18, 0x01, 0x00, 0x7C, 0x00, 0x10, 0x41,
	0x6F, 0x18, 0x40, 0x01, 0x7D, 0x29, 0x64, 0x24, 0x22, 0x75, 0x20, 0x32, 0x31, 0x22, 0x2F, 0x75,
	0x27, 0x33, 0x75, 0x75, 0x20, 0x62, 0x66, 0x21, 0x7F, 0x6D, 0x7D, 0x66, 0x6A, 0x38, 0x2A, 0x35,
	0x72, 0x6A, 0x30, 0x61, 0x74, 0x68, 0x24, 0x6F, 0x2A, 0x23, 0x73, 0x24, 0x32, 0x20, 0x35, 0x26,
	0x68, 0x2A, 0x22, 0x60, 0x32, 0x78, 0x74, 0x64, 0x35, 0x77, 0x20, 0x6F, 0x69, 0x66, 0x30, 0x24,
	0x64, 0x7D, 0x27, 0x60, 0x7C, 0x60, 0x64, 0x2F, 0x29, 0x64, 0x70, 0x27, 0x7E, 0x3E, 0x60, 0x64,
	0x3F, 0x21, 0x7D, 0x73, 0x33, 0x64, 0x73, 0x21, 0x3F, 0x65, 0x71, 0x64, 0x0A, 0x19, 0x10, 0x4B,
	0x1A, 0x19, 0x41, 0x40, 0x18, 0x49, 0x51, 0x00, 0x01,
};

FragmentHeader MakeFragment(uint32_t index, uint32_t count, uint32_t length)
{
	FragmentHeader fragment = {};
	fragment.present = true;
	fragment.index = index;
	fragment.count = count;
	fragment.id = (index << 16) | count;
	fragment.length = length;
	return fragment;
}

// A -2 split part: netID, sequence, number << 4 | count, then the payload
std::vector<uint8_t> MakeSplitPart(int32_t sequence, uint8_t number, uint8_t count, const std::vector<uint8_t> &payload)
{
	std::vector<uint8_t> part = { 0xFE, 0xFF, 0xFF, 0xFF };
	for (int shift = 0; shift < 32; shift += 8)
		part.push_back(uint8_t(uint32_t(sequence) >> shift));
	part.push_back(uint8_t((number << 4) | count));
	part.insert(part.end(), payload.begin(), payload.end());
	return part;
}

} // namespace

TEST(Channel, DecodesAServerPacket)
{
	std::vector<uint8_t> demunged;
	ChannelPacket packet;
	ASSERT_TRUE(DecodeChannelPacket(SERVER_PACKET.data(), SERVER_PACKET.size(), demunged, packet));

	// svc_print, then its text
	EXPECT_EQ(demunged[packet.payloadOffset], 8);
	EXPECT_EQ(std::string(reinterpret_cast<const char *>(&demunged[packet.payloadOffset + 1]), 12), "netinspector");

	EXPECT_EQ(packet.sequence, 1u);
	EXPECT_EQ(packet.acknowledged, 3u);
	EXPECT_TRUE(packet.reliable);
	EXPECT_TRUE(packet.reliableAcknowledged);
	EXPECT_TRUE(packet.hasFragments);

	const FragmentHeader &normal = packet.fragments[0];
	EXPECT_TRUE(normal.present);
	EXPECT_EQ(normal.index, 1u);
	EXPECT_EQ(normal.count, 1u);
	EXPECT_EQ(normal.offset, 0u);
	EXPECT_EQ(normal.length, 103u);
	EXPECT_FALSE(packet.fragments[1].present);

	EXPECT_EQ(packet.payloadOffset, 18u);
	EXPECT_EQ(packet.payloadLength, 103u);
}

TEST(Channel, MungeReversesUnmunge)
{
	std::vector<uint8_t> payload(SERVER_PACKET.begin() + 8, SERVER_PACKET.end());
	const std::vector<uint8_t> original = payload;

	UnmungeChannelPayload(payload.data(), payload.size(), 0x01);
	EXPECT_NE(payload, original);

	MungeChannelPayload(payload.data(), payload.size(), 0x01);
	EXPECT_EQ(payload, original);
}

TEST(Channel, RefusesFragmentsOutsideThePacket)
{
	std::vector<uint8_t> packet = SERVER_PACKET;

	// The fragment length is the last two bytes of the fragment header, demunged in place
	std::vector<uint8_t> demunged;
	ChannelPacket decoded;
	ASSERT_TRUE(DecodeChannelPacket(packet.data(), packet.size(), demunged, decoded));

	demunged[15] = 0xFF;
	demunged[16] = 0x7F;
	MungeChannelPayload(&demunged[8], demunged.size() - 8, 0x01);

	EXPECT_FALSE(DecodeChannelPacket(demunged.data(), demunged.size(), packet, decoded));
}

TEST(Channel, RefusesPacketsShorterThanTheSequenceWords)
{
	std::vector<uint8_t> demunged;
	ChannelPacket packet;
	EXPECT_FALSE(DecodeChannelPacket(SERVER_PACKET.data(), 7, demunged, packet));
}

TEST(SplitAssembler, JoinsPartsInAnyOrder)
{
	CSplitAssembler assembler;
	CSplitAssembler::Part part = {};
	std::vector<uint8_t> joined;

	const std::vector<uint8_t> second = MakeSplitPart(7, 1, 2, { 'c', 'd' });
	const std::vector<uint8_t> first = MakeSplitPart(7, 0, 2, { 'a', 'b' });

	EXPECT_EQ(assembler.Add(second.data(), second.size(), false, part, joined), CSplitAssembler::Result::Incomplete);
	EXPECT_EQ(part.number, 1u);
	EXPECT_EQ(part.count, 2u);

	ASSERT_EQ(assembler.Add(first.data(), first.size(), false, part, joined), CSplitAssembler::Result::Complete);
	EXPECT_EQ(joined, (std::vector<uint8_t>{ 'a', 'b', 'c', 'd' }));
}

TEST(SplitAssembler, ANewSequenceDropsAnUnfinishedOne)
{
	CSplitAssembler assembler;
	CSplitAssembler::Part part = {};
	std::vector<uint8_t> joined;

	const std::vector<uint8_t> stale = MakeSplitPart(1, 0, 2, { 'x' });
	const std::vector<uint8_t> only = MakeSplitPart(2, 0, 1, { 'y' });

	EXPECT_EQ(assembler.Add(stale.data(), stale.size(), false, part, joined), CSplitAssembler::Result::Incomplete);
	ASSERT_EQ(assembler.Add(only.data(), only.size(), false, part, joined), CSplitAssembler::Result::Complete);
	EXPECT_EQ(joined, (std::vector<uint8_t>{ 'y' }));
}

TEST(SplitAssembler, RefusesAPartNumberBeyondTheCount)
{
	CSplitAssembler assembler;
	CSplitAssembler::Part part = {};
	std::vector<uint8_t> joined;

	const std::vector<uint8_t> broken = MakeSplitPart(3, 5, 2, { 'z' });
	EXPECT_EQ(assembler.Add(broken.data(), broken.size(), false, part, joined), CSplitAssembler::Result::Malformed);
}

TEST(FragmentAssembler, CompletesAndSeesResends)
{
	CFragmentAssembler assembler;
	const uint8_t first[] = { 'B', 'Z', '2' };
	const uint8_t second[] = { '\0', '!' };

	EXPECT_EQ(assembler.Add(MakeFragment(1, 2, sizeof(first)), first), CFragmentAssembler::Result::Added);
	EXPECT_EQ(assembler.Add(MakeFragment(1, 2, sizeof(first)), first), CFragmentAssembler::Result::Repeated);
	ASSERT_EQ(assembler.Add(MakeFragment(2, 2, sizeof(second)), second), CFragmentAssembler::Result::Completed);

	EXPECT_EQ(assembler.GetMessage().size(), 5u);
	EXPECT_EQ(assembler.GetCount(), 2u);
	EXPECT_TRUE(assembler.IsCompressed());
}

TEST(FragmentAssembler, RefusesIndexesOutsideTheCount)
{
	CFragmentAssembler assembler;
	const uint8_t data[] = { 0 };

	EXPECT_EQ(assembler.Add(MakeFragment(0, 2, 1), data), CFragmentAssembler::Result::Malformed);
	EXPECT_EQ(assembler.Add(MakeFragment(3, 2, 1), data), CFragmentAssembler::Result::Malformed);
}

} // namespace NetInspector
