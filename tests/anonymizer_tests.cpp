//=============================================================================//
//
// What the anonymizer keeps and what it takes out
//
//=============================================================================//

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include "netinspector/anonymizer.h"
#include "netinspector/channel.h"

namespace NetInspector
{

namespace
{

const uint8_t TEST_KEY[CAnonymizer::KEY_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

CAnonymizer MakeAnonymizer()
{
	CAnonymizer anonymizer;
	anonymizer.SetKey(TEST_KEY);
	return anonymizer;
}

std::vector<uint8_t> Connectionless(const std::string &text)
{
	std::vector<uint8_t> packet = { 0xFF, 0xFF, 0xFF, 0xFF };
	packet.insert(packet.end(), text.begin(), text.end());
	return packet;
}

std::string TextOf(const std::vector<uint8_t> &packet)
{
	return std::string(packet.begin() + 4, packet.end());
}

uint32_t ToIPv4(const Endpoint &endpoint)
{
	return (uint32_t(endpoint.ip[0]) << 24) | (uint32_t(endpoint.ip[1]) << 16) | (uint32_t(endpoint.ip[2]) << 8) | endpoint.ip[3];
}

int CommonPrefixBits(uint32_t left, uint32_t right)
{
	int bits = 0;
	while (bits < 32 && ((left ^ right) & (0x80000000u >> bits)) == 0)
		bits++;
	return bits;
}

} // namespace

TEST(Anonymizer, KeepsPrefixesAndPorts)
{
	const CAnonymizer anonymizer = MakeAnonymizer();

	const Endpoint first = anonymizer.Map(Endpoint{ { 198, 51, 100, 177 }, 27015 });
	const Endpoint neighbour = anonymizer.Map(Endpoint{ { 198, 51, 100, 10 }, 27005 });
	const Endpoint stranger = anonymizer.Map(Endpoint{ { 10, 0, 0, 1 }, 27015 });

	EXPECT_NE(ToIPv4(first), 0xC63364B1u);
	EXPECT_EQ(first.port, 27015);
	EXPECT_GE(CommonPrefixBits(ToIPv4(first), ToIPv4(neighbour)), 24);
	EXPECT_LT(CommonPrefixBits(ToIPv4(first), ToIPv4(stranger)), 8);
}

TEST(Anonymizer, MapsTheSameWayWithTheSameKey)
{
	const Endpoint endpoint = { { 198, 51, 100, 177 }, 27015 };
	EXPECT_EQ(ToIPv4(MakeAnonymizer().Map(endpoint)), ToIPv4(MakeAnonymizer().Map(endpoint)));
}

TEST(Anonymizer, LeavesLoopbackAlone)
{
	const Endpoint loopback = { { 127, 0, 0, 1 }, 27015 };
	EXPECT_EQ(ToIPv4(MakeAnonymizer().Map(loopback)), 0x7F000001u);
}

TEST(Anonymizer, ScrubsRconPasswordsEvenWithoutAnonymizing)
{
	const CAnonymizer anonymizer = MakeAnonymizer();
	std::vector<uint8_t> scrubbed;

	const std::vector<uint8_t> quoted = Connectionless("rcon 12345 \"getpizd\" status\n");
	ASSERT_TRUE(anonymizer.ScrubConnectionless(quoted.data(), quoted.size(), false, scrubbed));
	EXPECT_EQ(TextOf(scrubbed), "rcon 12345 \"*******\" status\n");

	const std::vector<uint8_t> bare = Connectionless("rcon 12345 getpizd status\n");
	ASSERT_TRUE(anonymizer.ScrubConnectionless(bare.data(), bare.size(), false, scrubbed));
	EXPECT_EQ(TextOf(scrubbed), "rcon 12345 ******* status\n");
}

TEST(Anonymizer, ScrubsConnectButKeepsItsShape)
{
	const CAnonymizer anonymizer = MakeAnonymizer();
	const std::string text = "connect 48 777 \"\\prot\\3\\unique\\-1\\raw\\steam\\cdkey\\abcdef\" \"\\name\\player\\_pw\\sookaeb\\rate\\100000\"\n";

	std::vector<uint8_t> packet = Connectionless(text);
	const uint8_t ticket[] = { 0x14, 0x00, 0x00, 0x00, 0xAB, 0xCD };
	packet.insert(packet.end(), ticket, ticket + sizeof(ticket));

	std::vector<uint8_t> scrubbed;
	ASSERT_TRUE(anonymizer.ScrubConnectionless(packet.data(), packet.size(), true, scrubbed));
	ASSERT_EQ(scrubbed.size(), packet.size());

	const std::string scrubbedText(scrubbed.begin() + 4, scrubbed.begin() + 4 + text.size());
	EXPECT_NE(scrubbedText.find("\\raw\\steam\\cdkey\\000000\""), std::string::npos);
	EXPECT_NE(scrubbedText.find("\\name\\player\\_pw\\*******\\rate\\100000"), std::string::npos);

	for (size_t i = 4 + text.size(); i < scrubbed.size(); i++)
		EXPECT_EQ(scrubbed[i], 0) << "ticket byte " << i;
}

TEST(Anonymizer, MapsAddressesWithPortsInText)
{
	const CAnonymizer anonymizer = MakeAnonymizer();
	const std::vector<uint8_t> accept = Connectionless("B 1 \"198.51.100.177:27005\" 0 10561");

	std::vector<uint8_t> scrubbed;
	ASSERT_TRUE(anonymizer.ScrubConnectionless(accept.data(), accept.size(), true, scrubbed));

	const std::string text = TextOf(scrubbed);
	EXPECT_EQ(text.find("198.51.100.177"), std::string::npos);
	EXPECT_NE(text.find(":27005\" 0 10561"), std::string::npos);
}

TEST(Anonymizer, LeavesQuadsWithoutPortsAlone)
{
	const CAnonymizer anonymizer = MakeAnonymizer();
	const std::vector<uint8_t> info = Connectionless("version 1.1.2.7/Stdio");

	std::vector<uint8_t> scrubbed;
	EXPECT_FALSE(anonymizer.ScrubConnectionless(info.data(), info.size(), true, scrubbed));
	EXPECT_EQ(scrubbed, info);
}

TEST(Anonymizer, ScrubsSecretsWhenAddressesStayReal)
{
	const CAnonymizer anonymizer = MakeAnonymizer();
	const std::string text = "connect 48 777 \"\\prot\\3\\cdkey\\abcdef\" \"\\name\\player\\_pw\\sookaeb\"\n";

	std::vector<uint8_t> packet = Connectionless(text);
	packet.push_back(0xAB);

	std::vector<uint8_t> scrubbed;
	ASSERT_TRUE(anonymizer.ScrubConnectionless(packet.data(), packet.size(), false, scrubbed));

	const std::string scrubbedText(scrubbed.begin() + 4, scrubbed.end() - 1);
	EXPECT_NE(scrubbedText.find("\\cdkey\\000000\""), std::string::npos);
	EXPECT_NE(scrubbedText.find("\\_pw\\*******\""), std::string::npos);
	EXPECT_EQ(scrubbed.back(), 0);

	const std::vector<uint8_t> accept = Connectionless("B 1 \"198.51.100.177:27005\" 0 10561");
	EXPECT_FALSE(anonymizer.ScrubConnectionless(accept.data(), accept.size(), false, scrubbed));
	EXPECT_EQ(scrubbed, accept);
}

TEST(Anonymizer, MasksPrivateCommandsInChannelPackets)
{
	CAnonymizer anonymizer = MakeAnonymizer();
	anonymizer.SetPrivateCommands({ "token" });

	const std::string command = "\x03token \"sookaeb+/=\"\n";
	std::vector<uint8_t> packet = { 0x07, 0x00, 0x00, 0x80, 0x02, 0x00, 0x00, 0x00 };
	packet.insert(packet.end(), command.begin(), command.end());
	packet.push_back(0);
	packet.push_back(0x05);
	MungeChannelPayload(&packet[CHANNEL_HEADER_SIZE], packet.size() - CHANNEL_HEADER_SIZE, packet[0]);

	std::vector<uint8_t> scrubbed;
	ASSERT_TRUE(anonymizer.ScrubChannel(packet.data(), packet.size(), scrubbed));
	ASSERT_EQ(scrubbed.size(), packet.size());
	EXPECT_TRUE(std::equal(packet.begin(), packet.begin() + CHANNEL_HEADER_SIZE, scrubbed.begin()));

	UnmungeChannelPayload(&scrubbed[CHANNEL_HEADER_SIZE], scrubbed.size() - CHANNEL_HEADER_SIZE, scrubbed[0]);
	const std::string text(scrubbed.begin() + CHANNEL_HEADER_SIZE, scrubbed.end());
	EXPECT_EQ(text, std::string("\x03token \"**********\"\n") + std::string(1, '\0') + "\x05");

	// Nothing private: the packet stays as it was
	anonymizer.SetPrivateCommands({ "other" });
	EXPECT_FALSE(anonymizer.ScrubChannel(packet.data(), packet.size(), scrubbed));
	EXPECT_EQ(scrubbed, packet);
}

} // namespace NetInspector
