//=============================================================================//
//
// A server's packet split into its reliable data and its datagram
//
//=============================================================================//

#include <gtest/gtest.h>

#include <initializer_list>

#include "netinspector/decoder/protocol.h"
#include "netinspector/decoder/server_packet.h"

namespace NetInspector
{

namespace
{

constexpr int TEXT_MSG = 77;	// a user message

// Every message of 10 bytes, the stream read to its end
DecodedStream Stream(std::initializer_list<int> ids, bool complete = true)
{
	DecodedStream stream;
	for (int id : ids)
	{
		DecodedMessage message = {};
		message.id = id;
		message.length = 10;
		stream.messages.push_back(message);
	}
	stream.complete = complete;
	return stream;
}

} // namespace

TEST(ServerPacket, SplitsTheReliableDataFromTheDatagram)
{
	const ServerPacketParts parts = SplitServerPacket(Stream({ svc_print, TEXT_MSG, svc_time, svc_clientdata, svc_deltapacketentities, TEXT_MSG, svc_nop }), true);

	EXPECT_EQ(parts.layout, ServerPacketParts::Layout::Both);
	EXPECT_EQ(parts.reliableMessages, 2u);
	EXPECT_EQ(parts.reliableBytes, 20u);
	EXPECT_FALSE(parts.choked);
}

TEST(ServerPacket, TakesTheChokeAndTheAngleIntoTheDatagram)
{
	const ServerPacketParts parts = SplitServerPacket(Stream({ svc_time, svc_choke, svc_setangle, svc_clientdata, svc_packetentities }), false);

	EXPECT_EQ(parts.layout, ServerPacketParts::Layout::DatagramOnly);
	EXPECT_EQ(parts.reliableMessages, 0u);
	EXPECT_TRUE(parts.choked);
}

TEST(ServerPacket, AReliablePacketWithoutADatagramIsAllReliable)
{
	const ServerPacketParts parts = SplitServerPacket(Stream({ svc_serverinfo, svc_resourcelist, svc_nop }), true);

	EXPECT_EQ(parts.layout, ServerPacketParts::Layout::ReliableOnly);
	EXPECT_EQ(parts.reliableMessages, 2u);
	EXPECT_EQ(parts.reliableBytes, 20u);
}

// SV_WriteSpawn writes svc_time into the reliable data, with no svc_clientdata after it
TEST(ServerPacket, AReliableSvcTimeDoesNotOpenTheDatagram)
{
	const ServerPacketParts parts = SplitServerPacket(Stream({ svc_time, svc_updateuserinfo, svc_setangle, svc_time, svc_clientdata, svc_packetentities }), true);

	EXPECT_EQ(parts.layout, ServerPacketParts::Layout::Both);
	EXPECT_EQ(parts.reliableMessages, 3u);
}

TEST(ServerPacket, ReliableFlagWithFragmentsOnlyHasNoReliableMessages)
{
	const ServerPacketParts parts = SplitServerPacket(Stream({ svc_time, svc_clientdata, svc_deltapacketentities }), true);

	EXPECT_EQ(parts.layout, ServerPacketParts::Layout::DatagramOnly);
	EXPECT_EQ(parts.reliableBytes, 0u);
}

TEST(ServerPacket, LeavesWhatDoesNotFollowTheLayoutUnknown)
{
	// Two datagrams
	EXPECT_EQ(SplitServerPacket(Stream({ svc_time, svc_clientdata, svc_time, svc_clientdata }), true).layout, ServerPacketParts::Layout::Unknown);

	// Unreliable messages without a datagram, or before it
	EXPECT_EQ(SplitServerPacket(Stream({ TEXT_MSG }), false).layout, ServerPacketParts::Layout::Unknown);
	EXPECT_EQ(SplitServerPacket(Stream({ TEXT_MSG, svc_time, svc_clientdata }), false).layout, ServerPacketParts::Layout::Unknown);

	// The decoder stopped before a datagram it may not have reached
	EXPECT_EQ(SplitServerPacket(Stream({ svc_print }, false), true).layout, ServerPacketParts::Layout::Unknown);
}

// SV_DropClient writes svc_disconnect into netchan.message and sends it once more as the datagram
TEST(ServerPacket, TakesTheLastWordToADroppedClientAsTheDatagram)
{
	const ServerPacketParts alone = SplitServerPacket(Stream({ svc_disconnect, svc_nop }), false);
	EXPECT_EQ(alone.layout, ServerPacketParts::Layout::Final);
	EXPECT_EQ(alone.reliableMessages, 0u);

	const ServerPacketParts after = SplitServerPacket(Stream({ svc_print, TEXT_MSG, svc_disconnect, svc_disconnect }), true);
	EXPECT_EQ(after.layout, ServerPacketParts::Layout::Final);
	EXPECT_EQ(after.reliableMessages, 3u);

	const ServerPacketParts notice = SplitServerPacket(Stream({ svc_print }), false);
	EXPECT_EQ(notice.layout, ServerPacketParts::Layout::Final);

	// Unreliable messages before it are not what SV_DropClient sends
	EXPECT_EQ(SplitServerPacket(Stream({ TEXT_MSG, svc_disconnect }), false).layout, ServerPacketParts::Layout::Unknown);
}

TEST(ServerPacket, PaddingAloneIsAnEmptyDatagram)
{
	const ServerPacketParts parts = SplitServerPacket(Stream({ svc_nop }), false);

	EXPECT_EQ(parts.layout, ServerPacketParts::Layout::DatagramOnly);
	EXPECT_EQ(parts.reliableMessages, 0u);
}

} // namespace NetInspector
