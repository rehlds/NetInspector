//=============================================================================//
//
// A server's packet to a client in its two parts. Netchan_Transmit writes the
// reliable data first and the datagram after it. The server writes three
// datagrams: a frame's, from SV_SendClientDatagram, that opens with svc_time,
// an optional svc_choke, an optional svc_addangle or svc_setangle, then
// svc_clientdata; none, for a client that does not play yet; and the last
// word to a dropped client, a lone svc_disconnect from SV_DropClient or a
// secure server's svc_print. The split follows those and nothing else.
//
//=============================================================================//

#pragma once

#include <cstddef>

#include "netinspector/decoder/message_decoder.h"

namespace NetInspector
{

struct ServerPacketParts
{
	enum class Layout
	{
		ReliableOnly,	// no datagram: a client that does not play yet
		DatagramOnly,	// no reliable messages; fragments may still have ridden along
		Both,
		Final,			// a dropped client's last packet: its datagram is the last message
		Unknown,		// the packet does not follow the layout, or did not decode to the datagram
	};

	Layout	layout = Layout::Unknown;
	size_t	reliableMessages = 0;	// the first messages of the stream, the datagram after them
	size_t	reliableBytes = 0;		// what they took of netchan.message
	bool	choked = false;			// svc_choke: the server held packets back for the client's rate
};

// The packet's own stream, fragments taken out; reliable is the packet's reliable flag
ServerPacketParts SplitServerPacket(const DecodedStream &stream, bool reliable);

} // namespace NetInspector
