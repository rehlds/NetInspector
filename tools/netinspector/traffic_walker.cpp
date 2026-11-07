//=============================================================================//
//
// The pass over a recording that the message-level reports share
//
//=============================================================================//

#include "traffic_walker.h"

#include <cstring>

namespace NetInspector
{

namespace
{

int Index(Direction direction)
{
	return direction == Direction::In ? 0 : 1;
}

template <typename Body>
bool ReadBody(const EntryHeader &header, const uint8_t *data, Body &body)
{
	if (header.length < sizeof(Body))
		return false;

	std::memcpy(&body, data, sizeof(Body));
	return true;
}

} // namespace

void CTrafficWalker::Walk(CReader &reader, ITrafficListener &listener)
{
	m_Role = reader.GetHeader().role;

	EntryHeader header;
	const uint8_t *body = nullptr;
	while (reader.Next(header, body))
	{
		EndpointEntry address;
		FrameEntry frame;
		OverflowCaptureEntry overflow;
		ProcessTimeEntry processTime;

		switch (header.type)
		{
		case Entry::Endpoint:
			if (ReadBody(header, body, address))
				m_Endpoints.Add(header.endpoint, address);
			break;

		case Entry::Datagram:
			OnDatagram(header, body, listener);
			break;

		case Entry::Event:
			OnEvent(header, body, listener);
			break;

		case Entry::Frame:
			if (ReadBody(header, body, frame))
				listener.OnFrame(header, frame);
			break;

		case Entry::OverflowCapture:
			if (ReadBody(header, body, overflow))
				listener.OnOverflow(header, overflow);
			break;

		case Entry::ProcessTime:
			if (ReadBody(header, body, processTime))
				listener.OnProcessTime(header, processTime);
			break;

		default:
			if (m_Tables.Apply(header, body))
				listener.OnSessionTable(header);
			break;
		}
	}
}

MessageSource CTrafficWalker::SourceOf(Direction direction) const
{
	// A server receives what clients send, and the other way round
	const bool fromClient = (m_Role == Role::Server) == (direction == Direction::In);
	return fromClient ? MessageSource::Client : MessageSource::Server;
}

// A connect opens a new session: the channel starts over, and on a client so do the server's tables
void CTrafficWalker::OnEvent(const EntryHeader &header, const uint8_t *body, ITrafficListener &listener)
{
	EventEntry event;
	if (!ReadBody(header, body, event))
		return;

	if (event.event == Event::Connect && header.endpoint.IsValid())
	{
		m_Channels.erase(header.endpoint);
		if (m_Role == Role::Client)
			m_Tables.Clear();
	}

	listener.OnEvent(header, event, reinterpret_cast<const char *>(body + sizeof(event)));
}

void CTrafficWalker::OnDatagram(const EntryHeader &header, const uint8_t *body, ITrafficListener &listener)
{
	DatagramEntry datagram;
	if (!ReadBody(header, body, datagram))
		return;

	const uint8_t *data = body + sizeof(datagram);
	const size_t length = header.length - sizeof(datagram);
	listener.OnDatagram(header, datagram, data, length);

	if (datagram.type == Datagram::Channel)
	{
		OnChannelPacket(header, datagram.direction, data, length, listener);
		return;
	}

	if (datagram.type != Datagram::Split && datagram.type != Datagram::SplitExtended)
		return;

	CSplitAssembler::Part part = {};
	CSplitAssembler &splits = m_Channels[header.endpoint].splits[Index(datagram.direction)];
	if (splits.Add(data, length, datagram.type == Datagram::SplitExtended, part, m_Joined) != CSplitAssembler::Result::Complete)
		return;

	// The joined packet is copied: the assembler's buffer is reused by the next split
	const std::vector<uint8_t> joined(m_Joined);
	if (ClassifyDatagram(joined.data(), joined.size()) == Datagram::Channel)
		OnChannelPacket(header, datagram.direction, joined.data(), joined.size(), listener);
}

void CTrafficWalker::OnChannelPacket(const EntryHeader &header, Direction direction, const uint8_t *data, size_t length, ITrafficListener &listener)
{
	CChannelReceiver &receiver = m_Channels[header.endpoint].receivers[Index(direction)];
	receiver.Receive(data, length, m_Received);

	const ReceivedPacket packet = { header, direction, SourceOf(direction), length, m_Received };
	listener.OnChannelPacket(packet);

	if (m_Received.verdict != CChannelReceiver::Verdict::Accepted)
		return;

	if (m_Received.processed)
		DecodeStream(packet, false, m_Received.messages, listener);

	if (m_Received.completed[0])
		DecodeStream(packet, true, m_Received.streams[0], listener);

	if (m_Received.completed[1])
		listener.OnFileStream(packet);
}

void CTrafficWalker::DecodeStream(const ReceivedPacket &packet, bool fragmented, const std::vector<uint8_t> &bytes, ITrafficListener &listener)
{
	// A fragmented normal stream may be compressed as a whole
	const std::vector<uint8_t> *stream = &bytes;
	bool decompressed = false;
	if (fragmented && m_Decompressor.Decompress(bytes, m_Decompressed) == CStreamDecompressor::Result::Decompressed)
	{
		stream = &m_Decompressed;
		decompressed = true;
	}

	m_Decoder.Decode(packet.source, stream->data(), stream->size(), packet.received.packet.sequence, m_Decoded);
	m_Streams++;
	if (!m_Decoded.complete)
		m_Stopped++;

	const PacketStream view = { fragmented, decompressed, *stream, m_Decoded };
	listener.OnStream(packet, view);
}

} // namespace NetInspector
