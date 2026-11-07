//=============================================================================//
//
// Datagram classification and the names of the format's enums
//
//=============================================================================//

#include "netinspector/format.h"

#include <cstring>

namespace NetInspector
{

Datagram ClassifyDatagram(const uint8_t *data, size_t length)
{
	if (length < sizeof(int32_t))
		return Datagram::Unknown;

	int32_t netId;
	std::memcpy(&netId, data, sizeof(netId));

	// A channel packet starts with its sequence, whose flag bits never make -1..-3
	switch (netId)
	{
	case -1:	return Datagram::Connectionless;
	case -2:	return Datagram::Split;
	case -3:	return Datagram::SplitExtended;
	default:	return Datagram::Channel;
	}
}

const char *ToString(Role role)
{
	switch (role)
	{
	case Role::Client:	return "client";
	case Role::Server:	return "server";
	}

	return "unknown";
}

const char *ToString(Entry entry)
{
	switch (entry)
	{
	case Entry::Endpoint:			return "endpoint";
	case Entry::Datagram:			return "datagram";
	case Entry::Frame:				return "frame";
	case Entry::Event:				return "event";
	case Entry::ServerInfo:			return "server info";
	case Entry::OverflowCapture:	return "overflow capture";
	case Entry::RateSummary:		return "rate summary";
	case Entry::RecorderLoss:		return "recorder loss";
	case Entry::Stream:				return "stream";
	case Entry::UserMessages:		return "user messages";
	case Entry::DeltaDescription:	return "delta description";
	case Entry::Precache:			return "precache";
	case Entry::ProcessTime:		return "process time";
	}

	return "unknown";
}

const char *ToString(Direction direction)
{
	return direction == Direction::In ? "in" : "out";
}

const char *ToString(Datagram datagram)
{
	switch (datagram)
	{
	case Datagram::Channel:			return "channel";
	case Datagram::Connectionless:	return "connectionless";
	case Datagram::Split:			return "split";
	case Datagram::SplitExtended:	return "split extended";
	case Datagram::Unknown:			return "unknown";
	}

	return "unknown";
}

const char *ToString(Event event)
{
	switch (event)
	{
	case Event::RecordingStarted:	return "recording started";
	case Event::RecordingStopped:	return "recording stopped";
	case Event::Connect:			return "connect";
	case Event::Signon:				return "signon";
	case Event::Map:				return "map";
	case Event::Disconnect:			return "disconnect";
	case Event::ClientDropped:		return "client dropped";
	case Event::Note:				return "note";
	case Event::Settings:			return "settings";
	}

	return "unknown";
}

const char *ToString(PrecacheKind kind)
{
	switch (kind)
	{
	case PrecacheKind::Model:	return "model";
	case PrecacheKind::Sound:	return "sound";
	case PrecacheKind::Event:	return "event";
	case PrecacheKind::Generic:	return "generic";
	}

	return "unknown";
}

} // namespace NetInspector
