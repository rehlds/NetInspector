//=============================================================================//
//
// The summary of a recording
//
//=============================================================================//

#include "info_report.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <map>
#include <vector>

#include "endpoint_directory.h"
#include "netinspector/decoder/session_tables.h"
#include "report_clock.h"

namespace NetInspector
{

namespace
{

const PrecacheKind PRECACHE_KINDS[] = { PrecacheKind::Model, PrecacheKind::Sound, PrecacheKind::Event, PrecacheKind::Generic };

struct EndpointTraffic
{
	uint64_t packetsIn = 0;
	uint64_t packetsOut = 0;
	uint64_t bytesIn = 0;
	uint64_t bytesOut = 0;
	uint64_t firstTime = 0;
	uint64_t lastTime = 0;
	uint32_t sessions = 0;		// connect events
};

// Well above an ordinary 100 Hz tick: what a player feels as a stall
constexpr uint32_t SLOW_FRAME_MICROSECONDS = 50000;

struct FrameTotals
{
	uint64_t frames = 0;
	uint64_t microseconds = 0;
	uint32_t longest = 0;
	uint64_t longestEnd = 0;
	uint64_t slowFrames = 0;
	std::map<uint64_t, uint32_t> perSecond;	// frames that ended in each second of the recording
};

struct OverflowCapture
{
	uint64_t time;
	EndpointId endpoint;
	OverflowCaptureEntry state;
	uint32_t capturedBytes;
};

struct Totals
{
	std::map<Entry, uint64_t> entries;
	std::map<Datagram, uint64_t> datagrams;
	std::map<EndpointId, EndpointTraffic> traffic;
	FrameTotals frames;
	std::vector<OverflowCapture> overflows;
	uint64_t duration = 0;
	uint64_t lostEntries = 0;
	uint64_t lostBytes = 0;
};

template <typename Body>
bool ReadBody(const EntryHeader &header, const uint8_t *data, Body &body)
{
	if (header.length < sizeof(Body))
		return false;

	std::memcpy(&body, data, sizeof(Body));
	return true;
}

void CountDatagram(Totals &totals, const EntryHeader &header, const DatagramEntry &datagram)
{
	totals.datagrams[datagram.type]++;

	EndpointTraffic &traffic = totals.traffic[header.endpoint];
	if (traffic.packetsIn + traffic.packetsOut == 0)
		traffic.firstTime = header.time;
	traffic.lastTime = header.time;

	const uint64_t bytes = header.length - sizeof(DatagramEntry);
	if (datagram.direction == Direction::In)
	{
		traffic.packetsIn++;
		traffic.bytesIn += bytes;
	}
	else
	{
		traffic.packetsOut++;
		traffic.bytesOut += bytes;
	}
}

// A frame entry closes the frame before it
void CountFrame(FrameTotals &frames, const EntryHeader &header, const FrameEntry &frame)
{
	if (frame.durationMicroseconds == 0)
		return;

	frames.frames++;
	frames.microseconds += frame.durationMicroseconds;
	frames.perSecond[header.time / 1000000]++;

	if (frame.durationMicroseconds >= SLOW_FRAME_MICROSECONDS)
		frames.slowFrames++;

	if (frame.durationMicroseconds > frames.longest)
	{
		frames.longest = frame.durationMicroseconds;
		frames.longestEnd = header.time;
	}
}

void PrintFrames(const FrameTotals &frames, const CReportClock &clock)
{
	if (frames.frames == 0)
		return;

	// The first and the last second are cut by the recording's start and end
	uint64_t slowestSecond = 0;
	uint32_t slowestCount = 0;
	if (frames.perSecond.size() > 2)
	{
		std::map<uint64_t, uint32_t>::const_iterator second = std::next(frames.perSecond.begin());
		const std::map<uint64_t, uint32_t>::const_iterator last = std::prev(frames.perSecond.end());
		for (; second != last; ++second)
		{
			if (slowestCount == 0 || second->second < slowestCount)
			{
				slowestSecond = second->first;
				slowestCount = second->second;
			}
		}
	}

	const double average = double(frames.microseconds) / double(frames.frames);
	std::printf("\nframes\n");
	std::printf("  %-30s %" PRIu64 "\n", "count", frames.frames);
	std::printf("  %-30s %.2f ms, %.1f a second\n", "average", average / 1000.0, 1000000.0 / average);
	if (slowestCount)
		std::printf("  %-30s %u frames, from %s\n", "slowest second", slowestCount, clock.Relative(slowestSecond * 1000000).c_str());
	std::printf("  %-30s %.1f ms, ending at %s\n", "longest", frames.longest / 1000.0, clock.Relative(frames.longestEnd).c_str());
	std::printf("  %-30s %" PRIu64 "\n", "frames of 50 ms or more", frames.slowFrames);
}

void PrintSessionTables(const CSessionTables &tables)
{
	if (!tables.GetMaxClients() && !tables.GetUserMessageCount() && tables.GetDeltaDescriptions().empty())
	{
		std::printf("\nsession tables: none in the recording\n");
		return;
	}

	std::printf("\nsession tables, as the recording ends\n");

	if (tables.GetMaxClients())
	{
		std::printf("  %-30s %s, %s, %d players\n", "server", tables.GetMap().c_str(), tables.GetGameDirectory().c_str(), tables.GetMaxClients());
	}

	std::printf("  %-30s %zu\n", "user messages", tables.GetUserMessageCount());

	std::string names;
	for (const std::pair<const std::string, DeltaDescription> &description : tables.GetDeltaDescriptions())
		names += (names.empty() ? "" : ", ") + description.first;
	std::printf("  %-30s %zu%s%s\n", "delta descriptions", tables.GetDeltaDescriptions().size(), names.empty() ? "" : ": ", names.c_str());

	for (PrecacheKind kind : PRECACHE_KINDS)
	{
		const std::string label = std::string("precached ") + ToString(kind) + "s";
		std::printf("  %-30s %zu\n", label.c_str(), tables.GetPrecacheCount(kind));
	}
}

void PrintOverflows(const std::vector<OverflowCapture> &overflows, const CEndpointDirectory &addresses, const CReportClock &clock)
{
	if (overflows.empty())
		return;

	std::printf("\nreliable buffer overflows\n");
	for (const OverflowCapture &overflow : overflows)
	{
		std::printf("  %s %-26s %u of %u bytes queued, %u more asked; %u bytes in flight, %u fragment buffers waiting\n",
			clock.Relative(overflow.time).c_str(), addresses.Describe(overflow.endpoint).c_str(), overflow.capturedBytes,
			overflow.state.bufferBytes, overflow.state.requestedBytes, overflow.state.reliableInFlightBytes, overflow.state.queuedFragmentBuffers);
	}
}

} // namespace

int CInfoReport::Run(CReader &reader)
{
	const FileHeader &file = reader.GetHeader();
	const CReportClock clock(file);
	const bool anonymized = HasAny(file.flags, FileFlags::EndpointsAnonymized);

	std::printf("file\n");
	std::printf("  %-30s %u\n", "format version", file.version);
	std::printf("  %-30s %s, as %s\n", "recorded by", file.application, ToString(file.role));
	std::printf("  %-30s %d\n", "protocol", file.protocol);
	std::printf("  %-30s %s UTC, %s local\n", "started", clock.UtcDateTime(0).c_str(), clock.LocalTime(0).c_str());
	std::printf("  %-30s %s\n", "addresses", anonymized ? "anonymized" : "real");

	if (!anonymized)
		std::printf("  WARNING: real addresses inside; anonymize the file before sharing it\n");

	CEndpointDirectory addresses;
	CSessionTables tables;
	Totals totals;

	EntryHeader header;
	const uint8_t *body = nullptr;
	while (reader.Next(header, body))
	{
		totals.entries[header.type]++;
		totals.duration = header.time;

		EndpointEntry address;
		DatagramEntry datagram;
		FrameEntry frame;
		RecorderLossEntry loss;
		EventEntry event;
		OverflowCapture overflow;

		switch (header.type)
		{
		case Entry::Endpoint:
			if (ReadBody(header, body, address))
				addresses.Add(header.endpoint, address);
			break;

		case Entry::Datagram:
			if (ReadBody(header, body, datagram))
				CountDatagram(totals, header, datagram);
			break;

		case Entry::Event:
			if (ReadBody(header, body, event) && event.event == Event::Connect && header.endpoint.IsValid())
				totals.traffic[header.endpoint].sessions++;
			break;

		case Entry::Frame:
			if (ReadBody(header, body, frame))
				CountFrame(totals.frames, header, frame);
			break;

		case Entry::OverflowCapture:
			if (ReadBody(header, body, overflow.state))
			{
				overflow.time = header.time;
				overflow.endpoint = header.endpoint;
				overflow.capturedBytes = overflow.state.queuedBytes;
				totals.overflows.push_back(overflow);
			}
			break;

		case Entry::RecorderLoss:
			if (ReadBody(header, body, loss))
			{
				totals.lostEntries += loss.entries;
				totals.lostBytes += loss.bytes;
			}
			break;

		default:
			tables.Apply(header, body);
			break;
		}
	}

	std::printf("  %-30s %.3f s\n", "duration", double(totals.duration) / 1000000.0);
	if (reader.IsTruncated())
		std::printf("  WARNING: the file ends inside an entry; the recording was not stopped\n");

	std::printf("\nentries\n");
	for (const std::pair<const Entry, uint64_t> &count : totals.entries)
		std::printf("  %-30s %" PRIu64 "\n", ToString(count.first), count.second);

	std::printf("\ndatagrams\n");
	for (const std::pair<const Datagram, uint64_t> &count : totals.datagrams)
		std::printf("  %-30s %" PRIu64 "\n", ToString(count.first), count.second);

	PrintFrames(totals.frames, clock);
	PrintSessionTables(tables);
	PrintOverflows(totals.overflows, addresses, clock);

	if (totals.lostEntries)
	{
		std::printf("\nWARNING: the recorder dropped %" PRIu64 " entries (%" PRIu64 " bytes) with its queue full\n",
			totals.lostEntries, totals.lostBytes);
	}

	std::printf("\nendpoints\n");
	std::printf("  %-28s %8s %10s %12s %11s %12s %12s %12s\n", "address", "sessions", "packets in", "bytes in", "packets out", "bytes out", "first", "last");
	for (const std::pair<const EndpointId, EndpointTraffic> &endpoint : totals.traffic)
	{
		const EndpointTraffic &traffic = endpoint.second;
		std::printf("  %-28s %8u %10" PRIu64 " %12" PRIu64 " %11" PRIu64 " %12" PRIu64 " %12s %12s\n", addresses.Describe(endpoint.first).c_str(),
			traffic.sessions, traffic.packetsIn, traffic.bytesIn, traffic.packetsOut, traffic.bytesOut,
			clock.Relative(traffic.firstTime).c_str(), clock.Relative(traffic.lastTime).c_str());
	}

	return 0;
}

} // namespace NetInspector
