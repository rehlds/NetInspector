//=============================================================================//
//
// The recorder a game or a server embeds. It takes datagrams, frames and
// events from the program's threads and writes them to a .gcap file from a
// thread of its own: a recorded datagram costs the caller one copy into a
// queue, and with no recording running, one check.
//
//=============================================================================//

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "netinspector/format.h"

namespace NetInspector
{

class CRecorder
{
public:
	struct Settings
	{
		Role		role = Role::Client;
		std::string	application;					// name and version of the recording program
		int32_t		protocol = 0;
		bool		anonymizeAddresses = true;		// secrets are scrubbed either way
		uint32_t	queueBytes = 16 * 1024 * 1024;	// entries waiting for the writer; more are dropped and counted

		// Userinfo keys to scrub besides the ones starting with an underscore
		std::vector<std::string> privateUserInfoKeys;

		// Console commands whose arguments are scrubbed wherever a channel packet carries them
		std::vector<std::string> privateCommands;
	};

	struct UserMessage
	{
		int			id;
		int			size;	// -1: the message carries its own length
		const char	*name;
	};

	struct DeltaField
	{
		const char	*name;
		uint32_t	type;	// the engine's DT_ bits
		int			bits;
		float		preMultiplier;
		float		postMultiplier;
	};

	struct PrecacheItem
	{
		int			index;
		const char	*name;
	};

	CRecorder();
	~CRecorder();

	CRecorder(const CRecorder &) = delete;
	CRecorder &operator=(const CRecorder &) = delete;

	//-----------------------------------------------------------------------------
	// Creates the file and starts the writer thread. False if the file cannot be
	// created, a recording is running, or anonymization was asked for and no key
	// could be made.
	//-----------------------------------------------------------------------------
	bool Start(const char *path, const Settings &settings);

	// Writes out what is queued and closes the file
	void Stop();

	bool IsRecording() const { return m_Recording.load(std::memory_order_relaxed); }

	//-----------------------------------------------------------------------------
	// Any thread. Received datagrams are recorded on arrival, so a stalled main
	// loop shows as the gap between arrival and processing.
	//-----------------------------------------------------------------------------
	void RecordDatagram(Direction direction, const Endpoint &endpoint, const void *data, size_t length);

	//-----------------------------------------------------------------------------
	// The main loop, once per frame, at its start. Every frame is written: the
	// datagrams between two frames are what one frame took in and sent out.
	//-----------------------------------------------------------------------------
	void RecordFrame(uint64_t frameNumber);

	//-----------------------------------------------------------------------------
	// Any thread. The session tables as the program holds them, right after Start
	// and again whenever one changes; a later call replaces the table it names.
	// A precache list longer than an entry holds is cut at the entry's limit.
	//-----------------------------------------------------------------------------
	void RecordServerInfo(int maxClients, int instancedBaselines, const char *map, const char *gameDirectory);
	void RecordUserMessages(const UserMessage *messages, size_t count);
	void RecordDeltaDescription(const char *name, const DeltaField *fields, size_t count);
	void RecordPrecache(PrecacheKind kind, const PrecacheItem *items, size_t count);

	//-----------------------------------------------------------------------------
	// Any thread. A client's reliable buffer that a write did not fit, before it
	// is cleared: state.queuedBytes of queued, state.reliableInFlightBytes of
	// inFlight. Bytes past an entry's limit are cut, and the lengths with them.
	//-----------------------------------------------------------------------------
	void RecordOverflow(const Endpoint &client, const OverflowCaptureEntry &state, const void *queued, const void *inFlight);

	// The main loop. How long it took over one client's messages; the caller keeps only the long ones
	void RecordProcessTime(const Endpoint &client, uint32_t microseconds);

	//-----------------------------------------------------------------------------
	// Any thread. The text is key=value pairs without addresses: an address goes
	// through endpoint, where the anonymizer sees it.
	//-----------------------------------------------------------------------------
	void RecordEvent(Event event, const Endpoint *endpoint, const char *text);

	// Microseconds since Start on the recording's clock
	uint64_t GetTime() const;

	uint64_t GetBytesWritten() const;

	// The disk refused a write: the recording goes on, the file ends there
	bool HasFailed() const;

private:
	class CImpl;

	std::unique_ptr<CImpl>	m_Impl;
	std::atomic<bool>		m_Recording;
};

} // namespace NetInspector
