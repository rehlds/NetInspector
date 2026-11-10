//=============================================================================//
//
// The .gcap file layout. A file is a FileHeader followed by entries; every
// entry is an EntryHeader and a body whose layout depends on the entry type.
// All fields are little-endian. Readers skip entry types they do not know, so
// new types never break old readers. docs/format.md describes the same layout.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace NetInspector
{

// "GCAP", then CR LF, EOF and LF: a transfer that rewrites line endings or
// stops at ^Z breaks the magic, so a damaged copy is refused at the header
constexpr char FILE_MAGIC[8] = { 'G', 'C', 'A', 'P', '\r', '\n', '\x1A', '\n' };
constexpr uint16_t FORMAT_VERSION = 1;

// The largest entry body a reader accepts
constexpr uint32_t MAX_ENTRY_BODY = 256 * 1024;

//-----------------------------------------------------------------------------
// Bit sets over enum class, opted in per enum through IsBitSet
//-----------------------------------------------------------------------------
template <typename Enum>
struct IsBitSet : std::false_type {};

template <typename Enum, typename = typename std::enable_if<IsBitSet<Enum>::value>::type>
constexpr Enum operator|(Enum left, Enum right)
{
	using Bits = typename std::underlying_type<Enum>::type;
	return static_cast<Enum>(static_cast<Bits>(left) | static_cast<Bits>(right));
}

template <typename Enum, typename = typename std::enable_if<IsBitSet<Enum>::value>::type>
constexpr Enum &operator|=(Enum &left, Enum right)
{
	return left = left | right;
}

template <typename Enum, typename = typename std::enable_if<IsBitSet<Enum>::value>::type>
constexpr bool HasAny(Enum set, Enum flags)
{
	using Bits = typename std::underlying_type<Enum>::type;
	return (static_cast<Bits>(set) & static_cast<Bits>(flags)) != 0;
}

// The role of the program that made the recording; "in" is what it received
enum class Role : uint8_t
{
	Client = 1,
	Server = 2,
};

// Secrets are scrubbed in every file; addresses only when this says so
enum class FileFlags : uint32_t
{
	None				= 0,
	EndpointsAnonymized	= 1 << 0,
};

template <> struct IsBitSet<FileFlags> : std::true_type {};

//-----------------------------------------------------------------------------
// Session tables (ServerInfo, UserMessages, DeltaDescription, Precache) are
// what the program held when the recording started and whenever they changed
// after. They let a recording that starts mid-session be decoded: the
// messages that carry them crossed the wire before it began.
//-----------------------------------------------------------------------------
enum class Entry : uint8_t
{
	Endpoint			= 1,	// EndpointEntry: gives an endpoint the id later entries refer to
	Datagram			= 2,	// DatagramEntry and the datagram's bytes as they crossed the socket
	Frame				= 3,	// FrameEntry: a frame of the recording program's main loop; idle short ones left out
	Event				= 4,	// EventEntry and key=value text
	ServerInfo			= 5,	// ServerInfoEntry, then the map and the game directory, each NUL-terminated
	OverflowCapture		= 6,	// OverflowCaptureEntry and a client's reliable buffer as it overflowed
	RateSummary			= 7,	// reserved: datagrams of a flooding endpoint counted, not kept
	RecorderLoss		= 8,	// RecorderLossEntry: entries the recorder had to drop
	Stream				= 9,	// reserved: a reassembled stream stored instead of its fragments
	UserMessages		= 10,	// UserMessagesEntry, then per message a UserMessageRecord and its name
	DeltaDescription	= 11,	// DeltaDescriptionEntry, then its DeltaFieldRecord fields
	Precache			= 12,	// PrecacheEntry, then per item its index (u16) and name
	ProcessTime			= 13,	// ProcessTimeEntry: how long a server took over one client's messages in a frame
};

enum class PrecacheKind : uint8_t
{
	Model	= 1,
	Sound	= 2,
	Event	= 3,
	Generic	= 4,
};

enum class Direction : uint8_t
{
	In	= 0,
	Out	= 1,
};

// What a datagram is, by its first four bytes
enum class Datagram : uint8_t
{
	Channel			= 0,	// sequence words and a munged payload
	Connectionless	= 1,	// -1: challenges, connect, rcon, server queries
	Split			= 2,	// -2: a part of a packet larger than the routable size
	SplitExtended	= 3,	// -3: a part of a packet of the extended packet size
	Unknown			= 4,	// shorter than a header
};

enum class DatagramFlags : uint8_t
{
	None		= 0,
	Scrubbed	= 1 << 0,
};

template <> struct IsBitSet<DatagramFlags> : std::true_type {};

enum class EndpointFlags : uint8_t
{
	None		= 0,
	Anonymized	= 1 << 0,
};

template <> struct IsBitSet<EndpointFlags> : std::true_type {};

enum class Event : uint16_t
{
	RecordingStarted	= 1,
	RecordingStopped	= 2,
	Connect				= 3,
	Signon				= 4,
	Map					= 5,
	Disconnect			= 6,
	ClientDropped		= 7,
	Note				= 8,
	Settings			= 9,	// the recording program's settings that shape its traffic
};

// Refers to the Endpoint entry that defined it; 0 is none
struct EndpointId
{
	uint32_t value;

	constexpr bool IsValid() const { return value != 0; }
	constexpr bool operator==(EndpointId other) const { return value == other.value; }
	constexpr bool operator!=(EndpointId other) const { return value != other.value; }
	constexpr bool operator<(EndpointId other) const { return value < other.value; }
};

constexpr EndpointId NO_ENDPOINT = { 0 };

// An IPv4 endpoint
struct Endpoint
{
	uint8_t		ip[4];
	uint16_t	port;	// host order
};

#pragma pack(push, 1)

struct FileHeader
{
	char		magic[8];
	uint16_t	version;
	Role		role;
	uint8_t		reserved;
	FileFlags	flags;
	uint32_t	headerSize;				// entries start here; a later version may add fields
	uint64_t	startUtcMicroseconds;	// wall time of entry time 0
	int32_t		protocol;
	char		application[64];		// name and version of the program that wrote the file
};

struct EntryHeader
{
	Entry		type;
	uint8_t		flags;		// DatagramFlags for datagrams, 0 otherwise
	uint16_t	reserved;
	uint32_t	length;		// body bytes
	uint64_t	time;		// microseconds since the recording started, never decreasing
	EndpointId	endpoint;
};

struct EndpointEntry
{
	uint8_t			ip[4];
	uint16_t		port;
	EndpointFlags	flags;
	uint8_t			reserved;
};

struct DatagramEntry
{
	Direction	direction;
	Datagram	type;
	uint16_t	reserved;
};

struct FrameEntry
{
	uint64_t	frameNumber;
	uint32_t	durationMicroseconds;	// of the previous frame: from its start to this one's; 0 for the first
};

struct ServerInfoEntry
{
	uint8_t		maxClients;
	uint8_t		instancedBaselines;	// packet entities carry a baseline choice bit when there are any
	uint8_t		reserved[2];
};

struct UserMessagesEntry
{
	uint16_t	count;
	uint16_t	reserved;
};

struct UserMessageRecord
{
	uint8_t		id;
	int8_t		size;	// -1: the message carries its own length
};

// A delta field as svc_deltadescription carries it
struct DeltaFieldRecord
{
	uint32_t	type;	// the engine's DT_ bits, DT_SIGNED included
	uint16_t	bits;
	uint16_t	reserved;
	float		preMultiplier;
	float		postMultiplier;
	char		name[32];
};

struct DeltaDescriptionEntry
{
	char		name[32];
	uint16_t	fieldCount;
	uint16_t	reserved;
};

struct PrecacheEntry
{
	PrecacheKind	kind;
	uint8_t			reserved;
	uint16_t		count;
};

// The entry's endpoint is the client; only the long ones are written, the program decides how long
struct ProcessTimeEntry
{
	uint32_t	microseconds;
	uint32_t	reserved;
};

//-----------------------------------------------------------------------------
// The buffer a server queues a client's reliable messages in, taken when a
// message no longer fitted, before the engine cleared it. The body follows
// with queuedBytes of that buffer, then reliableInFlightBytes of the reliable
// message sent and not acknowledged yet. The entry's endpoint is the client.
//-----------------------------------------------------------------------------
struct OverflowCaptureEntry
{
	uint32_t	bufferBytes;			// the buffer's capacity
	uint32_t	requestedBytes;			// the write that did not fit
	uint32_t	queuedBytes;			// in the buffer when it did not
	uint32_t	reliableInFlightBytes;	// sent and not acknowledged yet
	uint32_t	queuedFragmentBuffers;	// waiting to be sent after it
	uint32_t	unacknowledgedPackets;	// sent since the last one the client acknowledged
	uint32_t	silentMilliseconds;		// since the client's last packet
	uint32_t	reserved;
};

struct EventEntry
{
	Event		event;
	uint16_t	reserved;
};

struct RecorderLossEntry
{
	uint32_t	entries;
	uint32_t	reserved;
	uint64_t	bytes;
};

#pragma pack(pop)

static_assert(sizeof(FileHeader) == 96, "FileHeader is part of the format");
static_assert(sizeof(EntryHeader) == 20, "EntryHeader is part of the format");
static_assert(sizeof(EndpointEntry) == 8, "EndpointEntry is part of the format");
static_assert(sizeof(DeltaFieldRecord) == 48, "DeltaFieldRecord is part of the format");
static_assert(sizeof(DeltaDescriptionEntry) == 36, "DeltaDescriptionEntry is part of the format");
static_assert(sizeof(OverflowCaptureEntry) == 32, "OverflowCaptureEntry is part of the format");

Datagram ClassifyDatagram(const uint8_t *data, size_t length);

const char *ToString(Role role);
const char *ToString(Entry entry);
const char *ToString(Direction direction);
const char *ToString(Datagram datagram);
const char *ToString(Event event);
const char *ToString(PrecacheKind kind);

} // namespace NetInspector
