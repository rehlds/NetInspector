# The .gcap format

A `.gcap` file ("GoldSrc capture") holds the datagrams one end of a GoldSrc connection sent
and received, as they crossed its socket, together with what that program did around them:
frame times, connection steps, disconnect reasons, the tables decoding needs and reliable
buffers that overflowed. `include/netinspector/format.h` is the
authoritative definition; this page describes the same layout for people writing their own
readers.

All integers are little-endian. Structures are packed.

## File header (96 bytes)

| Offset | Size | Field | |
|---|---|---|---|
| 0 | 8 | magic | `GCAP\r\n\x1A\n` |
| 8 | 2 | version | 1 |
| 10 | 1 | role | 1 client, 2 server: the role of the recording program, whose "in" and "out" the file uses |
| 11 | 1 | reserved | |
| 12 | 4 | flags | see below |
| 16 | 4 | headerSize | where the first entry starts; later versions may add fields |
| 20 | 8 | startUtcMicroseconds | wall time of entry time 0, microseconds since 1970-01-01 UTC |
| 28 | 4 | protocol | network protocol of the application, 48 for GoldSrc |
| 32 | 64 | application | name and version of the program that wrote the file, NUL-terminated |

The magic breaks on any transfer that rewrites line endings or stops at `^Z`, so a damaged
copy is refused at once instead of failing somewhere in the middle.

File flags:

| Bit | Meaning |
|---|---|
| 0 | endpoints anonymized, and the addresses in connectionless text with them |

Secrets are scrubbed in every file and have no flag: rcon passwords, auth blobs, cd keys and
private userinfo values in connectionless datagrams.

## Entries

Every entry is a 20-byte header and `length` bytes of body:

| Offset | Size | Field | |
|---|---|---|---|
| 0 | 1 | type | see below |
| 1 | 1 | flags | per type |
| 2 | 2 | reserved | |
| 4 | 4 | length | body bytes |
| 8 | 8 | time | microseconds since the recording started; never decreases |
| 16 | 4 | endpoint | id of an earlier Endpoint entry, 0 for none |

A reader skips entry types it does not know by their length. A file whose writer was killed
ends inside an entry; readers stop before it.

| Type | Entry | Body |
|---|---|---|
| 1 | Endpoint | ip[4], port (u16, host order), flags (bit 0: anonymized), reserved. Defines the id in the header's `endpoint` field. |
| 2 | Datagram | direction (0 in, 1 out), type, reserved (u16), then the datagram's bytes. Flags bit 0: scrubbed. |
| 3 | Frame | frameNumber (u64), durationMicroseconds (u32): written at the start of every frame of the main loop, with how long the frame before it took (0 for the first). The datagrams between two of them are what that frame took in and sent out. |
| 4 | Event | event (u16), reserved (u16), then `key=value` text, NUL-terminated. |
| 5 | ServerInfo | maxClients (u8), instancedBaselines (u8), reserved[2], then the map and the game directory, each NUL-terminated. |
| 6 | OverflowCapture | bufferBytes, requestedBytes, queuedBytes, reliableInFlightBytes, queuedFragmentBuffers, unacknowledgedPackets, silentMilliseconds, reserved (u32 each), then queuedBytes of the client's reliable message buffer at the write that did not fit and reliableInFlightBytes of the reliable data sent and not acknowledged. The endpoint is the client. |
| 8 | RecorderLoss | entries (u32), reserved (u32), bytes (u64) the recorder dropped with its queue full. |
| 10 | UserMessages | count (u16), reserved (u16), then per message: id (u8), size (i8, -1 when the message carries its length), name NUL-terminated. Replaces the whole table. |
| 11 | DeltaDescription | name (char[32]), fieldCount (u16), reserved (u16), then per field 48 bytes: type (u32, the engine's DT_ bits), bits (u16), reserved (u16), preMultiplier (f32), postMultiplier (f32), name (char[32]). Replaces the description of that name. |
| 12 | Precache | kind (u8: 1 model, 2 sound, 3 event, 4 generic), reserved (u8), count (u16), then per item: index (u16), name NUL-terminated. Replaces that kind's table. |
| 13 | ProcessTime | microseconds (u32), reserved (u32): how long a server took over one client's messages in a frame; the endpoint is the client. Only the long ones are written. |
| 7, 9 | reserved | rate summary, stream |

Datagram types, by the first four bytes: 0 channel packet, 1 connectionless (`-1`),
2 split (`-2`), 3 extended split (`-3`), 4 shorter than four bytes.

Events: 1 recording started, 2 recording stopped, 3 connect, 4 signon step, 5 map,
6 disconnect, 7 client dropped, 8 note, 9 settings.

## Session tables

ServerInfo, UserMessages, DeltaDescription and Precache hold what the recording program had
in memory: right after the recording starts, and again whenever one of them changes. The
messages that set these tables on the wire cross it once, when a player joins; a recording
that starts later still decodes with them. A table entry replaces the table it names; the
wire messages that set the same tables update them the same way.

## Channel packets

Datagrams are stored as they were on the wire, munged. Their first eight bytes are the
sequence and acknowledgement words; the rest is munged with COM_Munge2 keyed by the low byte
of the sequence. `include/netinspector/channel.h` decodes them.
