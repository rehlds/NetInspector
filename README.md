# NetInspector

Records and inspects GoldSrc network traffic.

A server or a game client embeds the recorder and writes every datagram it sends and receives
into a `.gcap` file, along with the start of every frame of its main loop, connection steps, disconnect reasons, the
session tables decoding needs (user messages, delta descriptions, precache names) and the
contents of a client's reliable buffer when it overflows. The `netinspector` tool reads the
file back: who recorded it, which endpoints took part, and a channel-level timeline of
sequences, acknowledgements, reliable bits, fragments and round trips. It answers questions a
log cannot, such as whether a client stopped answering before the server dropped it, or what
a flooding address actually sent.

Steam tickets, cd keys, private userinfo values and rcon passwords are always taken out.
Addresses are anonymized by default: each real address gets the same stand-in for the whole
recording, with shared prefixes kept, under a key that is never stored. A file can be shared
without handing out who played, and players stay apart in it.

A connect event opens a new session with its address; the tool numbers them, so a player who
joins the same server again is not mixed up with the earlier visit.

## The tool

```
netinspector info capture.gcap
netinspector health capture.gcap [--json]
netinspector threats capture.gcap [--json]
netinspector overflow capture.gcap [--list] [--json]
netinspector timeline capture.gcap [--address <#id | ip:port>] [--from <s>] [--to <s>] [--slow-frame <ms>]
netinspector messages capture.gcap [--address <#id | ip:port>] [--message <name>] [--from <s>] [--to <s>] [--dropped]
netinspector <command> --help
```

`health` lists what went wrong with honest traffic, by severity: reliable buffers that
overflowed, reliable data the other end answered around without acknowledging, reliable data
queued at a pace that leaves little room for lag, large batches of it, packets the server held
back for the client's rate, a resource list sent again in one sign-on, frames the recording program hung in, slow
parsing, packets lost on the way, and silences the other end kept although its answers were due.

The reliable data of a server's packet is told from its datagram by the layout the engine
writes: Netchan_Transmit puts the reliable messages first; SV_SendClientDatagram opens the
datagram with svc_time, an optional svc_choke and angle, then svc_clientdata; SV_DropClient's
last packet ends with svc_disconnect. Packets that follow none of these layouts are counted and
reported, not guessed at.

Each new reliable message, its own or sent as fragments, is what the server had queued. Against
the 3990 bytes one reliable message holds it is a batch: a game writes its MOTD or every
player's userinfo in one frame. Over a second it is a pace: 3990 bytes divided by the bytes
queued a second is how late acknowledgements may come before HLDS drops the client. A pace that
keeps that time under a second for a second or more is reported; a shorter stretch is a batch.

A silence is reported when the answers due over it, at the rate the other end answered before,
make missing them all by chance less likely than one in a thousand.

`threats` lists what looks like an attack: floods of commands and connectionless packets,
crafted packets, sign-on commands sent again, repeated resource lists from a client.

`overflow` takes every reliable buffer that overflowed on a server apart: the messages that
filled it, the reliable data still in flight, whether the client had gone silent and its
acknowledgements stopped, and what the server had been sending it.

`--json` writes JSON Lines, one object a line, for programs to read.

`messages` reads every packet the receiving end accepted down to its svc_ and clc_ messages:
deltas, packet entities, client data, events, temp entities, sounds, resources, moves. Where a
message cannot be read, it says which one and why, and goes on with the next packet. User
messages are shown by name and bytes; a game's own dissector (`IUserMessageDissector`) can
turn them into text.

Build it with CMake 3.21 or newer:

```
cmake --preset windows-x64          # or windows-x86, linux-gcc, linux-clang, linux-sanitizers
cmake --build --preset windows-x64
ctest --preset windows-x64
```

`scripts/build.sh` and `scripts/build.ps1` do the same in one step.

## Embedding the recorder

The recorder is compiled into the embedding program with that program's flags and toolchain.
It needs C++14, the standard library and the OS, nothing else. The oldest supported Linux
baseline is glibc 2.11 with libstdc++ 3.4.15 (CXXABI 1.3.5), 32-bit or 64-bit;
`scripts/build_baseline.sh` builds against it and checks the symbol versions.

CMake:

```cmake
include(dep/netinspector/cmake/NetInspector.cmake)
target_sources(engine PRIVATE ${NETINSPECTOR_SOURCES})
target_include_directories(engine PRIVATE ${NETINSPECTOR_INCLUDE_DIRS})
```

msbuild:

```xml
<ImportGroup Label="Shared">
  <Import Project="..\dep\netinspector\msvc\NetInspector.vcxitems" Label="Shared" />
</ImportGroup>
```

Then, where the program owns its socket:

```cpp
#include "netinspector/recorder.h"

NetInspector::CRecorder recorder;

NetInspector::CRecorder::Settings settings;
settings.role = NetInspector::Role::Server;
settings.application = "MyServer 1.0";
settings.protocol = 48;
recorder.Start("captures/session.gcap", settings);

recorder.RecordUserMessages(messages, count);	// and the other session tables, at start and on change
recorder.RecordDatagram(NetInspector::Direction::In, endpoint, data, length);	// on arrival
recorder.RecordFrame(frameNumber);												// once a frame
recorder.Stop();
```

## Format

[docs/format.md](docs/format.md) describes the `.gcap` layout.

## License

MIT, see [LICENSE](LICENSE).
