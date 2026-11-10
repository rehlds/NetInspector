//=============================================================================//
//
// A recording written by CRecorder and read back by CReader
//
//=============================================================================//

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "netinspector/decoder/session_tables.h"
#include "netinspector/reader.h"
#include "netinspector/recorder.h"

namespace NetInspector
{

namespace
{

struct ReadEntry
{
	EntryHeader header;
	std::vector<uint8_t> body;
};

class RecorderTest : public testing::Test
{
protected:
	void SetUp() override
	{
		m_Path = std::string(testing::TempDir()) + "netinspector_" + testing::UnitTest::GetInstance()->current_test_info()->name() + ".gcap";
	}

	void TearDown() override
	{
		std::remove(m_Path.c_str());
	}

	std::vector<ReadEntry> ReadAll(FileHeader &file)
	{
		std::vector<ReadEntry> entries;

		CReader reader;
		EXPECT_TRUE(reader.Open(m_Path.c_str()));
		file = reader.GetHeader();

		EntryHeader header;
		const uint8_t *body = nullptr;
		while (reader.Next(header, body))
			entries.push_back(ReadEntry{ header, std::vector<uint8_t>(body, body + header.length) });

		EXPECT_FALSE(reader.IsTruncated());
		return entries;
	}

	std::string m_Path;
};

// An address set aside for documentation (RFC 5737)
const Endpoint SERVER = { { 198, 51, 100, 177 }, 27015 };

} // namespace

TEST_F(RecorderTest, WritesWhatItWasGiven)
{
	CRecorder::Settings settings;
	settings.application = "tests";
	settings.protocol = 48;

	CRecorder recorder;
	ASSERT_TRUE(recorder.Start(m_Path.c_str(), settings));

	const uint8_t packet[] = { 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01 };
	recorder.RecordDatagram(Direction::In, SERVER, packet, sizeof(packet));
	recorder.RecordDatagram(Direction::Out, SERVER, packet, sizeof(packet));
	recorder.RecordEvent(Event::Signon, nullptr, "command=new");
	recorder.Stop();

	FileHeader file;
	const std::vector<ReadEntry> entries = ReadAll(file);

	EXPECT_EQ(file.role, Role::Client);
	EXPECT_EQ(file.protocol, 48);
	EXPECT_STREQ(file.application, "tests");
	EXPECT_TRUE(HasAny(file.flags, FileFlags::EndpointsAnonymized));

	// started, address, two datagrams, signon, stopped
	ASSERT_EQ(entries.size(), 6u);
	EXPECT_EQ(entries[0].header.type, Entry::Event);
	EXPECT_EQ(entries[1].header.type, Entry::Endpoint);
	EXPECT_EQ(entries[2].header.type, Entry::Datagram);
	EXPECT_EQ(entries[2].header.endpoint, entries[1].header.endpoint);
	EXPECT_EQ(entries[3].header.endpoint, entries[1].header.endpoint);
	EXPECT_EQ(entries[4].header.type, Entry::Event);
	EXPECT_STREQ(reinterpret_cast<const char *>(entries[4].body.data() + sizeof(EventEntry)), "command=new");

	EndpointEntry address;
	std::memcpy(&address, entries[1].body.data(), sizeof(address));
	EXPECT_TRUE(HasAny(address.flags, EndpointFlags::Anonymized));
	EXPECT_EQ(address.port, SERVER.port);
	EXPECT_NE(std::memcmp(address.ip, SERVER.ip, sizeof(address.ip)), 0);

	DatagramEntry datagram;
	std::memcpy(&datagram, entries[3].body.data(), sizeof(datagram));
	EXPECT_EQ(datagram.direction, Direction::Out);
	EXPECT_EQ(datagram.type, Datagram::Channel);
	EXPECT_EQ(entries[3].body.size(), sizeof(DatagramEntry) + sizeof(packet));

	for (size_t i = 1; i < entries.size(); i++)
		EXPECT_GE(entries[i].header.time, entries[i - 1].header.time);
}

TEST_F(RecorderTest, KeepsRealAddressesOnlyWhenAsked)
{
	CRecorder::Settings settings;
	settings.anonymizeAddresses = false;

	CRecorder recorder;
	ASSERT_TRUE(recorder.Start(m_Path.c_str(), settings));
	const uint8_t packet[] = { 0xFF, 0xFF, 0xFF, 0xFF, 'p', 'i', 'n', 'g' };
	recorder.RecordDatagram(Direction::Out, SERVER, packet, sizeof(packet));
	recorder.Stop();

	FileHeader file;
	const std::vector<ReadEntry> entries = ReadAll(file);
	EXPECT_FALSE(HasAny(file.flags, FileFlags::EndpointsAnonymized));

	ASSERT_GE(entries.size(), 2u);
	EndpointEntry address;
	std::memcpy(&address, entries[1].body.data(), sizeof(address));
	EXPECT_EQ(std::memcmp(address.ip, SERVER.ip, sizeof(address.ip)), 0);
}

TEST_F(RecorderTest, LeavesOutIdleFrames)
{
	CRecorder recorder;
	ASSERT_TRUE(recorder.Start(m_Path.c_str(), CRecorder::Settings()));

	// Idle and short: only the first is written
	for (uint64_t frame = 1; frame <= 1000; frame++)
		recorder.RecordFrame(frame);

	// Frame 1000 took a datagram in: the entry that closes it is written
	const uint8_t packet[] = { 0xFF, 0xFF, 0xFF, 0xFF, 'p', 'i', 'n', 'g' };
	recorder.RecordDatagram(Direction::In, SERVER, packet, sizeof(packet));
	recorder.RecordFrame(1001);
	recorder.RecordFrame(1002);

	// Idle but slow: written
	std::this_thread::sleep_for(std::chrono::milliseconds(60));
	recorder.RecordFrame(1003);
	recorder.Stop();

	FileHeader file;
	std::vector<FrameEntry> frames;
	for (const ReadEntry &entry : ReadAll(file))
	{
		if (entry.header.type != Entry::Frame)
			continue;

		FrameEntry frame;
		ASSERT_EQ(entry.body.size(), sizeof(frame));
		std::memcpy(&frame, entry.body.data(), sizeof(frame));
		frames.push_back(frame);
	}

	ASSERT_EQ(frames.size(), 3u);
	EXPECT_EQ(frames[0].frameNumber, 1u);
	EXPECT_EQ(frames[0].durationMicroseconds, 0u);
	EXPECT_EQ(frames[1].frameNumber, 1001u);
	EXPECT_EQ(frames[2].frameNumber, 1003u);
	EXPECT_GE(frames[2].durationMicroseconds, 50000u);
}

TEST_F(RecorderTest, WritesSessionTablesTheDecoderReads)
{
	CRecorder recorder;
	ASSERT_TRUE(recorder.Start(m_Path.c_str(), CRecorder::Settings()));

	recorder.RecordServerInfo(32, 3, "de_dust2", "cstrike");

	const CRecorder::UserMessage messages[] = { { 64, -1, "SayText" }, { 65, 1, "ResetHUD" } };
	recorder.RecordUserMessages(messages, 2);

	const CRecorder::DeltaField fields[] = { { "origin[0]", 4 | 0x80000000u, 21, 8.0f, 1.0f }, { "modelindex", 8, 10, 1.0f, 1.0f } };
	recorder.RecordDeltaDescription("entity_state_t", fields, 2);

	const CRecorder::PrecacheItem sounds[] = { { 1, "weapons/ak47-1.wav" }, { 7, "player/pl_step1.wav" } };
	recorder.RecordPrecache(PrecacheKind::Sound, sounds, 2);

	const uint8_t queued[] = { 8, 'h', 'i', 0 };
	const uint8_t inFlight[] = { 1, 1 };
	OverflowCaptureEntry state = {};
	state.bufferBytes = 4000;
	state.requestedBytes = 120;
	state.queuedBytes = sizeof(queued);
	state.reliableInFlightBytes = sizeof(inFlight);
	recorder.RecordOverflow(SERVER, state, queued, inFlight);
	recorder.Stop();

	FileHeader file;
	CSessionTables tables;
	size_t overflows = 0;
	for (const ReadEntry &entry : ReadAll(file))
	{
		if (entry.header.type == Entry::OverflowCapture)
		{
			overflows++;
			EXPECT_TRUE(entry.header.endpoint.IsValid());
			ASSERT_EQ(entry.body.size(), sizeof(state) + sizeof(queued) + sizeof(inFlight));
			EXPECT_EQ(entry.body[sizeof(state) + sizeof(queued)], 1);
		}
		else if (entry.header.type != Entry::Event && entry.header.type != Entry::Endpoint)
		{
			EXPECT_TRUE(tables.Apply(entry.header, entry.body.data())) << ToString(entry.header.type);
		}
	}

	EXPECT_EQ(overflows, 1u);
	EXPECT_EQ(tables.GetMaxClients(), 32);
	EXPECT_EQ(tables.GetInstancedBaselines(), 3);
	EXPECT_EQ(tables.GetMap(), "de_dust2");
	EXPECT_EQ(tables.GetGameDirectory(), "cstrike");

	ASSERT_NE(tables.FindUserMessage(64), nullptr);
	EXPECT_EQ(tables.FindUserMessage(64)->size, -1);
	EXPECT_EQ(tables.FindUserMessage(65)->name, "ResetHUD");

	const DeltaDescription *entity = tables.FindDeltaDescription("entity_state_t");
	ASSERT_NE(entity, nullptr);
	ASSERT_EQ(entity->fields.size(), 2u);
	EXPECT_STREQ(entity->fields[0].name, "origin[0]");
	EXPECT_EQ(entity->fields[0].bits, 21);
	EXPECT_EQ(entity->fields[0].preMultiplier, 8.0f);

	EXPECT_STREQ(tables.FindPrecache(PrecacheKind::Sound, 7), "player/pl_step1.wav");
	EXPECT_EQ(tables.FindPrecache(PrecacheKind::Sound, 2), nullptr);
	EXPECT_EQ(tables.FindPrecache(PrecacheKind::Model, 1), nullptr);
}

TEST_F(RecorderTest, RefusesASecondStart)
{
	CRecorder recorder;
	ASSERT_TRUE(recorder.Start(m_Path.c_str(), CRecorder::Settings()));
	EXPECT_FALSE(recorder.Start(m_Path.c_str(), CRecorder::Settings()));
	recorder.Stop();
	EXPECT_FALSE(recorder.IsRecording());
}

TEST(Reader, RefusesAFileThatIsNotACapture)
{
	const std::string path = std::string(testing::TempDir()) + "netinspector_not_a_capture.gcap";

	std::FILE *file = std::fopen(path.c_str(), "wb");
	ASSERT_NE(file, nullptr);
	std::fputs("this is a text file, not a capture, at least 96 bytes long so the header read succeeds......", file);
	std::fclose(file);

	CReader reader;
	EXPECT_FALSE(reader.Open(path.c_str()));
	std::remove(path.c_str());
}

} // namespace NetInspector
