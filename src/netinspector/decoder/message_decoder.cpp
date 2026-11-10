//=============================================================================//
//
// svc_ and clc_ messages
//
//=============================================================================//

#include "netinspector/decoder/message_decoder.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "netinspector/common/byte_order.h"
#include "netinspector/decoder/protocol.h"

namespace NetInspector
{

namespace
{

#define STRINGIFY(name) #name

constexpr int CLIENT_MESSAGE_COUNT = 12;

constexpr int MAX_EDICT_BITS             = 11;
constexpr int MAX_BASELINE_BITS          = 6;
constexpr int DELTA_OFFSET_BITS          = 6;
constexpr int DELTAFRAME_NUMBITS         = 8;

constexpr int MAX_WEAPON_BITS            = 6;
constexpr int MAX_WEAPONS                = 64;

constexpr int MAX_NUMEVENTS_BITS         = 5;
constexpr int MAX_EVENT_BITS             = 10;
constexpr int MAX_SOUND_INDEX_BITS       = 9;
constexpr int MAX_RESOURCE_INDEX_BITS    = 12;
constexpr int MAX_CONSISTENCY_INDEX_BITS = 10;
constexpr int MAX_USER_MESSAGE_NAME      = 16;

constexpr size_t MD5_SIZE                = 16;
constexpr size_t CONSISTENCY_INFO_SIZE   = 32;
constexpr size_t PREVIEW_CHARACTERS      = 160;
constexpr size_t PREVIEW_BYTES           = 32;

constexpr uint32_t ENTITY_BEAM           = 2;
constexpr uint32_t BASELINE_END          = 0xFFFF;
constexpr uint8_t  RES_CUSTOM            = 1 << 2;

enum SoundFlags
{
	SND_VOLUME		= 1 << 0,
	SND_ATTENUATION	= 1 << 1,
	SND_LARGE_INDEX	= 1 << 2,
	SND_PITCH		= 1 << 3,
	SND_SENTENCE	= 1 << 4,
	SND_STOP		= 1 << 5,
};

const char *const SERVER_MESSAGES[] =
{
	STRINGIFY(svc_bad),
	STRINGIFY(svc_nop),
	STRINGIFY(svc_disconnect),
	STRINGIFY(svc_event),
	STRINGIFY(svc_version),
	STRINGIFY(svc_setview),
	STRINGIFY(svc_sound),
	STRINGIFY(svc_time),
	STRINGIFY(svc_print),
	STRINGIFY(svc_stufftext),
	STRINGIFY(svc_setangle),
	STRINGIFY(svc_serverinfo),
	STRINGIFY(svc_lightstyle),
	STRINGIFY(svc_updateuserinfo),
	STRINGIFY(svc_deltadescription),
	STRINGIFY(svc_clientdata),
	STRINGIFY(svc_stopsound),
	STRINGIFY(svc_pings),
	STRINGIFY(svc_particle),
	STRINGIFY(svc_damage),
	STRINGIFY(svc_spawnstatic),
	STRINGIFY(svc_event_reliable),
	STRINGIFY(svc_spawnbaseline),
	STRINGIFY(svc_temp_entity),
	STRINGIFY(svc_setpause),
	STRINGIFY(svc_signonnum),
	STRINGIFY(svc_centerprint),
	STRINGIFY(svc_killedmonster),
	STRINGIFY(svc_foundsecret),
	STRINGIFY(svc_spawnstaticsound),
	STRINGIFY(svc_intermission),
	STRINGIFY(svc_finale),
	STRINGIFY(svc_cdtrack),
	STRINGIFY(svc_restore),
	STRINGIFY(svc_cutscene),
	STRINGIFY(svc_weaponanim),
	STRINGIFY(svc_decalname),
	STRINGIFY(svc_roomtype),
	STRINGIFY(svc_addangle),
	STRINGIFY(svc_newusermsg),
	STRINGIFY(svc_packetentities),
	STRINGIFY(svc_deltapacketentities),
	STRINGIFY(svc_choke),
	STRINGIFY(svc_resourcelist),
	STRINGIFY(svc_newmovevars),
	STRINGIFY(svc_resourcerequest),
	STRINGIFY(svc_customization),
	STRINGIFY(svc_crosshairangle),
	STRINGIFY(svc_soundfade),
	STRINGIFY(svc_filetxferfailed),
	STRINGIFY(svc_hltv),
	STRINGIFY(svc_director),
	STRINGIFY(svc_voiceinit),
	STRINGIFY(svc_voicedata),
	STRINGIFY(svc_sendextrainfo),
	STRINGIFY(svc_timescale),
	STRINGIFY(svc_resourcelocation),
	STRINGIFY(svc_sendcvarvalue),
	STRINGIFY(svc_sendcvarvalue2),
	STRINGIFY(svc_exec),
	STRINGIFY(svc_netmessage),
	STRINGIFY(svc_usermessage),
	STRINGIFY(svc_reserve62),
	STRINGIFY(svc_reserve63),
};

const char *const CLIENT_MESSAGES[] =
{
	STRINGIFY(clc_bad),
	STRINGIFY(clc_nop),
	STRINGIFY(clc_move),
	STRINGIFY(clc_stringcmd),
	STRINGIFY(clc_delta),
	STRINGIFY(clc_resourcelist),
	STRINGIFY(clc_tmove),
	STRINGIFY(clc_fileconsistency),
	STRINGIFY(clc_voicedata),
	STRINGIFY(clc_hltv),
	STRINGIFY(clc_cvarvalue),
	STRINGIFY(clc_cvarvalue2),
	STRINGIFY(clc_netmessage),
	STRINGIFY(clc_usermessage),
};

// The bytes after the type of a temp entity; the two whose length depends on their content are read apart
struct TempEntityLayout
{
	uint8_t		type;
	const char	*name;
	int			size;
	bool		startsAtPosition;	// the first three coords are where it happens
};

constexpr int TE_BSPDECAL      = 13;
constexpr int TE_TEXTMESSAGE   = 29;
constexpr size_t POSITION_SIZE = 6;

const TempEntityLayout TEMP_ENTITIES[] =
{
	{ 0, "TE_BEAMPOINTS", 24, true },			{ 1, "TE_BEAMENTPOINT", 20, false },		{ 2, "TE_GUNSHOT", 6, true },
	{ 3, "TE_EXPLOSION", 11, true },			{ 4, "TE_TAREXPLOSION", 6, true },			{ 5, "TE_SMOKE", 10, true },
	{ 6, "TE_TRACER", 12, true },				{ 7, "TE_LIGHTNING", 17, true },			{ 8, "TE_BEAMENTS", 16, false },
	{ 9, "TE_SPARKS", 6, true },				{ 10, "TE_LAVASPLASH", 6, true },			{ 11, "TE_TELEPORT", 6, true },
	{ 12, "TE_EXPLOSION2", 8, true },			{ 13, "TE_BSPDECAL", -1, true },			{ 14, "TE_IMPLOSION", 9, true },
	{ 15, "TE_SPRITETRAIL", 19, true },			{ 17, "TE_SPRITE", 10, true },				{ 18, "TE_BEAMSPRITE", 16, true },
	{ 19, "TE_BEAMTORUS", 24, true },			{ 20, "TE_BEAMDISK", 24, true },			{ 21, "TE_BEAMCYLINDER", 24, true },
	{ 22, "TE_BEAMFOLLOW", 10, false },			{ 23, "TE_GLOWSPRITE", 11, true },			{ 24, "TE_BEAMRING", 16, false },
	{ 25, "TE_STREAK_SPLASH", 19, true },		{ 27, "TE_DLIGHT", 12, true },				{ 28, "TE_ELIGHT", 16, false },
	{ 29, "TE_TEXTMESSAGE", -1, false },		{ 30, "TE_LINE", 17, true },				{ 31, "TE_BOX", 17, true },
	{ 99, "TE_KILLBEAM", 2, false },			{ 100, "TE_LARGEFUNNEL", 10, true },		{ 101, "TE_BLOODSTREAM", 14, true },
	{ 102, "TE_SHOWLINE", 12, true },			{ 103, "TE_BLOOD", 14, true },				{ 104, "TE_DECAL", 9, true },
	{ 105, "TE_FIZZ", 5, false },				{ 106, "TE_MODEL", 17, true },				{ 107, "TE_EXPLODEMODEL", 13, true },
	{ 108, "TE_BREAKMODEL", 24, true },			{ 109, "TE_GUNSHOTDECAL", 9, true },		{ 110, "TE_SPRITE_SPRAY", 17, true },
	{ 111, "TE_ARMOR_RICOCHET", 7, true },		{ 112, "TE_PLAYERDECAL", 10, false },		{ 113, "TE_BUBBLES", 19, true },
	{ 114, "TE_BUBBLETRAIL", 19, true },		{ 115, "TE_BLOODSPRITE", 12, true },		{ 116, "TE_WORLDDECAL", 7, true },
	{ 117, "TE_WORLDDECALHIGH", 7, true },		{ 118, "TE_DECALHIGH", 9, true },			{ 119, "TE_PROJECTILE", 16, true },
	{ 120, "TE_SPRAY", 18, true },				{ 121, "TE_PLAYERSPRITES", 6, false },		{ 122, "TE_PARTICLEBURST", 10, true },
	{ 123, "TE_FIREFIELD", 13, true },			{ 124, "TE_PLAYERATTACHMENT", 7, false },	{ 125, "TE_KILLPLAYERATTACHMENTS", 1, false },
	{ 126, "TE_MULTIGUNSHOT", 18, true },		{ 127, "TE_USERTRACER", 15, true },
};

const TempEntityLayout *FindTempEntity(int type)
{
	for (const TempEntityLayout &layout : TEMP_ENTITIES)
	{
		if (layout.type == type)
			return &layout;
	}

	return nullptr;
}

const unsigned char MOVE_MUNGE_TABLE[16] =
{
	0x7A, 0x64, 0x05, 0xF1, 0x1B, 0x9B, 0xA0, 0xB5,
	0xCA, 0xED, 0x61, 0x0D, 0x4A, 0xDF, 0x8E, 0xC7,
};

// COM_UnMunge, which hides the commands of clc_move under the packet's sequence
void UnmungeMove(uint8_t *data, size_t length, uint32_t sequence)
{
	const uint32_t key = sequence;
	for (size_t word = 0; word < length / 4; word++)
	{
		uint8_t *bytes = data + word * 4;
		uint32_t value = ReadUInt32LE(bytes) ^ key;

		for (uint32_t j = 0; j < 4; j++)
		{
			const uint32_t mask = 0xA5u | (j << j) | j | MOVE_MUNGE_TABLE[(word + j) & 0x0F];
			value ^= (mask & 0xFF) << (j * 8);
		}

		WriteUInt32LE(bytes, ByteSwap32(value) ^ ~key);
	}
}

std::string Format(const char *format, ...)
{
	char text[512];
	va_list arguments;
	va_start(arguments, format);
	std::vsnprintf(text, sizeof(text), format, arguments);
	va_end(arguments);
	return text;
}

// Text as a quoted line: control characters escaped, long text cut
std::string Quote(const std::string &text)
{
	std::string quoted = "\"";
	for (size_t i = 0; i < text.size() && i < PREVIEW_CHARACTERS; i++)
	{
		const unsigned char c = static_cast<unsigned char>(text[i]);
		if (c == '\n')
			quoted += "\\n";
		else if (c == '"')
			quoted += "\\\"";
		else if (c < 32)
			quoted += Format("\\x%02X", c);
		else
			quoted += char(c);
	}

	quoted += text.size() > PREVIEW_CHARACTERS ? "\"..." : "\"";
	return quoted;
}

std::string Hex(const uint8_t *data, size_t length)
{
	std::string text;
	std::string characters;
	for (size_t i = 0; i < length && i < PREVIEW_BYTES; i++)
	{
		text += Format(i ? " %02X" : "%02X", data[i]);
		characters += (data[i] >= 32 && data[i] < 127) ? (char)data[i] : '.';
	}

	if (length > PREVIEW_BYTES)
		text += " ...";
	return text + "  |" + characters + "|";
}

std::string BaseName(const std::string &path)
{
	const size_t slash = path.find_last_of("/\\");
	std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
	const size_t dot = name.rfind('.');
	return dot == std::string::npos ? name : name.substr(0, dot);
}

bool IsPlayer(int entity, int maxClients)
{
	return entity >= 1 && entity <= maxClients;
}

} // namespace

const char *CMessageDecoder::GetServerMessageName(int id)
{
	return id >= 0 && id < svc_startofusermessages ? SERVER_MESSAGES[id] : "user message";
}

const char *CMessageDecoder::GetClientMessageName(int id)
{
	return id >= 0 && id < clc_max ? CLIENT_MESSAGES[id] : "unknown";
}

void CMessageDecoder::Decode(MessageSource source, const uint8_t *data, size_t length, uint32_t sequence, DecodedStream &stream)
{
	stream = DecodedStream();
	CBitReader reader(data, length);

	while (reader.GetBytesLeft() > 0)
	{
		const size_t offset = reader.GetBytePosition();
		const int id = reader.ReadByte();

		DecodedMessage message = { id, std::string(), offset, 0, std::string() };
		std::string error;
		bool decoded;

		if (source == MessageSource::Server)
		{
			message.name = GetServerMessageName(id);
			decoded = id >= svc_startofusermessages ? DecodeUserMessage(id, reader, message.name, message.text, error)
				: DecodeServerMessage(id, reader, message.text, error);
		}
		else
		{
			message.name = GetClientMessageName(id);
			decoded = DecodeClientMessage(id, reader, sequence, message.text, error);
		}

		if (decoded && reader.IsOverflowed())
		{
			decoded = false;
			error = "the message runs past the end of the stream";
		}

		message.length = reader.GetBytePosition() - offset;
		if (!decoded)
		{
			stream.error = message.name + ": " + error;
			stream.stoppedAt = offset;
			return;
		}

		stream.messages.push_back(message);
	}

	stream.complete = true;
}

const DeltaDescription *CMessageDecoder::RequireDescription(const char *name, std::string &error) const
{
	const DeltaDescription *description = m_Tables.FindDeltaDescription(name);
	if (!description)
		error = std::string("no delta description ") + name + " in the recording";
	return description;
}

bool CMessageDecoder::ReadDeltaOf(CBitReader &reader, const char *description, std::string &text, std::string &error)
{
	const DeltaDescription *fields = RequireDescription(description, error);
	if (!fields)
		return false;

	if (!ReadDelta(reader, *fields, m_Values))
	{
		error = std::string("broken ") + description + " delta";
		return false;
	}

	text = FormatDelta(m_Values);
	return true;
}

std::string CMessageDecoder::PrecacheName(PrecacheKind kind, int index) const
{
	const char *name = m_Tables.FindPrecache(kind, index);
	return name ? std::string(name) : Format("#%d", index);
}

bool CMessageDecoder::DecodeServerMessage(int id, CBitReader &reader, std::string &text, std::string &error)
{
	switch (id)
	{
	case svc_nop:
	case svc_damage:
	case svc_spawnstatic:	// read as nothing
	case svc_killedmonster:
	case svc_foundsecret:
	case svc_intermission:
	case svc_choke:
		return true;

	case svc_disconnect:
	case svc_print:
	case svc_stufftext:
	case svc_centerprint:
	case svc_finale:
	case svc_cutscene:
	case svc_filetxferfailed:
	case svc_resourcelocation:
	case svc_sendcvarvalue:
		text = Quote(reader.ReadString());
		return true;

	case svc_event:     return DecodeEvents(reader, false, text, error);
	case svc_version:   text = Format("protocol %d", reader.ReadLong()); return true;
	case svc_setview:   text = Format("entity %d", reader.ReadShort()); return true;
	case svc_sound:     return DecodeSound(reader, text);
	case svc_time:      text = Format("%.3f", reader.ReadFloat()); return true;

	case svc_setangle:
	{
		const float pitch = reader.ReadHiresAngle();
		const float yaw = reader.ReadHiresAngle();
		const float roll = reader.ReadHiresAngle();
		text = Format("%.2f %.2f %.2f", pitch, yaw, roll);
		return true;
	}

	case svc_serverinfo:  return DecodeServerInfo(reader, text);

	case svc_lightstyle:
	{
		const int style = reader.ReadByte();
		text = Format("%d ", style) + Quote(reader.ReadString());
		return true;
	}

	case svc_updateuserinfo:
	{
		const int slot = reader.ReadByte();
		const int userid = reader.ReadLong();
		const std::string userinfo = reader.ReadString();
		reader.SkipBytes(MD5_SIZE);
		text = Format("slot %d userid %d ", slot, userid) + Quote(userinfo);
		return true;
	}

	case svc_deltadescription:  return DecodeDeltaDescription(reader, text, error);
	case svc_clientdata:        return DecodeClientData(reader, text, error);
	case svc_stopsound:
	{
		const int sound = reader.ReadShort();
		text = Format("entity %d channel %d", sound >> 3, sound & 7);
		return true;
	}

	case svc_pings:
	{
		int players = 0;
		reader.StartBitReading();
		while (reader.ReadOneBit() && !reader.IsOverflowed())
		{
			reader.ReadBits(5);
			reader.ReadBits(12);
			reader.ReadBits(7);
			players++;
		}
		reader.EndBitReading();
		text = Format("%d players", players);
		return true;
	}

	case svc_particle:         reader.SkipBytes(11); return true;	// origin, direction, count, color
	case svc_event_reliable:   return DecodeEvents(reader, true, text, error);
	case svc_spawnbaseline:    return DecodeBaseline(reader, text, error);
	case svc_temp_entity:      return DecodeTempEntity(reader, text, error);
	case svc_setpause:         text = reader.ReadByte() ? "paused" : "running"; return true;
	case svc_signonnum:        text = Format("%d", reader.ReadByte()); return true;
	case svc_spawnstaticsound: reader.SkipBytes(14); return true;
	case svc_cdtrack:          reader.SkipBytes(2); return true;

	case svc_restore:
	{
		text = Quote(reader.ReadString());
		const int maps = reader.ReadByte();
		for (int i = 0; i < maps && !reader.IsOverflowed(); i++)
			reader.ReadString();
		return true;
	}

	case svc_weaponanim:
	{
		const int sequence = reader.ReadByte();
		const int body = reader.ReadByte();
		text = Format("sequence %d body %d", sequence, body);
		return true;
	}

	case svc_decalname:
	{
		const int index = reader.ReadByte();
		text = Format("%d ", index) + Quote(reader.ReadString());
		return true;
	}

	case svc_roomtype: text = Format("%d", reader.ReadShort()); return true;
	case svc_addangle: text = Format("%.2f", reader.ReadHiresAngle()); return true;

	case svc_newusermsg:
	{
		const int messageId = reader.ReadByte();
		const int size = reader.ReadByte();
		char name[MAX_USER_MESSAGE_NAME + 1] = {};
		reader.ReadBytes(reinterpret_cast<uint8_t *>(name), MAX_USER_MESSAGE_NAME);

		m_Tables.SetUserMessage(messageId, size == 255 ? -1 : size, name);
		text = Format("%d %s, ", messageId, name) + (size == 255 ? std::string("sized by itself") : Format("%d bytes", size));
		return true;
	}

	case svc_packetentities:      return DecodePacketEntities(reader, false, text, error);
	case svc_deltapacketentities: return DecodePacketEntities(reader, true, text, error);
	case svc_resourcelist:        return DecodeResourceList(reader, text);

	case svc_newmovevars:	// 16 floats, footsteps, 8 floats, sky name
		reader.SkipBytes(16 * 4 + 1 + 8 * 4);
		text = "sky " + Quote(reader.ReadString());
		return true;

	case svc_resourcerequest:
	{
		const int spawnCount = reader.ReadLong();
		const int start = reader.ReadLong();
		text = Format("spawn %d from %d", spawnCount, start);
		return true;
	}

	case svc_customization:
	{
		const int player = reader.ReadByte();
		const int type = reader.ReadByte();
		const std::string name = reader.ReadString();
		reader.ReadShort();
		const int size = reader.ReadLong();
		const uint8_t flags = reader.ReadByte();
		if (flags & RES_CUSTOM)
			reader.SkipBytes(MD5_SIZE);
		text = Format("player %d type %d %d bytes ", player, type, size) + Quote(name);
		return true;
	}

	case svc_crosshairangle: reader.SkipBytes(2); return true;
	case svc_soundfade:      reader.SkipBytes(4); return true;

	case svc_hltv:
	{
		const int command = reader.ReadByte();
		if (command == 1)
			reader.SkipBytes(18);
		else if (command == 2)
			text = "listen " + Quote(reader.ReadString());
		return true;
	}

	case svc_director:
	{
		const int length = reader.ReadByte();
		const int command = length > 0 && reader.GetBytesLeft() > 0 ? reader.GetData()[reader.GetBytePosition()] : 0;
		reader.SkipBytes(size_t(length));
		text = Format("command %d, %d bytes", command, length);
		return true;
	}

	case svc_voiceinit:
	{
		const std::string codec = reader.ReadString();
		text = Quote(codec) + Format(" quality %d", reader.ReadByte());
		return true;
	}

	case svc_voicedata:
	{
		const int player = reader.ReadByte();
		const int length = reader.ReadShort();
		reader.SkipBytes(size_t(length > 0 ? length : 0));
		text = Format("player %d, %d bytes", player, length);
		return true;
	}

	case svc_sendextrainfo:
	{
		const std::string directory = reader.ReadString();
		text = Quote(directory) + Format(" cheats %d", reader.ReadByte());
		return true;
	}

	case svc_timescale: text = Format("%.3f", reader.ReadFloat()); return true;

	case svc_sendcvarvalue2:
	{
		const int request = reader.ReadLong();
		text = Format("request %d ", request) + Quote(reader.ReadString());
		return true;
	}

	case svc_exec: reader.SkipBytes(2); return true;	// type and the class

	case svc_netmessage: // a subtype and a sized payload
	{
		const uint32_t subtype = reader.ReadVarInt32();
		const uint32_t length = reader.ReadVarInt32();
		reader.SkipBytes(length);
		text = Format("subtype %u, %u bytes", subtype, length);
		return true;
	}

	case svc_usermessage: // a user message by name
	{
		const std::string name = reader.ReadString();
		const uint32_t size = reader.ReadVarInt32();
		if (reader.IsOverflowed() || size > reader.GetBytesLeft())
		{
			error = "the body runs past the end of the stream";
			return false;
		}

		text = DescribeUserMessage(name, reader.GetData() + reader.GetBytePosition(), size);
		reader.SkipBytes(size);
		return true;
	}

	default:
		error = id == svc_bad ? "the stream holds svc_bad" : "the layout of this message is not known";
		return false;
	}
}

bool CMessageDecoder::DecodeSound(CBitReader &reader, std::string &text)
{
	reader.StartBitReading();

	const uint32_t flags = reader.ReadBits(9);
	const int volume = (flags & SND_VOLUME) ? (int)reader.ReadBits(8) : 255;
	const double attenuation = (flags & SND_ATTENUATION) ? reader.ReadBits(8) / 64.0 : 0.8;
	const int channel = (int)reader.ReadBits(3);
	const int entity = (int)reader.ReadBits(MAX_EDICT_BITS);
	const int sound = (int)reader.ReadBits((flags & SND_LARGE_INDEX) ? (MAX_SOUND_INDEX_BITS - 1) * 2 : MAX_SOUND_INDEX_BITS - 1);

	float origin[3];
	reader.ReadBitVec3Coord(origin);
	const int pitch = (flags & SND_PITCH) ? (int)reader.ReadBits(8) : 100u;

	reader.EndBitReading();

	const std::string name = (flags & SND_SENTENCE) ? Format("sentence %d", sound) : PrecacheName(PrecacheKind::Sound, sound);
	text = Format("%s%s entity %d channel %d volume %d attenuation %.2f pitch %d at %.0f %.0f %.0f", (flags & SND_STOP) ? "stop " : "",
		name.c_str(), entity, channel, volume, attenuation, pitch, origin[0], origin[1], origin[2]);
	return true;
}

bool CMessageDecoder::DecodeServerInfo(CBitReader &reader, std::string &text)
{
	const int protocol = reader.ReadLong();
	const int spawnCount = reader.ReadLong();
	reader.ReadLong();
	reader.SkipBytes(MD5_SIZE);
	const int maxClients = reader.ReadByte();
	const int playerNumber = reader.ReadByte();
	reader.ReadByte();
	const std::string gameDirectory = reader.ReadString();
	const std::string hostName = reader.ReadString();
	const std::string map = reader.ReadString();
	reader.ReadString();
	reader.ReadByte();

	if (!reader.IsOverflowed())
		m_Tables.SetServerInfo(maxClients, BaseName(map), gameDirectory);

	text = Format("protocol %d spawn %d, %s, %s, player %d of %d, ", protocol, spawnCount, map.c_str(), gameDirectory.c_str(), playerNumber, maxClients) + Quote(hostName);
	return true;
}

bool CMessageDecoder::DecodeDeltaDescription(CBitReader &reader, std::string &text, std::string &error)
{
	DeltaDescription description;
	description.name = reader.ReadString();

	reader.StartBitReading();
	const uint32_t count = reader.ReadBits(16);
	for (uint32_t i = 0; i < count && !reader.IsOverflowed(); i++)
	{
		if (!ReadDelta(reader, GetMetaDescription(), m_Values))
		{
			error = "broken field description";
			return false;
		}

		description.fields.push_back(ToFieldRecord(m_Values));
	}
	reader.EndBitReading();

	if (reader.IsOverflowed())
		return true;

	m_Tables.SetDeltaDescription(description);
	text = Format("%s, %u fields", description.name.c_str(), count);
	return true;
}

bool CMessageDecoder::DecodeClientData(CBitReader &reader, std::string &text, std::string &error)
{
	reader.StartBitReading();

	const bool delta = reader.ReadOneBit();
	const int from = delta ? (int)reader.ReadBits(DELTAFRAME_NUMBITS) : -1;

	std::string fields;
	if (!ReadDeltaOf(reader, "clientdata_t", fields, error))
		return false;

	std::string weapons;
	for (int i = 0; i < MAX_WEAPONS && reader.ReadOneBit() && !reader.IsOverflowed(); i++)
	{
		const int weapon = (int)reader.ReadBits(MAX_WEAPON_BITS);
		std::string weaponFields;
		if (!ReadDeltaOf(reader, "weapon_data_t", weaponFields, error))
			return false;

		weapons += Format(" weapon %d {", weapon) + weaponFields + "}";
	}

	reader.EndBitReading();

	text = (delta ? Format("from %d: ", from) : std::string("full: ")) + fields + weapons;
	return true;
}

bool CMessageDecoder::DecodeEvents(CBitReader &reader, bool reliable, std::string &text, std::string &error)
{
	reader.StartBitReading();

	const uint32_t count = reliable ? 1 : reader.ReadBits(MAX_NUMEVENTS_BITS);
	for (uint32_t i = 0; i < count && !reader.IsOverflowed(); i++)
	{
		const int index = (int)reader.ReadBits(MAX_EVENT_BITS);
		std::string line = PrecacheName(PrecacheKind::Event, index);

		if (!reliable && reader.ReadOneBit())
			line += Format(" packet entity %u", reader.ReadBits(MAX_EDICT_BITS));

		std::string arguments;
		if (reliable || reader.ReadOneBit())
		{
			if (!ReadDeltaOf(reader, "event_t", arguments, error))
				return false;
			line += " {" + arguments + "}";
		}

		if (reader.ReadOneBit())
			line += Format(" delay %.2f", reader.ReadBits(16) / 100.0);

		text += (text.empty() ? "" : "; ") + line;
	}

	reader.EndBitReading();
	return true;
}

bool CMessageDecoder::DecodeBaseline(CBitReader &reader, std::string &text, std::string &error)
{
	const int maxClients = m_Tables.GetMaxClients();
	if (maxClients == 0)
	{
		error = "the number of players is not known: no server info in the recording";
		return false;
	}

	reader.StartBitReading();

	int entities = 0;
	std::string fields;
	while (reader.PeekBits(16) != BASELINE_END && !reader.IsOverflowed())
	{
		const int entity = (int)reader.ReadBits(MAX_EDICT_BITS);
		const uint32_t type = reader.ReadBits(2);
		const char *description = type == ENTITY_BEAM ? "custom_entity_state_t" : IsPlayer(entity, maxClients) ? "entity_state_player_t" : "entity_state_t";
		if (!ReadDeltaOf(reader, description, fields, error))
			return false;
		entities++;
	}

	reader.ReadBits(16);

	const int instanced = (int)reader.ReadBits(MAX_BASELINE_BITS);
	for (int i = 0; i < instanced && !reader.IsOverflowed(); i++)
	{
		if (!ReadDeltaOf(reader, "entity_state_t", fields, error))
			return false;
	}

	reader.EndBitReading();

	m_Tables.SetInstancedBaselines(instanced);
	text = Format("%d entities, %d instanced", entities, instanced);
	return true;
}

bool CMessageDecoder::DecodePacketEntities(CBitReader &reader, bool delta, std::string &text, std::string &error)
{
	const int maxClients = m_Tables.GetMaxClients();
	if (maxClients == 0)
	{
		error = "the number of players is not known: no server info in the recording";
		return false;
	}

	const int count = reader.ReadShort();
	const int from = delta ? reader.ReadByte() : -1;
	const bool instanced = m_Tables.GetInstancedBaselines() > 0;

	reader.StartBitReading();

	int number = 0;
	int changed = 0;
	int removed = 0;
	std::string fields;

	while (!reader.IsOverflowed())
	{
		if (reader.PeekBits(16) == 0)
		{
			reader.ReadBits(16);
			break;
		}

		bool remove = false;
		bool next = false;
		if (delta)
			remove = reader.ReadOneBit();
		else
			next = reader.ReadOneBit();

		if (next)
			number++;
		else if (reader.ReadOneBit())
			number = (int)reader.ReadBits(MAX_EDICT_BITS);
		else
			number += (int)reader.ReadBits(DELTA_OFFSET_BITS);

		if (remove)
		{
			removed++;
			continue;
		}

		const bool custom = reader.ReadOneBit();
		bool newBaseline = false;
		if (instanced)
		{
			newBaseline = reader.ReadOneBit();
			if (newBaseline)
				reader.ReadBits(MAX_BASELINE_BITS);
		}

		if (!delta && !newBaseline && reader.ReadOneBit())
			reader.ReadBits(MAX_BASELINE_BITS);

		const char *description = custom ? "custom_entity_state_t" : IsPlayer(number, maxClients) ? "entity_state_player_t" : "entity_state_t";
		if (!ReadDeltaOf(reader, description, fields, error))
			return false;
		changed++;
	}

	reader.EndBitReading();

	text = delta ? Format("%d entities, from %d: %d changed, %d removed", count, from, changed, removed)
		: Format("%d entities, full", count);
	return true;
}

bool CMessageDecoder::DecodeTempEntity(CBitReader &reader, std::string &text, std::string &error)
{
	const int type = reader.ReadByte();
	const TempEntityLayout *layout = FindTempEntity(type);
	if (!layout)
	{
		error = Format("temp entity %d has no known layout", type);
		return false;
	}

	text = layout->name;

	if (layout->startsAtPosition && reader.GetBytesLeft() >= POSITION_SIZE)
	{
		const uint8_t *position = reader.GetData() + reader.GetBytePosition();
		text += Format(" at %.0f %.0f %.0f", int16_t(ReadUInt16LE(position)) / 8.0, int16_t(ReadUInt16LE(position + 2)) / 8.0, int16_t(ReadUInt16LE(position + 4)) / 8.0);
	}

	if (type == TE_BSPDECAL)
	{
		reader.SkipBytes(POSITION_SIZE + 2);
		if (reader.ReadShort() != 0)
			reader.SkipBytes(2);
		return true;
	}

	if (type == TE_TEXTMESSAGE)
	{
		const int channel = reader.ReadByte();
		reader.SkipBytes(4);
		const int effect = reader.ReadByte();
		reader.SkipBytes(8 + 6 + (effect == 2 ? 2 : 0));
		text += Format(" channel %d ", channel) + Quote(reader.ReadString());
		return true;
	}

	reader.SkipBytes(size_t(layout->size));
	return true;
}

bool CMessageDecoder::DecodeResourceList(CBitReader &reader, std::string &text)
{
	enum resourcetype_t
	{
		t_sound = 0,
		t_skin,
		t_model,
		t_decal,
		t_generic,
		t_eventscript,
		t_world,
		rt_max
	};

	reader.StartBitReading();

	const uint32_t total = reader.ReadBits(MAX_RESOURCE_INDEX_BITS);
	for (uint32_t i = 0; i < total && !reader.IsOverflowed(); i++)
	{
		const uint32_t type = reader.ReadBits(4);
		const std::string name = reader.ReadBitString();
		const int index = (int)reader.ReadBits(MAX_RESOURCE_INDEX_BITS);
		reader.ReadBits(24);
		const uint32_t flags = reader.ReadBits(3);

		uint8_t skipped[CONSISTENCY_INFO_SIZE];
		if (flags & RES_CUSTOM)
			reader.ReadBitData(skipped, MD5_SIZE);
		if (reader.ReadOneBit())
			reader.ReadBitData(skipped, CONSISTENCY_INFO_SIZE);

		if (type == t_sound)
			m_Tables.SetPrecache(PrecacheKind::Sound, index, name);
		else if (type == t_model)
			m_Tables.SetPrecache(PrecacheKind::Model, index, name);
		else if (type == t_generic)
			m_Tables.SetPrecache(PrecacheKind::Generic, index, name);
		else if (type == t_eventscript)
			m_Tables.SetPrecache(PrecacheKind::Event, index, name);
	}

	int consistency = 0;
	if (reader.ReadOneBit())
	{
		while (reader.ReadOneBit() && !reader.IsOverflowed())
		{
			if (reader.ReadOneBit())
				reader.ReadBits(5);
			else
				reader.ReadBits(MAX_CONSISTENCY_INDEX_BITS);
			consistency++;
		}
	}

	reader.EndBitReading();

	text = Format("%u resources, %d checked for consistency", total, consistency);
	return true;
}

bool CMessageDecoder::DecodeUserMessage(int id, CBitReader &reader, std::string &name, std::string &text, std::string &error)
{
	const UserMessageInfo *message = m_Tables.FindUserMessage(id);
	if (!message)
	{
		error = Format("user message %d is not registered in the recording", id);
		return false;
	}

	name = message->name;
	const size_t length = message->size < 0 ? reader.ReadByte() : size_t(message->size);
	if (reader.IsOverflowed() || length > reader.GetBytesLeft())
	{
		error = "the body runs past the end of the stream";
		return false;
	}

	text = DescribeUserMessage(name, reader.GetData() + reader.GetBytePosition(), length);
	reader.SkipBytes(length);
	return true;
}

std::string CMessageDecoder::DescribeUserMessage(const std::string &name, const uint8_t *body, size_t length) const
{
	std::string text;
	for (const IUserMessageDissector *dissector : m_Dissectors)
	{
		if (m_Tables.GetGameDirectory() == dissector->GetGameDirectory() && dissector->Describe(name, body, length, text))
			return text;
	}

	return Format("%zu bytes", length) + (length ? ": " + Hex(body, length) : std::string());
}

bool CMessageDecoder::DecodeClientMessage(int id, CBitReader &reader, uint32_t sequence, std::string &text, std::string &error)
{
	switch (id)
	{
	case clc_nop:
	case clc_tmove: // read as nothing
	case clc_hltv:
		return true;

	case clc_move:       return DecodeMove(reader, sequence, text, error);
	case clc_stringcmd:  text = Quote(reader.ReadString()); return true;
	case clc_delta:      text = Format("from %d", reader.ReadByte()); return true;

	case clc_resourcelist:
	{
		const int total = reader.ReadShort();
		for (int i = 0; i < total && !reader.IsOverflowed(); i++)
		{
			const std::string name = reader.ReadString();
			reader.SkipBytes(1 + 2 + 4);

			if (reader.ReadByte() & RES_CUSTOM)
				reader.SkipBytes(MD5_SIZE);

			text += (text.empty() ? "" : " ") + Quote(name);
		}
		text = Format("%d resources ", total) + text;
		return true;
	}

	// TODO: The answers are munged under the server's spawn count, which the recording does not hold
	// WRITE spawncount in meta too
	case clc_fileconsistency:
	{
		const int length = reader.ReadShort();
		if (length <= 0)
		{
			error = "no answers";
			return false;
		}
		reader.SkipBytes(size_t(length));
		text = Format("%d bytes of answers", length);
		return true;
	}

	case clc_voicedata:
	{
		const int length = reader.ReadShort();
		reader.SkipBytes(size_t(length > 0 ? length : 0));
		text = Format("%d bytes", length);
		return true;
	}

	case clc_cvarvalue:	text = Quote(reader.ReadString()); return true;

	case clc_cvarvalue2:
	{
		const int request = reader.ReadLong();
		const std::string name = reader.ReadString();
		text = Format("request %d %s = ", request, name.c_str()) + Quote(reader.ReadString());
		return true;
	}

	default:
		error = id == clc_bad ? "the stream holds clc_bad" : "the server drops a client for this command";
		return false;
	}
}

bool CMessageDecoder::DecodeMove(CBitReader &reader, uint32_t sequence, std::string &text, std::string &error)
{
	const size_t length = reader.ReadByte();
	const int checksum = reader.ReadByte();
	if (length == 0 || length > reader.GetBytesLeft())
	{
		error = "the commands run past the end of the stream";
		return false;
	}

	std::vector<uint8_t> commands(reader.GetData() + reader.GetBytePosition(), reader.GetData() + reader.GetBytePosition() + length);
	reader.SkipBytes(length);
	UnmungeMove(commands.data(), commands.size(), sequence);

	// The commands are read where the engine reads them: on in the stream, past the munged length if they run longer
	CBitReader move(commands.data(), commands.size());
	const int loss = move.ReadByte();
	const int backup = move.ReadByte();
	const int count = move.ReadByte();

	std::string latest;
	for (int i = 0; i < backup + count && !move.IsOverflowed(); i++)
	{
		move.StartBitReading();
		std::string fields;
		if (!ReadDeltaOf(move, "usercmd_t", fields, error))
			return false;
		move.EndBitReading();

		if (i == backup + count - 1)
			latest = fields;
	}

	text = Format("%d new, %d backup, loss %d%%%s, checksum %02X", count, backup, loss & 0x7F, (loss & 0x80) ? " voice loopback" : "", checksum);
	if (move.IsOverflowed())
		text += ", the commands run past their length";
	else if (!latest.empty())
		text += ", the newest changes " + latest;
	return true;
}

} // namespace NetInspector
