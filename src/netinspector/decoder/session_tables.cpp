//=============================================================================//
//
// The session tables and their entries
//
//=============================================================================//

#include "netinspector/decoder/session_tables.h"

#include <cstring>

namespace NetInspector
{

namespace
{

// Reads an entry body front to back; every read fails once one ran past the end
class CBodyReader
{
public:
	CBodyReader(const uint8_t *data, size_t length) : m_Data(data), m_Length(length) {}

	template <typename Value>
	bool Read(Value &value)
	{
		if (!m_Valid || m_Length - m_Position < sizeof(Value))
		{
			m_Valid = false;
			return false;
		}

		std::memcpy(&value, m_Data + m_Position, sizeof(Value));
		m_Position += sizeof(Value);
		return true;
	}

	bool ReadString(std::string &text)
	{
		const void *end = m_Valid ? std::memchr(m_Data + m_Position, 0, m_Length - m_Position) : nullptr;
		if (!end)
		{
			m_Valid = false;
			return false;
		}

		const size_t length = static_cast<const uint8_t *>(end) - (m_Data + m_Position);
		text.assign(reinterpret_cast<const char *>(m_Data + m_Position), length);
		m_Position += length + 1;
		return true;
	}

private:
	const uint8_t	*m_Data;
	size_t			m_Length;
	size_t			m_Position = 0;
	bool			m_Valid = true;
};

// A fixed name field, which a damaged file may leave unterminated
std::string NameOf(const char *field, size_t size)
{
	const void *end = std::memchr(field, 0, size);
	return std::string(field, end ? static_cast<const char *>(end) - field : size);
}

} // namespace

bool CSessionTables::Apply(const EntryHeader &header, const uint8_t *body)
{
	switch (header.type)
	{
	case Entry::ServerInfo:			return ApplyServerInfo(body, header.length);
	case Entry::UserMessages:		return ApplyUserMessages(body, header.length);
	case Entry::DeltaDescription:	return ApplyDeltaDescription(body, header.length);
	case Entry::Precache:			return ApplyPrecache(body, header.length);
	default:						return false;
	}
}

void CSessionTables::Clear()
{
	m_MaxClients = 0;
	m_InstancedBaselines = 0;
	m_Map.clear();
	m_GameDirectory.clear();
	m_UserMessages.clear();
	m_DeltaDescriptions.clear();
	m_Precache.clear();
}

void CSessionTables::SetServerInfo(int maxClients, const std::string &map, const std::string &gameDirectory)
{
	m_MaxClients = maxClients;
	m_Map = map;
	m_GameDirectory = gameDirectory;
}

void CSessionTables::SetUserMessage(int id, int size, const std::string &name)
{
	UserMessageInfo &message = m_UserMessages[id];
	message.size = size;
	message.name = name;
}

void CSessionTables::SetDeltaDescription(const DeltaDescription &description)
{
	m_DeltaDescriptions[description.name] = description;
}

void CSessionTables::SetPrecache(PrecacheKind kind, int index, const std::string &name)
{
	m_Precache[kind][index] = name;
}

const UserMessageInfo *CSessionTables::FindUserMessage(int id) const
{
	const std::map<int, UserMessageInfo>::const_iterator message = m_UserMessages.find(id);
	return message != m_UserMessages.end() ? &message->second : nullptr;
}

const DeltaDescription *CSessionTables::FindDeltaDescription(const std::string &name) const
{
	const std::map<std::string, DeltaDescription>::const_iterator description = m_DeltaDescriptions.find(name);
	return description != m_DeltaDescriptions.end() ? &description->second : nullptr;
}

const char *CSessionTables::FindPrecache(PrecacheKind kind, int index) const
{
	const std::map<PrecacheKind, std::map<int, std::string>>::const_iterator table = m_Precache.find(kind);
	if (table == m_Precache.end())
		return nullptr;

	const std::map<int, std::string>::const_iterator item = table->second.find(index);
	return item != table->second.end() ? item->second.c_str() : nullptr;
}

size_t CSessionTables::GetPrecacheCount(PrecacheKind kind) const
{
	const std::map<PrecacheKind, std::map<int, std::string>>::const_iterator table = m_Precache.find(kind);
	return table != m_Precache.end() ? table->second.size() : 0;
}

bool CSessionTables::ApplyServerInfo(const uint8_t *body, size_t length)
{
	CBodyReader reader(body, length);

	ServerInfoEntry info;
	std::string map;
	std::string gameDirectory;
	if (!reader.Read(info) || !reader.ReadString(map) || !reader.ReadString(gameDirectory))
		return false;

	SetServerInfo(info.maxClients, map, gameDirectory);
	SetInstancedBaselines(info.instancedBaselines);
	return true;
}

bool CSessionTables::ApplyUserMessages(const uint8_t *body, size_t length)
{
	CBodyReader reader(body, length);

	UserMessagesEntry list;
	if (!reader.Read(list))
		return false;

	std::map<int, UserMessageInfo> messages;
	for (uint16_t i = 0; i < list.count; i++)
	{
		UserMessageRecord record;
		UserMessageInfo message;
		if (!reader.Read(record) || !reader.ReadString(message.name))
			return false;

		message.size = record.size;
		messages[record.id] = message;
	}

	m_UserMessages.swap(messages);
	return true;
}

bool CSessionTables::ApplyDeltaDescription(const uint8_t *body, size_t length)
{
	CBodyReader reader(body, length);

	DeltaDescriptionEntry entry;
	if (!reader.Read(entry))
		return false;

	DeltaDescription description;
	description.name = NameOf(entry.name, sizeof(entry.name));
	description.fields.resize(entry.fieldCount);

	for (DeltaFieldRecord &field : description.fields)
	{
		if (!reader.Read(field))
			return false;

		field.name[sizeof(field.name) - 1] = '\0';
	}

	SetDeltaDescription(description);
	return true;
}

bool CSessionTables::ApplyPrecache(const uint8_t *body, size_t length)
{
	CBodyReader reader(body, length);

	PrecacheEntry list;
	if (!reader.Read(list))
		return false;

	std::map<int, std::string> items;
	for (uint16_t i = 0; i < list.count; i++)
	{
		uint16_t index;
		std::string name;
		if (!reader.Read(index) || !reader.ReadString(name))
			return false;

		items[index] = name;
	}

	m_Precache[list.kind].swap(items);
	return true;
}

} // namespace NetInspector
