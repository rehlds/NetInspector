//=============================================================================//
//
// What decoding a session needs besides its datagrams: the server's limits,
// its user messages, its delta descriptions and its precache names. A
// recording carries them as session table entries; the messages that set them
// on the wire update the same tables.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "netinspector/format.h"

namespace NetInspector
{

struct UserMessageInfo
{
	int			size;	// -1: the message carries its own length
	std::string	name;
};

struct DeltaDescription
{
	std::string						name;
	std::vector<DeltaFieldRecord>	fields;
};

class CSessionTables
{
public:
	//-----------------------------------------------------------------------------
	// Takes the table a session table entry carries, replacing the one it names.
	// False for an entry of another type or one too short for what it says.
	//-----------------------------------------------------------------------------
	bool Apply(const EntryHeader &header, const uint8_t *body);

	void Clear();

	void SetServerInfo(int maxClients, const std::string &map, const std::string &gameDirectory);
	void SetInstancedBaselines(int count) { m_InstancedBaselines = count; }
	void SetUserMessage(int id, int size, const std::string &name);
	void SetDeltaDescription(const DeltaDescription &description);
	void SetPrecache(PrecacheKind kind, int index, const std::string &name);

	int GetMaxClients() const { return m_MaxClients; }
	int GetInstancedBaselines() const { return m_InstancedBaselines; }
	const std::string &GetMap() const { return m_Map; }
	const std::string &GetGameDirectory() const { return m_GameDirectory; }

	const UserMessageInfo *FindUserMessage(int id) const;
	size_t GetUserMessageCount() const { return m_UserMessages.size(); }

	const DeltaDescription *FindDeltaDescription(const std::string &name) const;
	const std::map<std::string, DeltaDescription> &GetDeltaDescriptions() const { return m_DeltaDescriptions; }

	// Null for an index the table does not have
	const char *FindPrecache(PrecacheKind kind, int index) const;
	size_t GetPrecacheCount(PrecacheKind kind) const;

private:
	bool ApplyServerInfo(const uint8_t *body, size_t length);
	bool ApplyUserMessages(const uint8_t *body, size_t length);
	bool ApplyDeltaDescription(const uint8_t *body, size_t length);
	bool ApplyPrecache(const uint8_t *body, size_t length);

	int											m_MaxClients = 0;
	int											m_InstancedBaselines = 0;
	std::string									m_Map;
	std::string									m_GameDirectory;
	std::map<int, UserMessageInfo>				m_UserMessages;
	std::map<std::string, DeltaDescription>		m_DeltaDescriptions;
	std::map<PrecacheKind, std::map<int, std::string>> m_Precache;
};

} // namespace NetInspector
