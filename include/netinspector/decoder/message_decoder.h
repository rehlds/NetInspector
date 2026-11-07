//=============================================================================//
//
// The messages of a channel stream, one by one, as the engine at the
// receiving end reads them: svc_ messages from a server, clc_ messages from a
// client. Messages that set session tables on the wire update them, so later
// messages decode with what the earlier ones set.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netinspector/decoder/bit_reader.h"
#include "netinspector/decoder/delta_reader.h"
#include "netinspector/decoder/session_tables.h"
#include "netinspector/decoder/user_message_dissector.h"

namespace NetInspector
{

enum class MessageSource
{
	Server,	// svc_ messages
	Client,	// clc_ messages
};

struct DecodedMessage
{
	int			id;
	std::string	name;
	size_t		offset;		// in the stream
	size_t		length;
	std::string	text;
};

struct DecodedStream
{
	std::vector<DecodedMessage>	messages;
	bool						complete = false;	// read to its end
	std::string					error;				// why it stopped, when it did
	size_t						stoppedAt = 0;
};

class CMessageDecoder
{
public:
	explicit CMessageDecoder(CSessionTables &tables) : m_Tables(tables) {}

	CMessageDecoder(const CMessageDecoder &) = delete;
	CMessageDecoder &operator=(const CMessageDecoder &) = delete;

	// Asked first for the user messages of its game; the decoder does not own it
	void AddDissector(const IUserMessageDissector *dissector) { m_Dissectors.push_back(dissector); }

	// sequence is the packet's, which keys the munge over clc_move
	void Decode(MessageSource source, const uint8_t *data, size_t length, uint32_t sequence, DecodedStream &stream);

	static const char *GetServerMessageName(int id);
	static const char *GetClientMessageName(int id);

private:
	// Each reads its message after the id; false and error when it cannot
	bool DecodeServerMessage(int id, CBitReader &reader, std::string &text, std::string &error);
	bool DecodeClientMessage(int id, CBitReader &reader, uint32_t sequence, std::string &text, std::string &error);

	bool DecodeSound(CBitReader &reader, std::string &text);
	bool DecodeServerInfo(CBitReader &reader, std::string &text);
	bool DecodeDeltaDescription(CBitReader &reader, std::string &text, std::string &error);
	bool DecodeClientData(CBitReader &reader, std::string &text, std::string &error);
	bool DecodeEvents(CBitReader &reader, bool reliable, std::string &text, std::string &error);
	bool DecodeBaseline(CBitReader &reader, std::string &text, std::string &error);
	bool DecodePacketEntities(CBitReader &reader, bool delta, std::string &text, std::string &error);
	bool DecodeTempEntity(CBitReader &reader, std::string &text, std::string &error);
	bool DecodeResourceList(CBitReader &reader, std::string &text);
	bool DecodeUserMessage(int id, CBitReader &reader, std::string &name, std::string &text, std::string &error);
	bool DecodeMove(CBitReader &reader, uint32_t sequence, std::string &text, std::string &error);

	// The description of name, or false with the error naming it
	const DeltaDescription *RequireDescription(const char *name, std::string &error) const;
	bool ReadDeltaOf(CBitReader &reader, const char *description, std::string &text, std::string &error);

	std::string DescribeUserMessage(const std::string &name, const uint8_t *body, size_t length) const;
	std::string PrecacheName(PrecacheKind kind, int index) const;

	CSessionTables								&m_Tables;
	std::vector<const IUserMessageDissector *>	m_Dissectors;
	std::vector<DeltaValue>						m_Values;
};

} // namespace NetInspector
