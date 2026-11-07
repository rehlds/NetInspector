//=============================================================================//
//
// "netinspector overflow": every reliable buffer that overflowed, with what
// filled it, what was still in flight, and how the client's channel stood:
// whether it went silent, whether its acknowledgements stopped, and how much
// the server had been sending it
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "command.h"
#include "endpoint_directory.h"
#include "json_writer.h"
#include "netinspector/decoder/message_decoder.h"
#include "netinspector/decoder/session_tables.h"
#include "report_clock.h"

namespace NetInspector
{

class COverflowReport : public CCommand
{
public:
	COverflowReport();

protected:
	void AddOptions(CLI::App &subcommand) override;
	int Run(CReader &reader) override;
	bool WritesJson() const override { return true; }

private:
	// What the server saw of one client's channel up to now
	struct ClientChannel
	{
		bool		heard = false;
		uint64_t	lastHeard = 0;			// the client's last packet
		uint32_t	acknowledged = 0;		// the newest of the server's packets it acknowledged
		uint64_t	acknowledgedSince = 0;	// when that acknowledgement last moved
		std::deque<std::pair<uint64_t, uint32_t>> sent;	// time and size of the server's recent packets
		uint64_t	overflowTime = 0;		// of the last overflow, to tie the drop to it
		bool		awaitingDrop = false;
	};

	// Messages of one name in a buffer
	struct MessageTotal
	{
		std::string	name;
		uint32_t	count;
		uint32_t	bytes;
	};

	void OnDatagram(const EntryHeader &header, const uint8_t *body);
	void OnOverflow(const EntryHeader &header, const uint8_t *body);
	void OnEvent(const EntryHeader &header, const uint8_t *body);

	// Decodes a server message stream and sums it up by message name, the largest first
	void Summarize(const uint8_t *data, size_t length, std::vector<MessageTotal> &totals);

	bool IsCutShort(size_t length) const;
	std::string CutMessageName() const;

	void PrintStream(const char *title, size_t length, const std::vector<MessageTotal> &totals) const;
	void WriteStream(const char *name, size_t length, const std::vector<MessageTotal> &totals);

	bool										m_List = false;
	const CReportClock							*m_Clock = nullptr;
	CEndpointDirectory							m_Endpoints;
	CSessionTables								m_Tables;
	CMessageDecoder								m_Decoder;
	DecodedStream								m_Decoded;
	CJsonWriter									m_Json;
	std::map<EndpointId, ClientChannel>			m_Clients;
	uint32_t									m_Overflows = 0;
};

} // namespace NetInspector
