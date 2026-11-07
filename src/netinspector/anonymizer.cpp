//=============================================================================//
//
// Address mapping and connectionless scrubbing. The mapping is
// prefix-preserving: bit i of a mapped address is bit i of the real one,
// flipped by a keyed hash of the bits before it, so equal prefixes map to
// equal prefixes and nothing else carries over.
//
//=============================================================================//

#include "netinspector/anonymizer.h"

#include <cstring>

#include "netinspector/channel.h"
#include "netinspector/common/siphash.h"
#include "netinspector/common/strtools.h"
#include "netinspector/protocol/connectionless.h"
#include "netinspector/protocol/info_string.h"
#include "netinspector/platform/random.h"

namespace NetInspector
{

namespace
{

// The protocol info of a connect request carries cd key hashes under every key but these
class CProtocolInfoRule final : public IInfoValueRule
{
public:
	char GetReplacement(const TextSpan &key, const TextSpan &value) const override
	{
		if (key.Equals("prot") || key.Equals("unique"))
			return 0;

		if (key.Equals("raw") && (value.Equals("steam") || value.Equals("valve")))
			return 0;

		return '0';
	}
};

// Keys starting with an underscore are private to the client by convention (setinfo _pw)
class CUserInfoRule final : public IInfoValueRule
{
public:
	explicit CUserInfoRule(const std::vector<std::string> &privateKeys) : m_PrivateKeys(privateKeys) {}

	char GetReplacement(const TextSpan &key, const TextSpan &) const override
	{
		if (key.length && key.data[0] == '_')
			return '*';

		for (const std::string &privateKey : m_PrivateKeys)
		{
			if (key.Equals(privateKey.c_str()))
				return '*';
		}

		return 0;
	}

private:
	const std::vector<std::string> &m_PrivateKeys;
};

} // namespace

bool CAnonymizer::GenerateKey()
{
	return CRandom::Fill(m_Key, sizeof(m_Key));
}

void CAnonymizer::SetKey(const uint8_t (&key)[KEY_SIZE])
{
	std::memcpy(m_Key, key, sizeof(m_Key));
}

void CAnonymizer::SetPrivateUserInfoKeys(const std::vector<std::string> &keys)
{
	m_PrivateUserInfoKeys = keys;
}

void CAnonymizer::SetPrivateCommands(const std::vector<std::string> &commands)
{
	m_PrivateCommands = commands;
}

bool CAnonymizer::ScrubChannel(const uint8_t *data, size_t length, std::vector<uint8_t> &scrubbed) const
{
	scrubbed.assign(data, data + length);
	if (m_PrivateCommands.empty() || length <= CHANNEL_HEADER_SIZE)
		return false;

	const uint8_t sequence = data[0];
	uint8_t *payload = &scrubbed[CHANNEL_HEADER_SIZE];
	const size_t payloadLength = length - CHANNEL_HEADER_SIZE;
	UnmungeChannelPayload(payload, payloadLength, sequence);

	bool changed = false;
	for (const std::string &command : m_PrivateCommands)
	{
		for (size_t position = 0; position + command.size() < payloadLength; position++)
		{
			if (std::memcmp(payload + position, command.data(), command.size()) != 0)
				continue;

			size_t value = position + command.size();
			if (payload[value] != ' ' && payload[value] != '"')
				continue;

			for (; value < payloadLength && payload[value] != 0; value++)
			{
				const uint8_t c = payload[value];
				if (c != ' ' && c != '"' && c != '\n' && c != '*')
				{
					payload[value] = '*';
					changed = true;
				}
			}

			position = value;
		}
	}

	if (!changed)
	{
		scrubbed.assign(data, data + length);
		return false;
	}

	MungeChannelPayload(payload, payloadLength, sequence);
	return true;
}

uint32_t CAnonymizer::MapIPv4(uint32_t ip) const
{
	// Loopback, unspecified and broadcast addresses identify nobody
	if ((ip >> 24) == 127 || ip == 0 || ip == 0xFFFFFFFF)
		return ip;

	const CSipHash hash(m_Key);

	uint32_t mapped = 0;
	for (int bit = 0; bit < 32; bit++)
	{
		const uint32_t prefix = bit ? ip >> (32 - bit) : 0;
		const uint32_t flip = uint32_t(hash.Hash((uint64_t(prefix) << 8) | uint64_t(bit)) & 1);
		const uint32_t source = (ip >> (31 - bit)) & 1;

		mapped |= (source ^ flip) << (31 - bit);
	}

	return mapped;
}

Endpoint CAnonymizer::Map(const Endpoint &endpoint) const
{
	const uint32_t ip = (uint32_t(endpoint.ip[0]) << 24) | (uint32_t(endpoint.ip[1]) << 16) | (uint32_t(endpoint.ip[2]) << 8) | endpoint.ip[3];
	const uint32_t mapped = MapIPv4(ip);

	return Endpoint{ { uint8_t(mapped >> 24), uint8_t(mapped >> 16), uint8_t(mapped >> 8), uint8_t(mapped) }, endpoint.port };
}

bool CAnonymizer::ScrubConnectionless(const uint8_t *data, size_t length, bool mapAddresses, std::vector<uint8_t> &scrubbed) const
{
	scrubbed.assign(data, data + length);
	if (length <= CONNECTIONLESS_HEADER_SIZE)
		return false;

	// The length of the password stays, so guessing still shows
	size_t passwordBegin = 0;
	size_t passwordEnd = 0;
	if (IsRconRequest(data, length))
	{
		if (!FindRconPassword(data, length, passwordBegin, passwordEnd) || passwordBegin == passwordEnd)
			return false;

		std::memset(&scrubbed[passwordBegin], '*', passwordEnd - passwordBegin);
		return true;
	}

	size_t textEnd = scrubbed.size();
	if (IsConnectRequest(data, length))
		ScrubConnect(scrubbed, textEnd);

	if (mapAddresses)
		MapTextAddresses(scrubbed, textEnd);

	return scrubbed.size() != length || std::memcmp(scrubbed.data(), data, length) != 0;
}

void CAnonymizer::ScrubConnect(std::vector<uint8_t> &packet, size_t &textEnd) const
{
	ConnectRequest request;
	ParseConnectRequest(packet.data(), packet.size(), request);

	ScrubInfoValues(packet.data(), request.protocolInfoBegin, request.protocolInfoEnd, CProtocolInfoRule());
	ScrubInfoValues(packet.data(), request.userInfoBegin, request.userInfoEnd, CUserInfoRule(m_PrivateUserInfoKeys));

	// The ticket keeps its length: oversized tickets are what exploits send
	textEnd = request.authBlobBegin;
	std::memset(packet.data() + textEnd, 0, packet.size() - textEnd);
}

//-----------------------------------------------------------------------------
// a.b.c.d:port before textEnd gets a mapped address. A quad without a port
// stays: it is as likely a version number.
//-----------------------------------------------------------------------------
void CAnonymizer::MapTextAddresses(std::vector<uint8_t> &packet, size_t textEnd) const
{
	std::vector<uint8_t> result;
	result.reserve(packet.size() + 16);

	size_t position = 0;
	while (position < textEnd)
	{
		const bool atBoundary = position == 0 || (!IsDigit(packet[position - 1]) && packet[position - 1] != '.');

		uint32_t ip = 0;
		size_t quadEnd = 0;
		const bool isAddress = atBoundary && IsDigit(packet[position])
			&& ParseIPv4(packet.data(), position, textEnd, ip, quadEnd)
			&& quadEnd + 1 < textEnd && packet[quadEnd] == ':' && IsDigit(packet[quadEnd + 1]);

		if (!isAddress)
		{
			result.push_back(packet[position++]);
			continue;
		}

		char quad[16];
		const int quadLength = FormatIPv4(MapIPv4(ip), quad, sizeof(quad));
		result.insert(result.end(), quad, quad + quadLength);
		position = quadEnd;
	}

	result.insert(result.end(), packet.begin() + textEnd, packet.end());
	packet.swap(result);
}

} // namespace NetInspector
