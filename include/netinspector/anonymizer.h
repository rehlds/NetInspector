//=============================================================================//
//
// Takes out of recorded traffic what identifies people. Secrets (rcon passwords,
// auth tickets, cd keys, private userinfo values) always go. Addresses are
// mapped with a key that lives only as long as the anonymizer and is never
// written: one real address is one fake address for the whole recording, so
// who is who stays readable, but the file cannot be mapped back. The mapping
// keeps prefixes: addresses of one subnet stay in one subnet, and a flood from
// a range still reads as one.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "netinspector/format.h"

namespace NetInspector
{

class CAnonymizer
{
public:
	static constexpr size_t KEY_SIZE = 16;

	// A key from the system's random source; false if it gave none
	bool GenerateKey();

	// A known key, so that two runs map alike
	void SetKey(const uint8_t (&key)[KEY_SIZE]);

	// Userinfo keys to scrub besides the ones starting with an underscore
	void SetPrivateUserInfoKeys(const std::vector<std::string> &keys);

	// Console commands whose arguments are secrets, such as an auth token a client sends
	void SetPrivateCommands(const std::vector<std::string> &commands);

	// Loopback, unspecified and broadcast addresses come back as they are
	Endpoint Map(const Endpoint &endpoint) const;

	//-----------------------------------------------------------------------------
	// A connectionless datagram, its -1 header included, rewritten into scrubbed
	// without its secrets; with mapAddresses, the addresses written in its text
	// are mapped too. True if anything changed.
	//-----------------------------------------------------------------------------
	bool ScrubConnectionless(const uint8_t *data, size_t length, bool mapAddresses, std::vector<uint8_t> &scrubbed) const;

	//-----------------------------------------------------------------------------
	// A channel packet rewritten into scrubbed with the arguments of private
	// commands masked: anywhere in its payload a private command is followed by a
	// space or a quote, what follows up to the string's end becomes '*', quotes,
	// spaces and line ends kept. True if anything changed.
	//-----------------------------------------------------------------------------
	bool ScrubChannel(const uint8_t *data, size_t length, std::vector<uint8_t> &scrubbed) const;

private:
	uint32_t MapIPv4(uint32_t ip) const;

	void ScrubConnect(std::vector<uint8_t> &packet, size_t &textEnd) const;
	void MapTextAddresses(std::vector<uint8_t> &packet, size_t textEnd) const;

	uint64_t m_Key[2] = {};
	std::vector<std::string> m_PrivateUserInfoKeys;
	std::vector<std::string> m_PrivateCommands;
};

} // namespace NetInspector
