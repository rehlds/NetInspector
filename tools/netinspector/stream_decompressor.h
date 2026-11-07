//=============================================================================//
//
// Decompresses the reliable streams a sender compressed: "BZ2\0" followed by
// a bzip2 stream
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <vector>

namespace NetInspector
{

class CStreamDecompressor
{
public:
	enum class Result
	{
		Decompressed,
		NotCompressed,
		Corrupt,
		TooLarge,
	};

	// On Decompressed the message is in decompressed
	Result Decompress(const std::vector<uint8_t> &message, std::vector<uint8_t> &decompressed);

	static const char *ToString(Result result);

private:
	std::vector<uint8_t> m_Buffer;
};

} // namespace NetInspector
