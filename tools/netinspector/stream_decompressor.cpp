//=============================================================================//
//
// bzip2 decompression of reliable streams
//
//=============================================================================//

#include "stream_decompressor.h"

#include <cstring>

#include <bzlib.h>

namespace NetInspector
{

namespace
{

constexpr size_t COMPRESSED_HEADER_SIZE = 4;	// "BZ2\0"

// Larger than any reliable message a GoldSrc channel accepts
constexpr unsigned int MAX_DECOMPRESSED_SIZE = 1024 * 1024;

} // namespace

CStreamDecompressor::Result CStreamDecompressor::Decompress(const std::vector<uint8_t> &message, std::vector<uint8_t> &decompressed)
{
	if (message.size() < COMPRESSED_HEADER_SIZE || std::memcmp(message.data(), "BZ2", COMPRESSED_HEADER_SIZE) != 0)
		return Result::NotCompressed;

	m_Buffer.resize(MAX_DECOMPRESSED_SIZE);
	unsigned int length = MAX_DECOMPRESSED_SIZE;

	// bzip2 takes non-const buffers but does not write the source
	char *source = const_cast<char *>(reinterpret_cast<const char *>(message.data() + COMPRESSED_HEADER_SIZE));
	const unsigned int sourceLength = static_cast<unsigned int>(message.size() - COMPRESSED_HEADER_SIZE);

	const int status = BZ2_bzBuffToBuffDecompress(reinterpret_cast<char *>(m_Buffer.data()), &length, source, sourceLength, 0, 0);
	if (status == BZ_OUTBUFF_FULL)
		return Result::TooLarge;
	if (status != BZ_OK)
		return Result::Corrupt;

	decompressed.assign(m_Buffer.begin(), m_Buffer.begin() + length);
	return Result::Decompressed;
}

const char *CStreamDecompressor::ToString(Result result)
{
	switch (result)
	{
	case Result::Decompressed:	return "decompressed";
	case Result::NotCompressed:	return "not compressed";
	case Result::Corrupt:		return "corrupt bzip2 data";
	case Result::TooLarge:		return "larger than any reliable message";
	}

	return "unknown";
}

} // namespace NetInspector
