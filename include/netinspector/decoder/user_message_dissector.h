//=============================================================================//
//
// What a game's user messages carry is up to the game. A dissector for one
// game turns the bodies of its messages into text; without one, a message is
// shown by its name and its bytes.
//
//=============================================================================//

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace NetInspector
{

class IUserMessageDissector
{
public:
	virtual ~IUserMessageDissector() = default;

	// The game directory whose messages it knows, as the server reports it
	virtual const char *GetGameDirectory() const = 0;

	// False for a message it does not know; text is left as it was then
	virtual bool Describe(const std::string &name, const uint8_t *body, size_t length, std::string &text) const = 0;
};

} // namespace NetInspector
