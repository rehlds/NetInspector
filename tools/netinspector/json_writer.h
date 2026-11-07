//=============================================================================//
//
// JSON Lines for the reports: one object a line, written as it is built. Only
// what the reports write is supported: objects, arrays, strings, numbers,
// booleans.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace NetInspector
{

class CJsonWriter
{
public:
	void BeginObject();
	void EndObject();
	void BeginArray();
	void EndArray();

	// The name of the next value inside an object
	void Key(const char *name);

	void String(const std::string &value);
	void Number(double value);
	void Integer(int64_t value);
	void Unsigned(uint64_t value);
	void Bool(bool value);

	// The value under a key, in one call
	void Field(const char *name, const std::string &value) { Key(name); String(value); }
	void Field(const char *name, const char *value) { Key(name); String(value); }
	void Field(const char *name, double value) { Key(name); Number(value); }
	void Field(const char *name, int value) { Key(name); Integer(value); }
	void Field(const char *name, int64_t value) { Key(name); Integer(value); }
	void Field(const char *name, uint32_t value) { Key(name); Unsigned(value); }
	void Field(const char *name, uint64_t value) { Key(name); Unsigned(value); }
	void Field(const char *name, bool value) { Key(name); Bool(value); }

	// Prints the line built so far to stdout and starts the next
	void EndLine();

private:
	void BeforeValue();
	void AppendQuoted(const std::string &value);

	std::string			m_Line;
	std::vector<bool>	m_First;	// per open object or array: nothing written in it yet
	bool				m_AfterKey = false;
};

} // namespace NetInspector
