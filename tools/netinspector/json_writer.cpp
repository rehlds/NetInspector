//=============================================================================//
//
// JSON Lines output
//
//=============================================================================//

#include "json_writer.h"

#include <cinttypes>
#include <cmath>
#include <cstdio>

namespace NetInspector
{

void CJsonWriter::BeforeValue()
{
	if (m_AfterKey)
	{
		m_AfterKey = false;
		return;
	}

	if (!m_First.empty())
	{
		if (!m_First.back())
			m_Line += ',';
		m_First.back() = false;
	}
}

void CJsonWriter::BeginObject()
{
	BeforeValue();
	m_Line += '{';
	m_First.push_back(true);
}

void CJsonWriter::EndObject()
{
	m_Line += '}';
	m_First.pop_back();
}

void CJsonWriter::BeginArray()
{
	BeforeValue();
	m_Line += '[';
	m_First.push_back(true);
}

void CJsonWriter::EndArray()
{
	m_Line += ']';
	m_First.pop_back();
}

void CJsonWriter::Key(const char *name)
{
	BeforeValue();
	AppendQuoted(name);
	m_Line += ':';
	m_AfterKey = true;
}

void CJsonWriter::String(const std::string &value)
{
	BeforeValue();
	AppendQuoted(value);
}

void CJsonWriter::AppendQuoted(const std::string &value)
{
	m_Line += '"';
	for (const char c : value)
	{
		const unsigned char byte = (unsigned char)c;
		switch (c)
		{
		case '"':	m_Line += "\\\""; break;
		case '\\':	m_Line += "\\\\"; break;
		case '\n':	m_Line += "\\n"; break;
		case '\r':	m_Line += "\\r"; break;
		case '\t':	m_Line += "\\t"; break;
		default:
			if (byte < 0x20)
			{
				char escaped[8];
				std::snprintf(escaped, sizeof(escaped), "\\u%04x", byte);
				m_Line += escaped;
			}
			else
			{
				m_Line += c;
			}
			break;
		}
	}
	m_Line += '"';
}

void CJsonWriter::Number(double value)
{
	BeforeValue();

	char text[32];
	if (!std::isfinite(value))
		std::snprintf(text, sizeof(text), "null");
	else
		std::snprintf(text, sizeof(text), "%.12g", value);
	m_Line += text;
}

void CJsonWriter::Integer(int64_t value)
{
	BeforeValue();

	char text[32];
	std::snprintf(text, sizeof(text), "%" PRId64, value);
	m_Line += text;
}

void CJsonWriter::Unsigned(uint64_t value)
{
	BeforeValue();

	char text[32];
	std::snprintf(text, sizeof(text), "%" PRIu64, value);
	m_Line += text;
}

void CJsonWriter::Bool(bool value)
{
	BeforeValue();
	m_Line += value ? "true" : "false";
}

void CJsonWriter::EndLine()
{
	std::printf("%s\n", m_Line.c_str());
	m_Line.clear();
	m_First.clear();
	m_AfterKey = false;
}

} // namespace NetInspector
