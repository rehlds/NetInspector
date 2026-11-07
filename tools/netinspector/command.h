//=============================================================================//
//
// A subcommand of the tool over one recording. It declares its options on the
// command line parser, and runs once they are parsed and the file is open.
//
//=============================================================================//

#pragma once

#include <string>

#include "netinspector/reader.h"

namespace CLI
{
class App;
}

namespace NetInspector
{

class CCommand
{
public:
	CCommand(const char *name, const char *description) : m_Name(name), m_Description(description) {}
	virtual ~CCommand() = default;

	CCommand(const CCommand &) = delete;
	CCommand &operator=(const CCommand &) = delete;

	// Adds the subcommand, its recording argument and its options
	void Register(CLI::App &app);

	bool IsChosen() const;

	// Opens the recording and runs; the tool's exit code
	int Execute();

protected:
	virtual void AddOptions(CLI::App &subcommand);

	// Prints to stdout; the exit code of the command
	virtual int Run(CReader &reader) = 0;

	// --json: JSON Lines instead of text, one object a line; offered by the commands that write it
	virtual bool WritesJson() const { return false; }
	bool IsJson() const { return m_Json; }

	// The recording the command was run on, as given
	const std::string &GetPath() const { return m_Path; }

private:
	bool		m_Json = false;
	const char	*m_Name;
	const char	*m_Description;
	CLI::App	*m_Subcommand = nullptr;
	std::string	m_Path;
};

} // namespace NetInspector
