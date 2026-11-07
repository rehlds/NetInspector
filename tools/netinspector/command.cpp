//=============================================================================//
//
// The part every subcommand shares: its recording argument and opening it
//
//=============================================================================//

#include "command.h"

#include <cstdio>

#include <CLI/CLI.hpp>

namespace NetInspector
{

void CCommand::Register(CLI::App &app)
{
	m_Subcommand = app.add_subcommand(m_Name, m_Description);
	m_Subcommand->add_option("file", m_Path, "the .gcap recording")->required()->check(CLI::ExistingFile);
	if (WritesJson())
		m_Subcommand->add_flag("--json", m_Json, "JSON Lines instead of text: one object a line, for programs to read");
	AddOptions(*m_Subcommand);
}

bool CCommand::IsChosen() const
{
	return m_Subcommand && m_Subcommand->parsed();
}

void CCommand::AddOptions(CLI::App &)
{
}

int CCommand::Execute()
{
	CReader reader;
	if (!reader.Open(m_Path.c_str()))
	{
		std::fprintf(stderr, "netinspector: %s is not a readable .gcap file\n", m_Path.c_str());
		return 2;
	}

	return Run(reader);
}

} // namespace NetInspector
