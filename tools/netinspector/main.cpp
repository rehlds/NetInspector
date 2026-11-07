//=============================================================================//
//
// netinspector: the command line over .gcap recordings
//
//=============================================================================//

#include <CLI/CLI.hpp>

#include "health_report.h"
#include "info_report.h"
#include "messages_report.h"
#include "netinspector_version.h"
#include "overflow_report.h"
#include "threats_report.h"
#include "timeline_report.h"

int main(int argc, char **argv)
{
	CLI::App app("Reads .gcap traffic recordings", "netinspector");
	app.set_version_flag("--version", "netinspector " NETINSPECTOR_VERSION);
	app.require_subcommand(1);

	NetInspector::CInfoReport info;
	NetInspector::CTimelineReport timeline;
	NetInspector::CMessagesReport messages;
	NetInspector::COverflowReport overflow;
	NetInspector::CHealthReport health;
	NetInspector::CThreatsReport threats;
	NetInspector::CCommand *const commands[] = { &info, &health, &threats, &overflow, &messages, &timeline };

	for (NetInspector::CCommand *command : commands)
		command->Register(app);

	CLI11_PARSE(app, argc, argv);

	for (NetInspector::CCommand *command : commands)
	{
		if (command->IsChosen())
			return command->Execute();
	}

	return 1;
}
