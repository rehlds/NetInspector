//=============================================================================//
//
// "netinspector info": who made a recording, its time span, what it holds, its
// frame times and the traffic and sessions of every endpoint in it
//
//=============================================================================//

#pragma once

#include "command.h"

namespace NetInspector
{

class CInfoReport : public CCommand
{
public:
	CInfoReport() : CCommand("info", "who recorded the file, its time span, counts, frame times, endpoints") {}

protected:
	int Run(CReader &reader) override;
};

} // namespace NetInspector
