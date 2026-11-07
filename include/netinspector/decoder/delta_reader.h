//=============================================================================//
//
// Delta-compressed structures as DELTA_ParseDelta reads them: a mask of the
// fields that changed, then each changed field in the bits its description
// gives. Only what changed is known; the values it changed from are not.
//
//=============================================================================//

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "netinspector/decoder/bit_reader.h"
#include "netinspector/decoder/session_tables.h"

namespace NetInspector
{

// The engine's field types
enum DeltaFieldType : uint32_t
{
	DT_BYTE				= 1 << 0,
	DT_SHORT			= 1 << 1,
	DT_FLOAT			= 1 << 2,
	DT_INTEGER			= 1 << 3,
	DT_ANGLE			= 1 << 4,
	DT_TIMEWINDOW_8		= 1 << 5,
	DT_TIMEWINDOW_BIG	= 1 << 6,
	DT_STRING			= 1 << 7,
	DT_SIGNED			= 0x80000000u,
};

struct DeltaValue
{
	const DeltaFieldRecord	*field;
	double					number;	// every type but strings, multipliers applied
	std::string				text;	// strings
};

//-----------------------------------------------------------------------------
// Reads one delta of description into values. False when the delta names a
// field type the description does not know or the message ends inside it.
//-----------------------------------------------------------------------------
bool ReadDelta(CBitReader &reader, const DeltaDescription &description, std::vector<DeltaValue> &values);

// "name=value ..." of the values
std::string FormatDelta(const std::vector<DeltaValue> &values);

// The description svc_deltadescription sends its fields in
const DeltaDescription &GetMetaDescription();

// A delta of the meta description as the field record it describes
DeltaFieldRecord ToFieldRecord(const std::vector<DeltaValue> &values);

} // namespace NetInspector
