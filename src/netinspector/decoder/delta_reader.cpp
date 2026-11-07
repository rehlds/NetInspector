//=============================================================================//
//
// Delta decoding
//
//=============================================================================//

#include "netinspector/decoder/delta_reader.h"

#include <cmath>
#include <cstdio>
#include <cstring>

#include "netinspector/common/strtools.h"

namespace NetInspector
{

namespace
{

// The mask is a 3-bit byte count and as many bytes
constexpr int MASK_COUNT_BITS  = 3;
constexpr int MAX_DELTA_FIELDS = 56;

bool IsMultiplier(float multiplier)
{
	return multiplier < 0.9999f || multiplier > 1.0001f;
}

DeltaFieldRecord MakeField(uint32_t type, int bits, float preMultiplier, const char *name)
{
	DeltaFieldRecord field = {};
	field.type = type;
	field.bits = uint16_t(bits);
	field.preMultiplier = preMultiplier;
	field.postMultiplier = 1.0f;
	CopyString(field.name, sizeof(field.name), name);
	return field;
}

DeltaDescription MakeMetaDescription()
{
	DeltaDescription meta;
	meta.name = "delta_description_t";
	meta.fields.push_back(MakeField(DT_INTEGER, 32,    1.0f, "fieldType"));
	meta.fields.push_back(MakeField(DT_STRING,   1,    1.0f, "fieldName"));
	meta.fields.push_back(MakeField(DT_INTEGER, 16,    1.0f, "fieldOffset"));
	meta.fields.push_back(MakeField(DT_INTEGER,  8,    1.0f, "fieldSize"));
	meta.fields.push_back(MakeField(DT_INTEGER,  8,    1.0f, "significant_bits"));
	meta.fields.push_back(MakeField(DT_FLOAT,   32, 4000.0f, "premultiply"));
	meta.fields.push_back(MakeField(DT_FLOAT,   32, 4000.0f, "postmultiply"));
	return meta;
}

const DeltaDescription META_DESCRIPTION = MakeMetaDescription();

} // namespace

bool ReadDelta(CBitReader &reader, const DeltaDescription &description, std::vector<DeltaValue> &values)
{
	values.clear();

	const uint32_t maskBytes = reader.ReadBits(MASK_COUNT_BITS);
	uint8_t mask[8] = {};
	for (uint32_t i = 0; i < maskBytes; i++)
		mask[i] = (uint8_t)reader.ReadBits(8);

	const size_t fieldCount = description.fields.size() < MAX_DELTA_FIELDS ? description.fields.size() : MAX_DELTA_FIELDS;
	for (size_t i = 0; i < fieldCount && !reader.IsOverflowed(); i++)
	{
		if (!(mask[i / 8] & (1u << (i % 8))))
			continue;

		const DeltaFieldRecord &field = description.fields[i];
		const bool isSigned = (field.type & DT_SIGNED) != 0;
		const int bits = field.bits;

		DeltaValue value = { &field, 0.0, std::string() };

		switch (field.type & ~DT_SIGNED)
		{
		case DT_BYTE:
		case DT_SHORT:
		case DT_FLOAT:
		case DT_INTEGER:
			value.number = isSigned ? (double)reader.ReadSBits(bits) : (double)reader.ReadBits(bits);
			if (IsMultiplier(field.preMultiplier))
				value.number /= field.preMultiplier;
			if (IsMultiplier(field.postMultiplier))
				value.number *= field.postMultiplier;
			break;

		case DT_ANGLE:
			value.number = reader.ReadBitAngle(bits);
			break;

		// Hundredths of a second before the message time
		case DT_TIMEWINDOW_8:
			value.number = -(double)reader.ReadSBits(8) / 100.0;
			break;

		case DT_TIMEWINDOW_BIG:
			value.number = -(double)reader.ReadSBits(bits);
			if (IsMultiplier(field.preMultiplier))
				value.number /= field.preMultiplier;
			break;

		case DT_STRING:
			value.text = reader.ReadBitString();
			break;

		default:
			return false;
		}

		values.push_back(value);
	}

	return !reader.IsOverflowed();
}

std::string FormatDelta(const std::vector<DeltaValue> &values)
{
	std::string text;
	for (const DeltaValue &value : values)
	{
		char number[64];
		if ((value.field->type & ~DT_SIGNED) == DT_STRING)
			std::snprintf(number, sizeof(number), "\"%s\"", value.text.c_str());
		else if (value.number == std::floor(value.number) && std::fabs(value.number) < 1e9)
			std::snprintf(number, sizeof(number), "%.0f", value.number);
		else
			std::snprintf(number, sizeof(number), "%.3f", value.number);

		if (!text.empty())
			text += ' ';
		text += value.field->name;
		text += '=';
		text += number;
	}

	return text;
}

const DeltaDescription &GetMetaDescription()
{
	return META_DESCRIPTION;
}

DeltaFieldRecord ToFieldRecord(const std::vector<DeltaValue> &values)
{
	DeltaFieldRecord field = {};
	field.preMultiplier = 1.0f;
	field.postMultiplier = 1.0f;

	for (const DeltaValue &value : values)
	{
		const char *name = value.field->name;
		if (!std::strcmp(name, "fieldType"))
			field.type = (uint32_t)(int64_t)value.number;
		else if (!std::strcmp(name, "fieldName"))
			CopyString(field.name, sizeof(field.name), value.text.c_str());
		else if (!std::strcmp(name, "significant_bits"))
			field.bits = (uint16_t)value.number;
		else if (!std::strcmp(name, "premultiply"))
			field.preMultiplier = float(value.number);
		else if (!std::strcmp(name, "postmultiply"))
			field.postMultiplier = float(value.number);
	}

	return field;
}

} // namespace NetInspector
