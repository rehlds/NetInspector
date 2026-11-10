//=============================================================================//
//
// The message ids of protocol 48 and the channel limits the engines share
//
//=============================================================================//

#pragma once

#include <cstddef>

namespace NetInspector
{

enum SvcCommands
{
	svc_bad,
	svc_nop,
	svc_disconnect,
	svc_event,
	svc_version,
	svc_setview,
	svc_sound,
	svc_time,
	svc_print,
	svc_stufftext,
	svc_setangle,
	svc_serverinfo,
	svc_lightstyle,
	svc_updateuserinfo,
	svc_deltadescription,
	svc_clientdata,
	svc_stopsound,
	svc_pings,
	svc_particle,
	svc_damage,
	svc_spawnstatic,
	svc_event_reliable,
	svc_spawnbaseline,
	svc_temp_entity,
	svc_setpause,
	svc_signonnum,
	svc_centerprint,
	svc_killedmonster,
	svc_foundsecret,
	svc_spawnstaticsound,
	svc_intermission,
	svc_finale,
	svc_cdtrack,
	svc_restore,
	svc_cutscene,
	svc_weaponanim,
	svc_decalname,
	svc_roomtype,
	svc_addangle,
	svc_newusermsg,
	svc_packetentities,
	svc_deltapacketentities,
	svc_choke,
	svc_resourcelist,
	svc_newmovevars,
	svc_resourcerequest,
	svc_customization,
	svc_crosshairangle,
	svc_soundfade,
	svc_filetxferfailed,
	svc_hltv,
	svc_director,
	svc_voiceinit,
	svc_voicedata,
	svc_sendextrainfo,
	svc_timescale,
	svc_resourcelocation,
	svc_sendcvarvalue,
	svc_sendcvarvalue2,
	svc_exec,
	svc_netmessage,				// PROTOCOL_EXT_NETMESSAGE:  [varint subtype] [varint length] [payload]
	svc_usermessage,			// PROTOCOL_EXT_USERMESSAGE: [string name]    [varint size]   [body]
	svc_reserve62,
	svc_reserve63,
	svc_startofusermessages = svc_reserve63 + 1,
	svc_endoflist = 255,
};

enum ClcCommands
{
	clc_bad,
	clc_nop,
	clc_move,				// [CUserCmd]
	clc_stringcmd,			// [string] message
	clc_delta,				// [byte] request for delta compressed entity packet,
							//	delta is from last incoming sequence [byte]
	clc_resourcelist,
	clc_tmove,
	clc_fileconsistency,
	clc_voicedata,			// Voicestream data from a client
	clc_hltv,
	clc_cvarvalue,
	clc_cvarvalue2,
	clc_netmessage,			// PROTOCOL_EXT_NETMESSAGE, same layout as svc_netmessage
	clc_usermessage,		// PROTOCOL_EXT_USERMESSAGE, same layout as svc_usermessage
	clc_max,
	clc_endoflist = 255,
};

// The most one reliable message carries: what one end queued while its last one was in flight.
// HLDS holds no more in netchan.message and drops the client past it; ReHLDS holds 64 KB and
// sends a longer buffer as fragments.
constexpr size_t MAX_MSGLEN = 3990;

} // namespace NetInspector
