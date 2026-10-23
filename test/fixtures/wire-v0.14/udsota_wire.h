/* udsota wire contract (ISO 14229-1 over ISO-TP): the server's (udsota_server_wire.h: SIDs, NRCs, sessions,
 * SecurityAccess, timing, F186/F18C/F1F2) and the updater's (udsota_update_wire.h: download framing, reason codes,
 * F189/F1F0/F1F1/F1F3, RIDs, and the status and result layouts). Pure C. Every value there is on the wire: changing
 * one needs a matching client change and a CHANGELOG entry. */
#pragma once
#include "udsota_server_wire.h"
#include "udsota_update_wire.h"
