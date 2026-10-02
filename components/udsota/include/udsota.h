/* udsota's API: the UDS server (udsota_server.h) and its firmware updater (udsota_update.h), over the wire contract
 * in udsota_wire.h. Pure C: shared by the host tests and the firmware. */
#pragma once
#include "udsota_wire.h"
#include "udsota_server.h"
#include "udsota_update.h"

/* The udsota release this header belongs to, for an #if on the release a feature arrived in. tools/release.py sets
 * all four at each cut, and its check fails when they disagree with the tag (RELEASING.md). */
#define UDSOTA_VERSION_MAJOR 0
#define UDSOTA_VERSION_MINOR 14
#define UDSOTA_VERSION_PATCH 2
#define UDSOTA_VERSION       "0.14.2"
