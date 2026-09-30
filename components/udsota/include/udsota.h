/* udsota's API on this branch: the firmware updater (udsota_update.h) and what its ports share (udsota_common.h),
 * over the wire contract in udsota_wire.h. No UDS server: a host server (iso14229, udsota_iso14229.h) calls it.
 * Pure C: shared by the host tests and the firmware. */
#pragma once
#include "udsota_wire.h"
#include "udsota_common.h"
#include "udsota_update.h"
