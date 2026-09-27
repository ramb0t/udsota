/* Force-included into isotp-c/isotp.c ONLY (see CMakeLists.txt): replaces isotp-c's compile-time
 * receive BS and STmin with per-link values. Every use of the two macros in isotp.c has `link` in
 * scope (isotp.c:591-597, 636-642, 684-686; 770 is streaming, compiled out). isotp_config.h only
 * defines its defaults #ifndef, so these win. Do not add these macros component-wide: other files
 * have no `link` in scope. */
#pragma once
#include "isotp_port.h"

#define ISO_TP_DEFAULT_BLOCK_SIZE isotp_port_bs(link)
#define ISO_TP_DEFAULT_ST_MIN_US  isotp_port_st_min_us(link)
