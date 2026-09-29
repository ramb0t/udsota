#!/bin/sh
# Fails when a server/ source, the core's or the port's, reaches into the updater: it mentions the updater's member of udsota_server_t
# (->update or .update), or includes an updater header other than udsota_update_state.h, by a path through '../' or
# 'update/' or by the name of a header in components/udsota/update/include. The port's server/ may still include the
# umbrella udsota.h, which is in include/; the core-only build keeps the core's server/ from doing so.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
member='(->|\.)[[:space:]]*update([^[:alnum:]_]|$)'
# The updater's header names, listed at run time, less the one the server context may name; dots escaped.
hdrs=$(ls "$root/components/udsota/update/include" | grep -E '\.h$' | grep -vx 'udsota_update_state\.h' |
       sed 's/\./\\./g' | paste -sd'|' -)
[ -n "$hdrs" ] || { echo "check_seam: no updater headers in update/include"; exit 2; }
inc="^[[:space:]]*#[[:space:]]*include[[:space:]]*[<\"]([^\">]*(\.\./|update/)|([^\">]*/)?($hdrs)[\">])"
hit() { pat=$1; shift; grep -rnE --include='*.c' --include='*.h' -e "$pat" "$@" || [ $? -eq 1 ]; }   # 2 still fails
scan() { grep -rnE --include='*.c' --include='*.h' -e "$member" -e "$inc" "$@" || [ $? -eq 1 ]; }
# Self-check 1: the fixture holds exactly 8 hits (4 member, 4 include) and 5 near-misses.
n=$(scan "$root/test/fixtures/seam_grep_probe.c" | wc -l)
[ "$n" -eq 8 ] || { echo "check_seam: self-check found $n of 8 hits: a pattern is broken"; exit 2; }
# Self-check 2: live positives, since the updater itself uses the member and includes its own headers.
hit "$member" "$root/components/udsota/update" | grep -q . || { echo "check_seam: no member hit in update/"; exit 2; }
hit "$inc" "$root/components/udsota/update" | grep -q . || { echo "check_seam: no include hit in update/"; exit 2; }
# The scanned tree must exist and hold sources: a moved or empty directory would pass silently.
[ "$(find "$root/components/udsota/server" -name '*.c' | wc -l)" -ge 5 ] || { echo "check_seam: server/ missing"; exit 2; }
hits=$(scan "$root/components/udsota/server" "$root/components/udsota_esp32/server")
[ -z "$hits" ] || { printf '%s\n' "$hits"; echo "check_seam: server/ reaches into the updater"; exit 1; }
echo "check_seam: PASS"
