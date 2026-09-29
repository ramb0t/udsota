#!/bin/sh
# Fails when a server-core source mentions the updater's member of udsota_server_t (->update or .update).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
pat='(->|\.)[[:space:]]*update([^[:alnum:]_]|$)'
scan() { grep -rnE --include='*.c' --include='*.h' "$pat" "$@" || [ $? -eq 1 ]; }   # 2 (error) still fails
# Self-check 1: the fixture holds exactly 4 hits and 3 near-misses.
n=$(scan "$root/test/fixtures/seam_grep_probe.c" | wc -l)
[ "$n" -eq 4 ] || { echo "check_seam: self-check found $n of 4 hits: the pattern is broken"; exit 2; }
# Self-check 2: a live positive, since the updater itself uses the member.
scan "$root/components/udsota/update" | grep -q . || { echo "check_seam: no hit in update/"; exit 2; }
# The scanned tree must exist and hold sources: a moved or empty directory would pass silently.
[ "$(find "$root/components/udsota/server" -name '*.c' | wc -l)" -ge 5 ] || { echo "check_seam: server/ missing"; exit 2; }
hits=$(scan "$root/components/udsota/server" "$root/components/udsota_esp32/server")
[ -z "$hits" ] || { printf '%s\n' "$hits"; echo "check_seam: server/ touches the updater's member"; exit 1; }
echo "check_seam: PASS"
