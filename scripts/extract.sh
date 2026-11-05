#!/usr/bin/env bash
# Extract one crate to Lean: cargo hax json --use-ids, then haxpipeT from hax-lean.
#   scripts/extract.sh <x3dh-hax|pqxdh-hax|doubleratchet-hax> [path-to-haxpipeT]
# haxpipeT is built with `lake build haxpipeT` in a checkout of
# https://github.com/spitters/hax-lean at revision 8482a3104d69 (branch lean-upgrade-4.35).
set -euo pipefail
crate="$1"
haxpipet="${2:-haxpipeT}"
case "$crate" in
  x3dh-hax) name=X3dh ;;
  pqxdh-hax) name=Pqxdh ;;
  doubleratchet-hax) name=Doubleratchet ;;
  *) echo "unknown crate: $crate" >&2; exit 2 ;;
esac
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/$crate"
cargo hax json --use-ids
ulimit -s unlimited 2>/dev/null || true
"$haxpipet" --hax --emit-certified --name "$name" hax_frontend_export.json > "${name}_haxpipe.lean"
echo "wrote $crate/${name}_haxpipe.lean"
