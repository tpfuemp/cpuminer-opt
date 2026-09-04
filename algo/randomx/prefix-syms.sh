#!/bin/sh
# Prefix every symbol DEFINED in a static archive, so a second copy of the
# RandomX core can be linked alongside the stock one.
#
#   prefix-syms.sh <in.a> <out.a> <prefix> [nm] [objcopy]
#
# Not objcopy --prefix-symbols: that also renames UNDEFINED symbols, so every
# reference to libc and libstdc++ gets the prefix and the link fails on
# hundreds of missing symbols. Renaming only what the archive defines leaves
# its outgoing references intact while making its own names unique.
#
# Nothing narrower than "all definitions" is safe. Both copies define the
# randomx_* C API and the whole randomx:: C++ namespace, vtables and template
# instantiations included; a partial rename binds a variant entry point to
# stock internals, which is silent corruption rather than a link error.

set -e

IN="$1"; OUT="$2"; PREFIX="$3"
NM="${4:-nm}"; OBJCOPY="${5:-objcopy}"

if [ -z "$IN" ] || [ -z "$OUT" ] || [ -z "$PREFIX" ]; then
   echo "usage: $0 <in.a> <out.a> <prefix> [nm] [objcopy]" >&2
   exit 1
fi

MAP="$OUT.syms"

# Defined symbols only, deduplicated. Skip anything already prefixed so the
# rule is idempotent.
"$NM" --defined-only --format=posix "$IN" \
  | awk '{ print $1 }' \
  | grep -v '^$' \
  | grep -v "^$PREFIX" \
  | sort -u \
  | awk -v p="$PREFIX" '{ print $1 " " p $1 }' > "$MAP"

COUNT=$(grep -c '' "$MAP" || true)
if [ "$COUNT" -eq 0 ]; then
   echo "$0: refusing to continue -- no defined symbols found in $IN" >&2
   echo "  (an empty rename map would produce an unprefixed copy, which links" >&2
   echo "   against the stock core and mines the wrong algorithm silently)" >&2
   exit 1
fi

cp "$IN" "$OUT"
"$OBJCOPY" --redefine-syms="$MAP" "$OUT"

# Prove it took: the archive must now define the prefixed C entry point and
# must no longer define the bare one.
if ! "$NM" --defined-only --format=posix "$OUT" \
     | awk '{print $1}' | grep -qx "${PREFIX}randomx_calculate_hash"; then
   echo "$0: ${PREFIX}randomx_calculate_hash is not defined in $OUT" >&2
   exit 1
fi
if "$NM" --defined-only --format=posix "$OUT" \
     | awk '{print $1}' | grep -qx "randomx_calculate_hash"; then
   echo "$0: $OUT still defines the unprefixed randomx_calculate_hash" >&2
   exit 1
fi

echo "  prefixed $COUNT symbols in $(basename "$OUT") with '$PREFIX'"
