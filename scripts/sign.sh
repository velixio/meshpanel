#!/bin/sh
# Signs a release file with meshpanel's ed25519 release key: sign.sh FILE SIGNATURE
# The key (PEM) comes from $MESHPANEL_SIGNING_KEY and never touches the disk
# except in a private temp file removed on exit. The matching public key is
# internal/update/signing.pub; the updater refuses anything it doesn't verify.
set -eu
[ $# -eq 2 ] || { echo "usage: sign.sh FILE SIGNATURE" >&2; exit 2; }
[ -n "${MESHPANEL_SIGNING_KEY:-}" ] || { echo "sign.sh: MESHPANEL_SIGNING_KEY is not set; refusing to publish an unsigned release" >&2; exit 1; }
umask 077
key=$(mktemp)
trap 'rm -f "$key"' EXIT
printf '%s\n' "$MESHPANEL_SIGNING_KEY" > "$key"
openssl pkeyutl -sign -rawin -inkey "$key" -in "$1" -out "$2"
[ "$(wc -c < "$2")" -eq 64 ] || { echo "sign.sh: unexpected signature size" >&2; exit 1; }
