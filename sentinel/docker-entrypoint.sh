#!/bin/sh
# Refresh nuclei's templates on every start (never pinned, see docs/UPDATES.md), then run the daemon. A failed refresh
# is not fatal: the templates baked into the image at build time are used until the next successful one.
set -e
nuclei -update-templates >/dev/null 2>&1 || echo "could not refresh nuclei templates; using the ones built into the image"
exec "$@"
