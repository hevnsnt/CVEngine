#!/usr/bin/env bash
# Does the server see each visitor's own address? (review r3 S2; docs/DEPLOYMENT.md, "Client addresses behind a host proxy")
#
#   scripts/client-address-check.sh            the check: asks the web service for a one-time token, sends one request with it through the public
#                                               address (https://DOMAIN_NAME, or CVENGINE_CLIENT_ADDRESS_URL), reads back the address the server took for
#                                               it, and compares that with the address Cloudflare saw (https://DOMAIN_NAME/cdn-cgi/trace) when there is one.
#                                               Also says whether the upstream secret is set and loaded and whether CVENGINE_TRUSTED_PROXIES is a range.
#   scripts/client-address-check.sh --snippet   prints the host nginx lines to install (config/nginx/host-proxy-client-address.conf) with this
#                                               install's secret filled in. They contain the secret: write them to a root-only file.
#
# Every update runs the check after the new version answers and writes its lines to the update log; it never fails an update.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=compose-layout.sh
. scripts/compose-layout.sh
# shellcheck source=client-address.sh
. scripts/client-address.sh
cvengine_compose_layout || exit 2
case "${1:-}" in
  --snippet) cvengine_client_address_snippet "${COMPOSE[@]}" ;;
  '') cvengine_client_address_report "${COMPOSE[@]}" ;;
  *) echo "usage: $0 [--snippet]" >&2; exit 2 ;;
esac
