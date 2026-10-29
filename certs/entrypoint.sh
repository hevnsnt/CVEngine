#!/bin/sh

# The web interface certificate, signed by a local authority this script creates once.
#
# Idempotent: it issues a certificate only when one is needed, so it is safe to run again at any time (`make certs`, the installer, and
# scripts/renew-certs.sh every day or so). A certificate is issued when
#   - there is none, or it does not verify against this authority (which includes having expired), or it does not belong to the key;
#   - it no longer covers DOMAIN_NAME, localhost, 127.0.0.1 or CERT_EXTRA_SANS;
#   - fewer than CERT_RENEW_DAYS (30) days remain, so it is renewed well before a browser would warn;
#   - it was issued for more than CERT_MAX_DAYS (400) days, which is what the installer made before 1.x (3650): browsers refuse a lifetime
#     above 398 days, so such a certificate is re-issued once, with the same key, the same authority and the same names;
#   - CERT_FORCE=1.
# CERT_ONLY_OURS=1 (what scripts/renew-certs.sh sets) makes it renew only a certificate this authority issued: a certificate someone else
# issued (Let's Encrypt, a Cloudflare origin certificate: docs/HOSTING-ONLINE.md) is never replaced, and no authority is created. It prints
# `cert-result: external` for that. Without it (`make certs`, the installer) the certificate is replaced as it always was.
# A new certificate is valid for CERT_VALID_DAYS (397). The key is kept across runs: only the certificate changes. The authority (ca.key,
# ca.crt, ca.srl) is created when missing and never touched otherwise, and its password handling is unchanged.
# The files a container has mounted (the proxy) are rewritten in place, never replaced, so the running proxy sees the new certificate at
# its next `nginx -s reload` with no restart.
#
# The last lines it prints are `cert-result: issued|kept|external` and `cert-not-after: <date>`, which scripts/renew-certs.sh reads.

CERT_DIR=${CERT_DIR:-/certs}
CERT_VALID_DAYS=${CERT_VALID_DAYS:-397}
CERT_RENEW_DAYS=${CERT_RENEW_DAYS:-30}
CERT_MAX_DAYS=${CERT_MAX_DAYS:-400}

# subjectAltName value for a host name or IPv4 address (a :port is dropped), plus localhost, 127.0.0.1 and CERT_EXTRA_SANS
# (comma separated names or addresses).
san_list() {
  host=${1%%:*}
  list=""
  for name in "${host}" localhost 127.0.0.1 $(echo "${CERT_EXTRA_SANS:-}" | tr ',' ' '); do
    [ -n "${name}" ] || continue
    if echo "${name}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then entry="IP:${name}"; else entry="DNS:${name}"; fi
    case ",${list}," in *",${entry},"*) continue ;; esac
    list="${list:+${list},}${entry}"
  done
  echo "${list}"
}

# Prints why the certificate has to be issued, and nothing when the one in place can stay.
cert_problem() {
  COMMON_NAME=${1}
  FILENAME=${2:-app}
  if [ "${CERT_FORCE:-}" = 1 ]; then echo "it was asked for (CERT_FORCE=1)"; return; fi
  if [ ! -s "${FILENAME}.pem" ] || [ ! -s "${FILENAME}_rsa.key" ]; then echo "there is none yet"; return; fi
  if ! openssl verify -CAfile ca.crt "${FILENAME}.pem" >/dev/null 2>&1; then
    echo "it has expired or was not signed by this authority"; return
  fi
  if [ "$(openssl x509 -in "${FILENAME}.pem" -noout -pubkey 2>/dev/null)" != "$(openssl pkey -in "${FILENAME}_rsa.key" -pubout 2>/dev/null)" ]; then
    echo "it does not belong to the key"; return
  fi
  for entry in $(san_list "${COMMON_NAME}" | tr ',' ' '); do
    case "${entry}" in
      IP:*) check="-checkip ${entry#IP:}" ;;
      *) check="-checkhost ${entry#DNS:}" ;;
    esac
    # shellcheck disable=SC2086
    if ! openssl x509 -in "${FILENAME}.pem" -noout ${check} 2>/dev/null | grep -q "does match certificate"; then
      echo "it does not cover ${entry#*:}"; return
    fi
  done
  if ! openssl x509 -in "${FILENAME}.pem" -noout -checkend $((CERT_RENEW_DAYS * 86400)) >/dev/null 2>&1; then
    echo "fewer than ${CERT_RENEW_DAYS} days remain"; return
  fi
  # -checkend succeeds when the certificate is still valid after that many seconds. One valid for more than CERT_MAX_DAYS from now was
  # issued for longer than that (a new one never has more than CERT_VALID_DAYS left), which needs no date arithmetic to see.
  if openssl x509 -in "${FILENAME}.pem" -noout -checkend $((CERT_MAX_DAYS * 86400)) >/dev/null 2>&1; then
    echo "it was issued for more than ${CERT_MAX_DAYS} days"; return
  fi
}

cert() {
  COMMON_NAME=${1}
  FILENAME=${2:-app}

  echo "Creating new certificate for ${COMMON_NAME} (${3})"

  # Generate a new RSA key pair unless the previous run left one: only the certificate is renewed
  if [ ! -s "${FILENAME}_rsa.key" ]; then
    openssl genrsa -out "${FILENAME}_rsa.key" 4096 || exit 1
  fi

  # Request a new certificate for the key pair
  openssl req -new -sha256 \
     -key "${FILENAME}_rsa.key" \
     -out "${FILENAME}.csr" \
     -subj "/C=${COUNTRY_CODE}/ST=${STATE}/L=${CITY}/O=${COMPANY}/CN=${COMMON_NAME}" || exit 1

  # Creating SAN extension which is needed by modern browsers. An IP address needs an IP entry (a DNS entry never matches it),
  # and the loopback names are always added so the address works from the machine itself.
  echo "subjectAltName=$(san_list "${COMMON_NAME}")" > client-ext.cnf

  # Create a new certificate using our own CA, beside the one in place: that one is only overwritten by a certificate that was made
  if ! openssl x509 -req -sha256 -passin env:AUTHORITY_PASSWORD -days "${CERT_VALID_DAYS}" -CAcreateserial \
    -in "${FILENAME}.csr" -CA ca.crt -CAkey ca.key \
    -out "${FILENAME}.crt.new" \
    -extfile client-ext.cnf; then
    rm -f "${FILENAME}.crt.new" "${FILENAME}.csr" client-ext.cnf
    echo "Could not sign the certificate; the one in place was not changed." >&2
    exit 1
  fi

  # Written in place (the same file, new contents): the proxy mounts these files, and a replaced file would stay invisible to it
  cat "${FILENAME}.crt.new" > "${FILENAME}.pem"
  cat ca.crt > "${FILENAME}_chain.pem"
  rm -f "${FILENAME}.crt.new" "${FILENAME}.csr" client-ext.cnf
}

# Create the certificate folder if it does not exist
[ -d "${CERT_DIR}" ] || mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}" || exit 1

# A certificate this authority did not issue is left to its owner when asked to renew only our own
if [ "${CERT_ONLY_OURS:-}" = 1 ] && [ -s rengine.pem ]; then
  if [ ! -f ca.crt ] || [ ! -f ca.key ] || [ "$(openssl x509 -in rengine.pem -noout -issuer_hash 2>/dev/null)" != "$(openssl x509 -in ca.crt -noout -subject_hash 2>/dev/null)" ]; then
    echo "The certificate in ${CERT_DIR} was not issued by this authority; it is left as it is."
    echo "cert-result: external"
    echo "cert-not-after: $(openssl x509 -in rengine.pem -noout -enddate | cut -d= -f2)"
    exit 0
  fi
fi

# Create a new CA if it does not exist
if [ ! -f ca.key ] || [ ! -f ca.crt ]; then
  echo "Creating new CA..."
  # The CA key is encrypted with AUTHORITY_PASSWORD (it was written in the clear before, whatever the password said) and readable by
  # root only; the password is read from the environment, never put on a command line. A CA created by an older version keeps its
  # key as it is: delete ca.key and ca.crt in the certs volume and run this again to replace it (browsers then need the new CA).
  (umask 077; openssl genrsa -aes256 -passout env:AUTHORITY_PASSWORD -out ca.key 4096)
  openssl req -new -x509 -sha256 \
   -passin env:AUTHORITY_PASSWORD \
   -extensions v3_ca -key ca.key -out ca.crt -days 3650 \
   -subj "/C=${COUNTRY_CODE}/O=${COMPANY}/CN=${AUTHORITY_NAME}"

  echo "01" > ca.srl
fi

# Create a new certificate for the DOMAIN_NAME when the one in place cannot stay
problem=$(cert_problem "${DOMAIN_NAME}" rengine)
if [ -n "${problem}" ]; then
  cert "${DOMAIN_NAME}" rengine "${problem}"
  result=issued
else
  echo "The certificate for ${DOMAIN_NAME} is still good; nothing to renew."
  result=kept
fi

# Print all cert files
ls -l "${CERT_DIR}"

echo "cert-result: ${result}"
echo "cert-not-after: $(openssl x509 -in rengine.pem -noout -enddate | cut -d= -f2)"
