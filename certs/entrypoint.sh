#!/bin/sh

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

cert() {
  COMMON_NAME=${1}
  FILENAME=${2:-app}

  echo "Creating new certificate for ${COMMON_NAME}"
  
  # Generate a new RSA key pair if does not exist
  if ! test -f ${CERT}_rsa.key; then
    openssl genrsa -out ${FILENAME}.key 4096
  else
    mv ${CERT}_rsa.key ${FILENAME}.key
  fi

  # Request a new certificate for the generated key pair
  openssl req -new -sha256 \
     -key ${FILENAME}.key \
     -out ${FILENAME}.csr \
     -subj "/C=${COUNTRY_CODE}/ST=${STATE}/L=${CITY}/O=${COMPANY}/CN=${COMMON_NAME}"

  # Creating SAN extension which is needed by modern browsers. An IP address needs an IP entry (a DNS entry never matches it),
  # and the loopback names are always added so the address works from the machine itself.
  echo "subjectAltName=$(san_list "${COMMON_NAME}")" > client-ext.cnf

  # Create a new certificate using our own CA
  openssl x509 -req -sha256 -passin env:AUTHORITY_PASSWORD -days 3650 \
    -in ${FILENAME}.csr -CA ca.crt -CAkey ca.key \
    -out ${FILENAME}.crt \
    -extfile client-ext.cnf

  # Rename files and remove useless ones
  mv ${FILENAME}.crt ${FILENAME}.pem
  cp ca.crt ${FILENAME}_chain.pem
  mv ${FILENAME}.key ${FILENAME}_rsa.key
  rm ${FILENAME}.csr
  rm client-ext.cnf
}

# Create /certs folder if it does not exist
[[ -d /certs ]] || mkdir /certs
cd /certs

# Create a new CA if it does not exist
if (! test -f ca.key) || (! test -f ca.crt); then
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

# Create a new certificate for the DOMAIN_NAME
cert ${DOMAIN_NAME} rengine

# Print all cert files
ls -l /certs

