#!/bin/sh
# Ephemeral test-only CA; never use these credentials outside the test network.
set -eu
cd /certificates
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.crt -days 2 -subj /CN=test-root
for name in server client; do
  cn=vpn-gateway
  usage=serverAuth
  if [ "$name" = client ]; then cn=vpn-client; usage=clientAuth; fi
  mkdir -p "$name"
  cp ca.crt "$name/ca.crt"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$name/tls.key" -out "$name/request" -subj "/CN=$cn"
  printf "extendedKeyUsage=%s\nkeyUsage=digitalSignature,keyEncipherment\n" "$usage" > "$name/extensions"
  openssl x509 -req -in "$name/request" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$name/tls.crt" -days 2 -extfile "$name/extensions"
done
