#!/usr/bin/env bash

set -e
cd "$(dirname "$0")"

openssl x509 -x509toreq -in ca.crt -copy_extensions copyall -signkey ca.key -out ca.csr
openssl x509 -req -copy_extensions copyall -days 365 -in ca.csr -set_serial 0x01 -signkey ca.key -out ca.crt && rm ca.csr
openssl x509 -in ca.crt -outform der | sha256sum | awk '{print $1}' > ca.der.sha256

openssl x509 -x509toreq -in es.crt -copy_extensions copyall -signkey es.key -out es.csr
openssl x509 -req -copy_extensions copyall -days 365 -in es.csr -set_serial 0x01 -CA ca.crt -CAkey ca.key -out es.crt && rm es.csr

# output ISO8601 timestamp to file
date -Iseconds > GENERATED_AT