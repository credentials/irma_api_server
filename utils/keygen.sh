#!/bin/bash

# Check if openssl exists
if ! type openssl >/dev/null 2>&1; then
    >&2 echo "openssl not found, exiting"
    exit 1
fi

if [[ $# -eq 0 ]]; then
	SK=sk
	PK=pk
fi
if [[ $# -eq 1 ]]; then
	>&2 echo "Either supply 0 or 2 arguments"
	exit 1
fi
if [[ $# -eq 2 ]]; then
	SK=$1
	PK=$2
fi

if [ -e ${SK}.der ] || [ -e ${PK}.der ]; then
    echo "Keys already exist, not generating new ones"
    exit
fi

# Generate a private key in PEM format
openssl genrsa -out ${SK}.pem 2048
# Convert it to DER for Java
openssl pkcs8 -topk8 -inform PEM -outform DER -in ${SK}.pem -out ${SK}.der -nocrypt
# Calculate corresponding public key, saved in PEM format
openssl rsa -in ${SK}.pem -pubout -outform PEM -out ${PK}.pem
# Calculate corresponding public key, saved in DER format
openssl rsa -in ${SK}.pem -pubout -outform DER -out ${PK}.der
