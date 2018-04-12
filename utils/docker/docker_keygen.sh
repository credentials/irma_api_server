#!/bin/bash

# Check if openssl exists
if ! type openssl >/dev/null 2>&1; then
    >&2 echo "openssl not found, exiting"
    exit 1
fi

# Create tmp directory
DIR=`mktemp -d`
SK=$DIR/sk
PK=$DIR/pk

# Generate a private key in PEM format
openssl genrsa -out ${SK}.pem 2048
# Convert it to DER for Java
openssl pkcs8 -topk8 -inform PEM -outform DER -in ${SK}.pem -out ${SK}.der -nocrypt
# Calculate corresponding public key, saved in PEM format
openssl rsa -in ${SK}.pem -pubout -outform PEM -out ${PK}.pem
# Calculate corresponding public key, saved in DER format
openssl rsa -in ${SK}.pem -pubout -outform DER -out ${PK}.der

# Echo docker config
cat << EOF

Key generation finished, use (and save!) the following command to start your container:

# docker run -p 8080:8080 -e IRMA_API_CONF_BASE64_JWT_PUBLICKEY=`cat $PK.der | base64 | tr -d '\n'` -e IRMA_API_CONF_BASE64_JWT_PRIVATEKEY=`cat $SK.der | base64 | tr -d '\n'` privacybydesign/irma_api_server

EOF

echo "Use (and save!) the following key in your IRMA-enabled application to verify JWT tokens:"
echo
cat $PK.pem
echo

# Clean up
rm $SK.{pem,der} $PK.{pem,der}
rmdir $DIR
