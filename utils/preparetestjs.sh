#!/bin/bash

main=./src/main/resources

# Generate test issuer's keys
mkdir -p $main/issuers
./keygen.sh $main/issuers/testip-sk $main/issuers/testip

# Generate test verifier's keys
mkdir -p $main/verifiers
./keygen.sh $main/verifiers/testsp-sk $main/verifiers/testsp
