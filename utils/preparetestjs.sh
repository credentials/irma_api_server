#!/bin/bash

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
main=$dir/../src/main/resources

# Generate test issuer's keys
mkdir -p $main/issuers
$dir/keygen.sh $main/issuers/testip-sk $main/issuers/testip

# Generate test verifier's keys
mkdir -p $main/verifiers
$dir/keygen.sh $main/verifiers/testsp-sk $main/verifiers/testsp
