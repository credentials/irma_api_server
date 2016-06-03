#!/bin/bash

main=./src/main/resources
test=./src/test/resources

# Symlink irma_configuration if it is present in ../
if [ ! -d $main/irma_configuration ] && [ -d ../irma_configuration ]; then
    ln -s ../../../../irma_configuration $main/
fi

# Generate JWT signing keys
./keygen.sh $main/sk $main/pk
rm $main/sk.pem 2> /dev/null # Not needed

# Check if JWT private key for unit tests exists; if it does, then
# we might as well assume that the corresponding public keys also exist
if [ ! -e $test/test-sk.der ]; then
    # Generate JWT keys for unit tests
    ./keygen.sh $test/test-sk $test/test-pk

    # Move them to the appropriate locations
    mkdir $test/verifiers $test/issuers
    cp $test/test-pk.der $test/verifiers/testsp.der
    mv $test/test-pk.der $test/issuers/testip.der

    # PEM versions are not needed
    rm $test/test-sk.pem $test/test-pk.pem
fi
