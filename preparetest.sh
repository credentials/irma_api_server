#!/bin/bash

path=./src/main/resources

# Generate JWT signing keys
./keygen.sh $path/sk $path/pk
rm $path/sk.pem 2> /dev/null # Not needed

# Check if JWT private key for unit tests exists; if it does, then
# we might as well assume that the corresponding public keys also exist
if [ ! -e $path/test-sk.der ]; then
    # Generate JWT keys for unit tests
    ./keygen.sh $path/test-sk $path/test-pk

    # Move them to the appropriate locations
    mkdir $path/verifiers $path/issuers
    cp $path/test-pk.der $path/verifiers/testsp.der
    mv $path/test-pk.der $path/issuers/testip.der

    # PEM versions are not needed
    rm $path/test-sk.pem $path/test-pk.pem
fi

# Symlink irma_configuration if it is present in ../
if [ ! -d $path/irma_configuration ] && [ -d ../irma_configuration ]; then
    ln -s ../../../../irma_configuration $path/irma_configuration
fi
