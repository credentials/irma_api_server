#!/bin/bash

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
testdir=$dir/../src/test/resources

# Check if JWT private key for unit tests exists; if it does, then
# we might as well assume that the corresponding public keys also exist
if [ ! -e $testdir/test-sk.der ]; then
    # Generate JWT keys for unit tests
    $dir/keygen.sh $testdir/test-sk $testdir/test-pk

    $dir/keygen.sh $testdir/sk $testdir/pk
    rm $testdir/sk.pem 2> /dev/null # Not needed

    # Move them to the appropriate locations
    mkdir $testdir/verifiers $testdir/issuers
    cp $testdir/test-pk.der $testdir/verifiers/testsp.der
    mv $testdir/test-pk.der $testdir/issuers/testip.der

    # PEM versions are not needed
    rm $testdir/test-sk.pem $testdir/test-pk.pem
fi
