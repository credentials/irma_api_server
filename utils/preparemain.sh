#!/bin/bash

dir=$(cd -P -- "$(dirname -- "$0")" && pwd -P)
maindir=$dir/../src/main/resources

# Symlink irma_configuration if it is present in the same dir as irma_api_server
if [ -d $dir/../../irma_configuration ]; then
	# Calculate absolute path without ../.. in it
    confdir=$(cd -P -- "$dir/../../irma_configuration" && pwd -P)
    if [ ! -d $maindir/irma_configuration ]; then
        ln -s $confdir $maindir/
    fi
fi

# Generate JWT signing keys
$dir/keygen.sh $maindir/sk $maindir/pk
rm $maindir/sk.pem 2> /dev/null # Not needed
