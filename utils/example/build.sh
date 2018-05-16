#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
cd $SCRIPTPATH/../irma_js

git submodule update --init && \
npm install -g bower  && \
npm install -g grunt-cli && \
bower install && \
npm install && \
grunt build --client --server

cd - &> /dev/null
