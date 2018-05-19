#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
cd $SCRIPTPATH/../irma_js

if ! type "bower" &> /dev/null; then
  sudo npm install -g bower || exit 1
fi
if ! type "grunt" &> /dev/null; then
  sudo npm install -g grunt-cli || exit 1
fi

git submodule update --init && \
bower install && \
npm install && \
grunt build --client --server

cd - &> /dev/null
