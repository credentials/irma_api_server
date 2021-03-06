#!/bin/bash

die() {
  cd "$DIR"; exit 1
}

SRCDIR="$( cd "$(dirname "$0")" ; pwd -P )/.." # irma_api_server/src/main
DIR="$( pwd )" # to switch back to afterwards

# Get irmago including dependencies, and set them to the correct versions
go get -u github.com/privacybydesign/irmago || die
cd $GOPATH/src/github.com/privacybydesign/irmago || die
if type "dep" &> /dev/null; then
  dep ensure || die
else
  echo "Cannot fetch correct versions of irmago dependencies as dep is not installed"
  echo "Possibly using incorrect versions of dependencies!"
fi

# Compile timestamp binaries
cd "$SRCDIR/go"
GOARCH=amd64
CGO_ENABLED=0
GOOS=darwin go build -o "$SRCDIR/resources/timestamp-macos" timestamp.go || die
GOOS=linux go build -o "$SRCDIR/resources/timestamp-linux" timestamp.go || die
GOOS=windows go build -o "$SRCDIR/resources/timestamp-windows.exe" timestamp.go || die
GOOS=freebsd go build -o "$SRCDIR/resources/timestamp-freebsd" timestamp.go || die

cd "$DIR"
