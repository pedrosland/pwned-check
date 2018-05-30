#!/bin/bash

VERSION="3.5.1"

cd /tmp

curl --silent -LO https://github.com/google/protobuf/releases/download/v${VERSION}/protoc-${VERSION}-linux-x86_64.zip
unzip protoc-${VERSION}-linux-x86_64.zip -d $HOME/protoc3
