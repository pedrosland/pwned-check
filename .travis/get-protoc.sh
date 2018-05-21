#!/bin/bash

VERSION="3.5.1"

cd /tmp

curl -LO https://github.com/google/protobuf/releases/download/v${VERSION}/protoc-${VERSION}-linux-x86_64.zip
unzip protoc-${VERSION}-linux-x86_64.zip -d protoc3

mv protoc3/bin/* /usr/local/bin/
mv protoc3/include/* /usr/local/include/