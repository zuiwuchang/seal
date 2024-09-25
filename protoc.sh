#!/bin/bash
set -e
cd "`dirname "BASH_SOURCE"`"

protoc ./raw/raw.proto --go_out=./ --go_opt=paths=source_relative