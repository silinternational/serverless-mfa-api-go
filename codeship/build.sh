#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo out all commands for monitoring progress
set -x

# Build the binaries
CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap ./lambda
