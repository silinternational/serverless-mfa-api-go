#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo out all commands for monitoring progress
set -x

# When using the provided.al2 runtime, the binary must be named "bootstrap" and be in the root directory
CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap ./application/lambda
