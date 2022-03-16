#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo commands to console
set -x

# disabled tests due to issue on Codeship resolving dynamo container
#go test -v ./...

# Print the Serverless version in the logs
serverless --version

# Validate Serverless config
serverless info
