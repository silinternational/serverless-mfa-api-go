#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo out all commands for monitoring progress
set -x

# temporary: see permissions on .git folder to troubleshoot error message "error obtaining VCS status: exit status 128"
ls -adl .git
git config --global --add safe.directory $(pwd)

# Build binaries
CGO_ENABLED=0 go build -tags lambda.norpc -ldflags="-s -w" -o bootstrap ./lambda

# Print the Serverless version in the logs
serverless --version

echo "Deploying stage $STAGE of serverless package to region $1..."
serverless deploy --verbose --stage "$STAGE" --region "$1"
