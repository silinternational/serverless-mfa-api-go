#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo out all commands for monitoring progress
set -x

# circumvent Go error message "error obtaining VCS status: exit status 128"
git config --global --add safe.directory $(pwd)

# Print the Serverless version in the logs
serverless --version

echo "Deploying stage $2 of serverless package to region $1..."
serverless deploy --verbose --stage "$2" --region "$1"
