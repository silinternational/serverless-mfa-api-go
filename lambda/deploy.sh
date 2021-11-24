#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo out all commands for monitoring progress
set -x

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
cd $SCRIPTPATH

# Build the binaries
go build -ldflags="-s -w" -o ./bin/webauthn .

# export appropriate env vars
if [ "${CI_BRANCH}" == "develop" ];
then
  STAGE="staging"
  export API_KEY_TABLE="${STG_API_KEY_TABLE}"
  export WEBAUTHN_TABLE="${STG_WEBAUTHN_TABLE}"
elif [ "${CI_BRANCH}" == "main" ];
then
  STAGE="production"
  export API_KEY_TABLE="${PRD_API_KEY_TABLE}"
  export WEBAUTHN_TABLE="${PRD_WEBAUTHN_TABLE}"
else
    echo "deployments only happen from develop and main branches"
    exit 1
fi

# Install Node and Serverless
curl -sL https://deb.nodesource.com/setup_16.x | bash -
apt-get update \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*
npm install -g serverless

# deploy serverless package
serverless deploy -v --stage $STAGE
