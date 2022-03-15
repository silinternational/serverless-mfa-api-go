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
  STAGE="dev"
  export AWS_ACCESS_KEY_ID="${STG_AWS_ACCESS_KEY_ID}"
  set +x
  export AWS_SECRET_ACCESS_KEY="${STG_AWS_SECRET_ACCESS_KEY}"
  set -x
  export LAMBDA_ROLE="${STG_LAMBDA_ROLE}"
  export API_KEY_TABLE="${STG_API_KEY_TABLE}"
  export WEBAUTHN_TABLE="${STG_WEBAUTHN_TABLE}"
elif [ "${CI_BRANCH}" == "main" ];
then
  STAGE="production"
  export AWS_ACCESS_KEY_ID="${PRD_AWS_ACCESS_KEY_ID}"
  set +x
  export AWS_SECRET_ACCESS_KEY="${PRD_AWS_SECRET_ACCESS_KEY}"
  set -x
  export LAMBDA_ROLE="${PRD_LAMBDA_ROLE}"
  export API_KEY_TABLE="${PRD_API_KEY_TABLE}"
  export WEBAUTHN_TABLE="${PRD_WEBAUTHN_TABLE}"
else
    echo "deployments only happen from develop and main branches (branch: ${CI_BRANCH})"
    exit 1
fi

# Install Node and Serverless
curl -sL https://deb.nodesource.com/setup_16.x | bash -
apt-get update \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*
npm install -g serverless@3

# deploy serverless package
serverless deploy --verbose --stage $STAGE
