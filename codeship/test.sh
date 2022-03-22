#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo commands to console
set -x

# export appropriate AWS credentials for `serverless info`
if [ "${CI_BRANCH}" == "main" ];
then
  STAGE="production"
  export AWS_ACCESS_KEY_ID="${PRD_AWS_ACCESS_KEY_ID}"
  set +x
  export AWS_SECRET_ACCESS_KEY="${PRD_AWS_SECRET_ACCESS_KEY}"
  set -x
else
  STAGE="dev"
  export AWS_ACCESS_KEY_ID="${STG_AWS_ACCESS_KEY_ID}"
  set +x
  export AWS_SECRET_ACCESS_KEY="${STG_AWS_SECRET_ACCESS_KEY}"
  set -x
fi

# disabled tests due to issue on Codeship resolving dynamo container
#go test -v ./...

# Print the Serverless version in the logs
serverless --version

# Validate Serverless config
serverless info --stage "${STAGE}"
