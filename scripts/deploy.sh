#!/usr/bin/env bash

# Exit script with error if any step fails.
set -e

# Echo out all commands for monitoring progress
set -x

# Build binaries
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
"$DIR"/build.sh

# export appropriate env vars
if [ "${GITHUB_REF}" == "develop" ];
then
  STAGE="dev"
  export AWS_ACCESS_KEY_ID="${STG_AWS_ACCESS_KEY_ID}"
  set +x
  export AWS_SECRET_ACCESS_KEY="${STG_AWS_SECRET_ACCESS_KEY}"
  set -x
  export LAMBDA_ROLE="${STG_LAMBDA_ROLE}"
  export API_KEY_TABLE="${STG_API_KEY_TABLE}"
  export WEBAUTHN_TABLE="${STG_WEBAUTHN_TABLE}"
elif [ "${GITHUB_REF}" == "main" ];
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
    echo "deployments only happen from develop and main branches (branch: ${GITHUB_REF})"
    exit
fi

# Print the Serverless version in the logs
serverless --version

echo "Deploying stage $STAGE of serverless package..."
serverless deploy --verbose --stage "$STAGE" --region us-east-1
serverless deploy --verbose --stage "$STAGE" --region us-west-2
