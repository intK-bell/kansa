#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"

cd "$BACKEND_DIR"

npm --prefix src install
sam build
sam deploy

STACK_NAME="kansa-backend"
API_URL="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' --output text)"
PHOTO_BUCKET="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`PhotoBucketName`].OutputValue' --output text)"
COGNITO_REGION="$(aws configure get region)"
COGNITO_DOMAIN_URL="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`CognitoHostedUiDomain`].OutputValue' --output text)"
COGNITO_CLIENT_ID="$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`CognitoUserPoolClientId`].OutputValue' --output text)"
COGNITO_DOMAIN_HOST="${COGNITO_DOMAIN_URL#https://}"
COGNITO_DOMAIN_PREFIX="${COGNITO_DOMAIN_HOST%%.auth.*}"

cat <<MSG

Deploy complete.
Set these in browser console:
localStorage.setItem('kansa_api_base', '$API_URL');
localStorage.setItem('kansa_photo_bucket', '$PHOTO_BUCKET');
localStorage.setItem('kansa_cognito_region', '$COGNITO_REGION');
localStorage.setItem('kansa_cognito_domain', '$COGNITO_DOMAIN_PREFIX');
localStorage.setItem('kansa_cognito_client_id', '$COGNITO_CLIENT_ID');
localStorage.setItem('kansa_cognito_redirect_uri', window.location.origin);

MSG
