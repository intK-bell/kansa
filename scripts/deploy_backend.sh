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

cat <<MSG

Deploy complete.
Set these in browser console:
localStorage.setItem('kansa_api_base', '$API_URL');
localStorage.setItem('kansa_photo_bucket', '$PHOTO_BUCKET');

MSG
