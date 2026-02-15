#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"

cd "$BACKEND_DIR"

npm --prefix src install
sam build

# Stripe secret values should not be committed to the repo.
# Provide them via environment variables when deploying:
#   STRIPE_SECRET_KEY=sk_test_... STRIPE_WEBHOOK_SECRET=whsec_... ./scripts/deploy_backend.sh
STRIPE_SECRET_KEY_VALUE="${STRIPE_SECRET_KEY-}"
STRIPE_WEBHOOK_SECRET_VALUE="${STRIPE_WEBHOOK_SECRET-}"

if [[ -n "$STRIPE_SECRET_KEY_VALUE" && -n "$STRIPE_WEBHOOK_SECRET_VALUE" ]]; then
  # Keep non-secret parameter_overrides from backend/samconfig.toml (e.g. Stripe price ids),
  # and only inject secrets here. Passing --parameter-overrides overrides config values.
  EXISTING_OVERRIDES="$(
    sed -n 's/^parameter_overrides[[:space:]]*=[[:space:]]*"\(.*\)"[[:space:]]*$/\1/p' samconfig.toml \
      | head -n 1
  )"
  sam deploy --parameter-overrides $EXISTING_OVERRIDES \
    StripeSecretKey="$STRIPE_SECRET_KEY_VALUE" \
    StripeWebhookSecret="$STRIPE_WEBHOOK_SECRET_VALUE"
else
  echo "[WARN] Stripe keys not provided. Deploying without Stripe secrets." 1>&2
  echo "       Set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET env vars to enable Stripe." 1>&2
  sam deploy
fi

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
