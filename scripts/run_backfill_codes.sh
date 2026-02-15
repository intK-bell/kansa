#!/usr/bin/env bash
set -euo pipefail

STACK_NAME="${1:-kansa-backend}"
MODE="${2:-dry-run}"

if [[ "$MODE" == "apply" ]]; then
  PAYLOAD='{"apply":true}'
  OUT_FILE="/tmp/kansa-backfill-apply.json"
else
  PAYLOAD='{"apply":false}'
  OUT_FILE="/tmp/kansa-backfill-dryrun.json"
fi

FUNC_NAME="$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].Outputs[?OutputKey==`BackfillCodesFunctionName`].OutputValue' \
  --output text)"

if [[ -z "$FUNC_NAME" || "$FUNC_NAME" == "None" ]]; then
  echo "BackfillCodesFunctionName not found in stack outputs"
  exit 1
fi

aws lambda invoke \
  --function-name "$FUNC_NAME" \
  --cli-binary-format raw-in-base64-out \
  --payload "$PAYLOAD" \
  "$OUT_FILE" >/tmp/kansa-backfill-invoke-meta.json

echo "mode: $MODE"
echo "function: $FUNC_NAME"
echo "result file: $OUT_FILE"
cat "$OUT_FILE"
echo
