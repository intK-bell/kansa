#!/usr/bin/env bash
set -euo pipefail

# Required:
#   API_BASE="https://<api-domain>"
#   TOKEN="<admin-jwt>"
#
# Optional:
#   PLAN_CHECKOUT="BASIC"   # BASIC|PLUS|PRO
#   PLAN_UPGRADE="PLUS"     # BASIC|PLUS|PRO
#   PLAN_DOWNGRADE="BASIC"  # BASIC|PLUS|PRO
#   RUN_CHANGE="1"          # 1=run change APIs, 0=skip
#
# Example:
#   API_BASE="https://xxxx.execute-api.ap-northeast-1.amazonaws.com" \
#   TOKEN="eyJ..." \
#   ./scripts/run_subscription_checks.sh

if [[ -z "${API_BASE:-}" ]]; then
  echo "[NG] API_BASE is required" >&2
  exit 1
fi
if [[ -z "${TOKEN:-}" ]]; then
  echo "[NG] TOKEN is required" >&2
  exit 1
fi

PLAN_CHECKOUT="${PLAN_CHECKOUT:-BASIC}"
PLAN_UPGRADE="${PLAN_UPGRADE:-PLUS}"
PLAN_DOWNGRADE="${PLAN_DOWNGRADE:-BASIC}"
RUN_CHANGE="${RUN_CHANGE:-1}"

ok=0
ng=0

pass() { echo "[OK] $1"; ok=$((ok + 1)); }
fail() { echo "[NG] $1"; ng=$((ng + 1)); }

tmp_body="$(mktemp)"
trap 'rm -f "$tmp_body"' EXIT

api_call() {
  local method="$1"; shift
  local path="$1"; shift
  local body="${1:-}"

  if [[ -n "$body" ]]; then
    curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" "$API_BASE$path" \
      -H "Authorization: Bearer $TOKEN" \
      -H "content-type: application/json" \
      -d "$body"
  else
    curl -sS -o "$tmp_body" -w "%{http_code}" -X "$method" "$API_BASE$path" \
      -H "Authorization: Bearer $TOKEN" \
      -H "content-type: application/json"
  fi
}

body_field() {
  local expr="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r "$expr // empty" "$tmp_body" 2>/dev/null || true
  else
    echo ""
  fi
}

echo "== subscription backend checks start =="
echo "API_BASE=$API_BASE"

status="$(api_call GET /team/subscription)"
mode=""
if [[ "$status" == "200" ]]; then
  mode="$(body_field '.billingMode')"
  plan="$(body_field '.subscription.currentPlan')"
  pass "GET /team/subscription (mode=${mode:-unknown}, plan=${plan:-unknown})"
else
  fail "GET /team/subscription status=$status body=$(cat "$tmp_body")"
fi

success_url="https://example.com/?subscription=success&plan=${PLAN_CHECKOUT}&session_id={CHECKOUT_SESSION_ID}"
cancel_url="https://example.com/"
status="$(api_call POST /team/subscription/checkout "{\"plan\":\"$PLAN_CHECKOUT\",\"successUrl\":\"$success_url\",\"cancelUrl\":\"$cancel_url\"}")"
if [[ "$status" == "200" ]]; then
  checkout_url="$(body_field '.url')"
  session_id="$(body_field '.sessionId')"
  if [[ -n "$checkout_url" && -n "$session_id" ]]; then
    pass "POST /team/subscription/checkout (plan=$PLAN_CHECKOUT)"
  else
    fail "POST /team/subscription/checkout missing url/sessionId body=$(cat "$tmp_body")"
  fi
else
  fail "POST /team/subscription/checkout status=$status body=$(cat "$tmp_body")"
fi

if [[ "$RUN_CHANGE" == "1" ]]; then
  status="$(api_call POST /team/subscription/change "{\"action\":\"upgrade\",\"targetPlan\":\"$PLAN_UPGRADE\"}")"
  msg="$(body_field '.message')"
  if [[ "$status" == "200" ]]; then
    plan="$(body_field '.billing.subscription.currentPlan')"
    pass "POST /team/subscription/change upgrade->$PLAN_UPGRADE (current=${plan:-unknown})"
  elif [[ "$status" == "400" && "${mode:-}" != "subscription" ]]; then
    pass "POST /team/subscription/change upgrade->$PLAN_UPGRADE skipped (mode=${mode:-unknown})"
  else
    fail "POST /team/subscription/change upgrade status=$status body=$(cat "$tmp_body")"
  fi

  status="$(api_call POST /team/subscription/change "{\"action\":\"downgrade\",\"targetPlan\":\"$PLAN_DOWNGRADE\"}")"
  if [[ "$status" == "200" || "$status" == "400" ]]; then
    if [[ "$status" == "200" ]]; then
      pending="$(body_field '.billing.subscription.pendingPlan')"
      pass "POST /team/subscription/change downgrade->$PLAN_DOWNGRADE accepted (pending=${pending:-none})"
    elif [[ "${mode:-}" != "subscription" ]]; then
      pass "POST /team/subscription/change downgrade->$PLAN_DOWNGRADE skipped (mode=${mode:-unknown})"
    else
      pass "POST /team/subscription/change downgrade->$PLAN_DOWNGRADE rejected by guard"
    fi
  else
    fail "POST /team/subscription/change downgrade status=$status body=$(cat "$tmp_body")"
  fi

  status="$(api_call POST /team/subscription/change '{"action":"cancel"}')"
  if [[ "$status" == "200" ]]; then
    pass "POST /team/subscription/change cancel"
  elif [[ "$status" == "400" && "${mode:-}" != "subscription" ]]; then
    pass "POST /team/subscription/change cancel skipped (mode=${mode:-unknown})"
  else
    fail "POST /team/subscription/change cancel status=$status body=$(cat "$tmp_body")"
  fi

  status="$(api_call POST /team/subscription/change '{"action":"resume"}')"
  if [[ "$status" == "200" ]]; then
    pass "POST /team/subscription/change resume"
  elif [[ "$status" == "400" && "${mode:-}" != "subscription" ]]; then
    pass "POST /team/subscription/change resume skipped (mode=${mode:-unknown})"
  else
    fail "POST /team/subscription/change resume status=$status body=$(cat "$tmp_body")"
  fi
else
  echo "[INFO] RUN_CHANGE=0: change API checks are skipped."
fi

echo "== subscription backend checks done =="
echo "summary: OK=$ok NG=$ng"
[[ $ng -eq 0 ]]
