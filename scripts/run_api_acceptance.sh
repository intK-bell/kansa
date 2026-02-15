#!/usr/bin/env bash
set -u

API_BASE="${1:-https://0nhz8sat7j.execute-api.ap-northeast-1.amazonaws.com}"
USER_A_KEY="test-user-a"
USER_A_NAME="testerA"
USER_B_KEY="test-user-b"
USER_B_NAME="testerB"

ok=0
ng=0

pass() { echo "[OK] $1"; ok=$((ok+1)); }
fail() { echo "[NG] $1"; ng=$((ng+1)); }

api() {
  local method="$1"; shift
  local path="$1"; shift
  local user_key="$1"; shift
  local user_name="$1"; shift
  local body="${1:-}"

  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "$API_BASE$path" \
      -H "content-type: application/json" \
      -H "x-user-key: $user_key" \
      -H "x-user-name: $user_name" \
      -d "$body"
  else
    curl -sS -X "$method" "$API_BASE$path" \
      -H "content-type: application/json" \
      -H "x-user-key: $user_key" \
      -H "x-user-name: $user_name"
  fi
}

api_status() {
  local method="$1"; shift
  local path="$1"; shift
  local user_key="$1"; shift
  local user_name="$1"; shift
  local body="${1:-}"

  if [[ -n "$body" ]]; then
    curl -sS -o /tmp/kansa_resp.json -w "%{http_code}" -X "$method" "$API_BASE$path" \
      -H "content-type: application/json" \
      -H "x-user-key: $user_key" \
      -H "x-user-name: $user_name" \
      -d "$body"
  else
    curl -sS -o /tmp/kansa_resp.json -w "%{http_code}" -X "$method" "$API_BASE$path" \
      -H "content-type: application/json" \
      -H "x-user-key: $user_key" \
      -H "x-user-name: $user_name"
  fi
}

echo "== API acceptance start =="

folder_title="受入試験_$(date +%Y%m%d_%H%M%S)"
folder_json=$(api POST /folders "$USER_A_KEY" "$USER_A_NAME" "{\"title\":\"$folder_title\"}")
folder_id=$(echo "$folder_json" | jq -r '.folderId // empty')
folder_code=$(echo "$folder_json" | jq -r '.folderCode // empty')

if [[ -n "$folder_id" ]]; then pass "フォルダ作成"; else fail "フォルダ作成"; fi
if [[ "$folder_code" =~ ^F[0-9]{3}$ ]]; then pass "フォルダ採番 (folderCode=$folder_code)"; else fail "フォルダ採番 (folderCode=$folder_code)"; fi

upload_json=$(api POST "/folders/$folder_id/photos/upload-url" "$USER_A_KEY" "$USER_A_NAME" '{"fileName":"test.jpg","contentType":"image/jpeg"}')
upload_url=$(echo "$upload_json" | jq -r '.uploadUrl // empty')
photo_id=$(echo "$upload_json" | jq -r '.photoId // empty')
s3_key=$(echo "$upload_json" | jq -r '.s3Key // empty')
if [[ -n "$upload_url" && -n "$photo_id" && -n "$s3_key" ]]; then pass "アップロードURL発行"; else fail "アップロードURL発行"; fi

printf 'fake-image-bytes' > /tmp/kansa_test.jpg
if curl -sS -X PUT "$upload_url" -H 'content-type: image/jpeg' --data-binary @/tmp/kansa_test.jpg >/dev/null; then pass "S3アップロード"; else fail "S3アップロード"; fi

photo_json=$(api POST "/folders/$folder_id/photos" "$USER_A_KEY" "$USER_A_NAME" "{\"photoId\":\"$photo_id\",\"s3Key\":\"$s3_key\",\"fileName\":\"test.jpg\"}")
photo_code=$(echo "$photo_json" | jq -r '.photoCode // empty')
if [[ -n "$photo_id" ]]; then pass "写真登録"; else fail "写真登録"; fi
if [[ "$photo_code" =~ ^F[0-9]{3}-P[0-9]{3}$ ]]; then pass "写真採番 (photoCode=$photo_code)"; else fail "写真採番 (photoCode=$photo_code)"; fi

status=$(api_status PUT "/photos/$photo_id" "$USER_A_KEY" "$USER_A_NAME" '{"fileName":"renamed.jpg"}')
if [[ "$status" == "200" ]]; then pass "写真名リネーム(本人)"; else fail "写真名リネーム(本人) status=$status"; fi

status=$(api_status PUT "/photos/$photo_id" "$USER_B_KEY" "$USER_B_NAME" '{"fileName":"hacked.jpg"}')
if [[ "$status" == "403" ]]; then pass "写真名リネーム(他人拒否)"; else fail "写真名リネーム(他人拒否) status=$status"; fi

comment_json=$(api POST "/photos/$photo_id/comments" "$USER_A_KEY" "$USER_A_NAME" '{"text":"初回コメント"}')
comment_id=$(echo "$comment_json" | jq -r '.commentId // empty')
if [[ -n "$comment_id" ]]; then pass "コメント追加"; else fail "コメント追加"; fi

status=$(api_status PUT "/photos/$photo_id/comments/$comment_id" "$USER_A_KEY" "$USER_A_NAME" '{"text":"更新コメント"}')
if [[ "$status" == "200" ]]; then pass "コメント修正(本人)"; else fail "コメント修正(本人) status=$status"; fi

status=$(api_status PUT "/photos/$photo_id/comments/$comment_id" "$USER_B_KEY" "$USER_B_NAME" '{"text":"改ざん"}')
if [[ "$status" == "403" ]]; then pass "コメント修正(他人拒否)"; else fail "コメント修正(他人拒否) status=$status"; fi

status=$(api_status DELETE "/photos/$photo_id/comments/$comment_id" "$USER_B_KEY" "$USER_B_NAME")
if [[ "$status" == "403" ]]; then pass "コメント削除(他人拒否)"; else fail "コメント削除(他人拒否) status=$status"; fi

status=$(api_status DELETE "/photos/$photo_id/comments/$comment_id" "$USER_A_KEY" "$USER_A_NAME")
if [[ "$status" == "200" ]]; then pass "コメント削除(本人)"; else fail "コメント削除(本人) status=$status"; fi

status=$(api_status DELETE "/photos/$photo_id" "$USER_B_KEY" "$USER_B_NAME")
if [[ "$status" == "403" ]]; then pass "写真削除(他人拒否)"; else fail "写真削除(他人拒否) status=$status"; fi

status=$(api_status DELETE "/photos/$photo_id" "$USER_A_KEY" "$USER_A_NAME")
if [[ "$status" == "200" ]]; then pass "写真削除(本人)"; else fail "写真削除(本人) status=$status"; fi

echo "== API acceptance done =="
echo "summary: OK=$ok NG=$ng"
[[ $ng -eq 0 ]]
