# 本番運用手順（監査ログ / Amplify公開）

## 0. Backendデプロイ

本番 backend は AWS SAM でデプロイします。  
実行場所はリポジトリ直下です。

### 最短手順

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa
./scripts/deploy_backend.sh
```

このスクリプトで以下をまとめて実行します。

- `backend/src` の `npm install`
- `sam build`
- `sam deploy`

デプロイ完了後は、CloudFormation Outputs から取得した値を使うための
`localStorage.setItem(...)` がターミナルに表示されます。

### Stripe秘密値も含めてデプロイする場合

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa
STRIPE_SECRET_KEY=sk_live_xxx STRIPE_WEBHOOK_SECRET=whsec_xxx ./scripts/deploy_backend.sh
```

`STRIPE_SECRET_KEY` と `STRIPE_WEBHOOK_SECRET` はリポジトリへ commit しないこと。

### デプロイ結果確認

```bash
aws cloudformation describe-stacks \
  --stack-name kansa-backend \
  --query 'Stacks[0].StackStatus' \
  --output text
```

`UPDATE_COMPLETE` が返れば反映完了。

### デプロイ履歴

- 2026-04-29 19:55 JST: `./scripts/deploy_backend.sh` で `kansa-backend` を更新。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。Stripe秘密値は環境変数未指定のため未注入。
- 2026-04-29 21:52 JST: メンバー削除の冪等化修正を `./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。Stripe秘密値は環境変数未指定のため未注入。
- 2026-04-29 21:57 JST: `GET /team/members` で `left` メンバーを返さない修正を `./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。Stripe秘密値は環境変数未指定のため未注入。
- 2026-04-29 22:08 JST: メンバー一覧の `userKey` を ROOM member の実キーへ揃え、削除APIが対象を正しく更新できるようにした修正を `./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。Stripe秘密値は環境変数未指定のため未注入。
- 2026-04-29 22:29 JST: `PUT /team/members/{userKey}` の `status:left` 更新で DynamoDB 予約語 `status` を `#status` に修正し、`./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。デプロイ後に `status:left` 更新が `200` になり、ROOM側 `status=left` / USER側 `memberStatus=left` を確認済み。
- 2026-04-29 22:48 JST: 招待受諾時のメンバー種別整理を実装。お部屋メンバーがフォルダ招待を受けても降格せず、フォルダメンバーが お部屋招待を受けた場合は `folderScope=all` / `folderIds=[]` に昇格する修正を `./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。
- 2026-04-29 22:56 JST: お部屋メンバー一覧から `folderScope=invited` を除外し、フォルダメンバー一覧は対象フォルダの `folderScope=invited` だけ返す修正を `./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。デプロイ後に bell が お部屋メンバー一覧から除外され、対象フォルダメンバー一覧だけに表示されることを確認済み。
- 2026-04-29 23:12 JST: フォルダメンバー解除を `status:left` ではなく `folderIds` から対象フォルダだけ外す `DELETE /folders/{folderId}/members/{userKey}` に変更。残りフォルダが空の場合のみ `status=left` にする修正を `./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。
- 2026-04-29 23:16 JST: 本番フロントが古い間の安全装置として、複数 `folderIds` を持つフォルダメンバーは `PUT /team/members/{userKey}` の `status:left` で削除できないようにする修正を `./scripts/deploy_backend.sh` で再デプロイ。`sam build` / `sam deploy` 成功、CloudFormation `UPDATE_COMPLETE`。

### 手動で実行したい場合

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa/backend
npm --prefix src install
sam build
sam deploy
```

### 依存ライブラリの脆弱性確認

Backend 依存の脆弱性確認は `backend/src` で実行します。

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa/backend/src
npm audit
```

対応方針:

- `npm audit fix` で解消できるものは、差分を確認してから反映する
- `npm audit fix --force` が必要なものは破壊的更新を含むため、先に影響範囲を確認する
- 未使用の直接依存は、更新より削除を優先する
- `package.json` / `package-lock.json` 更新後は `node --check api.js` と `npm audit` を再実行する
- 依存更新は Lambda パッケージへ反映するため、Backend 再デプロイが必要

2026-04-29 対応メモ:

- `uuid@11.1.0` は実コードで未使用だったため直接依存から削除した
- ID 生成は Node.js 標準の `node:crypto` `randomUUID()` を利用している
- AWS SDK 経由の `@aws-sdk/xml-builder` を `3.972.21` へ更新し、`fast-xml-parser` を `5.7.2` へ更新した
- 対応後の `npm audit` は `found 0 vulnerabilities`

## 1. 監査ログ（CloudWatch Logs）
APIの作成/修正/削除時、Lambdaは `kind=audit` のJSONログを出力します。

### ロググループ
- `/aws/lambda/kansa-backend-ApiFunction-*`

### Logs Insights 例
```sql
fields @timestamp, action, actor, actorName, folderId, photoId, commentId, result, reason, requestId
| filter kind = "audit"
| sort @timestamp desc
| limit 200
```

### 削除/修正だけ見る
```sql
fields @timestamp, action, actorName, actor, photoId, commentId, result, reason
| filter kind = "audit"
| filter action in ["photo.delete", "photo.update", "comment.delete", "comment.update"]
| sort @timestamp desc
| limit 200
```

## 2. Amplify Hosting 公開

## 前提
- このリポジトリをGitHubへpush済み
- AWS Amplify Consoleで対象リポジトリ接続済み

### 2-1. Amplifyアプリ作成
1. Amplify Console -> New app -> Host web app
2. 対象リポジトリ/ブランチを選択
3. Build settings はリポジトリの `amplify.yml` を利用
4. Deploy

`amplify.yml` は `frontend/` をそのまま配信します。

### 2-2. フロント設定（本番）
`frontend/config.js` に本番値を設定してコミット:

```js
window.KANSA_CONFIG = {
  apiBase: 'https://api.ph4k.aokigk.com',
  photoBucket: 'kansa-backend-photobucket-ufurvgtp4oqi',
};
```

### 2-3. 独自ドメイン + HTTPS
1. Amplify Console -> Domain management -> Add domain
2. 独自ドメイン入力（例: `audit.example.com`）
3. Route 53管理なら自動設定、外部DNSなら表示されるCNAMEを手動追加
4. SSL/TLS証明書はAmplify管理のACMが自動発行
5. ステータスが `Available` になればHTTPS公開完了

## 3. 公開後チェック
- `https://<独自ドメイン>` で画面表示
- フォルダ作成/写真アップ/コメント作成が動作
- CloudWatch Logs Insightsで `kind=audit` が記録される

## 3-1. 出力ファイル保持

- `ExportBucket` に保存される `PDF` `軽量PPT` `高画質PPT` は一時生成物として扱う
- 保持期間は `7日`
- `7日` 経過後は自動削除する想定
- 実装は `S3 Lifecycle` を優先する
- 生成済み出力ファイルは利用容量には含めない

## 4. API custom domain 切替手順
APIを `execute-api` 直URLから独自ドメインへ切り替える手順です。

1. ACM証明書を作成（`ap-northeast-1`、使用ドメイン名）
2. API Gateway (HTTP API) で Custom domain を作成
3. API mapping で `$default` stage を紐付け
4. Route 53 (または外部DNS) で CNAME/ALIAS をCustom domainへ向ける
5. フロント設定 `frontend/config.js` の `apiBase` を独自ドメインURLへ更新
6. フロント再デプロイ（Amplify）
7. 動作確認（フォルダ一覧、作成、PPT出力）
8. 問題なければ `execute-api` endpoint を無効化

### execute-api endpoint 無効化（最後）
- API Gateway の Disable execute-api endpoint を有効化
- この操作後は独自ドメイン経由のみアクセス可能
- 切替ミス時はAPIが全断になるため、必ず手順7の確認後に実施

## 5. API レート制限（即時有効）
- `backend/template.yaml` に API Gateway default route throttling を設定済み
- 既定値:
  - `ApiThrottleRateLimit = 50` (req/sec)
  - `ApiThrottleBurstLimit = 100`
- 変更する場合はデプロイ時にパラメータ上書き:

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa/backend
sam deploy --parameter-overrides ApiThrottleRateLimit=20 ApiThrottleBurstLimit=40
```

## 6. CloudFront + WAF（強化案）
- HTTP APIの`$default`ステージへWAF直接関連付けは制約があるため、
  強いIPレート制限は CloudFront 前段 + WAF(CLOUDFRONT) を推奨。
- 構成:
  1. CloudFront originをAPI Gatewayに設定
  2. WAF (Scope=CLOUDFRONT) でRateBased rule設定
  3. APIはCloudFront経由URLのみフロントで使用
