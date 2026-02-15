# 本番運用手順（監査ログ / Amplify公開）

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

`amplify.yml` は `frontend/` を `dist/` にコピーして配信します。

### 2-2. フロント設定（本番）
`frontend/config.js` に本番値を設定してコミット:

```js
window.KANSA_CONFIG = {
  apiBase: 'https://0nhz8sat7j.execute-api.ap-northeast-1.amazonaws.com',
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
