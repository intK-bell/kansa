# Kansa (監査写真コメントアプリ)

Cognito認証（MFA）で利用者を管理し、写真アップロード・コメント・本人のみ削除・フォルダ単位PowerPoint出力を行う構成です。

## License
本リポジトリは `All rights reserved` です。  
著作権者の事前書面許可なしに、利用・複製・改変・再配布を禁止します。詳細は `LICENSE` を参照してください。

## 構成
- Frontend: `frontend/` (静的SPA)
- Backend: `backend/` (AWS SAM: Lambda + API Gateway + DynamoDB + S3)

## 最短デプロイ
前提: AWS CLI / SAM CLI / Node.js

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa
./scripts/deploy_backend.sh
```

これで backend の `npm install / sam build / sam deploy` まで完了し、
最後にブラウザコンソールへ貼る `localStorage.setItem(...)` が表示されます。

## 手動デプロイ（必要時のみ）
`backend/samconfig.toml` を使うため、`--guided` は不要です。

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa/backend
npm --prefix src install
sam build
sam deploy
```

## 既存データコード補完（1回実行）
既存データで `F---` / `P---` 表示になるものを補完します。

1. まず最新デプロイ

```bash
cd /Users/aokikensaku/Documents/Devapps/kansa
./scripts/deploy_backend.sh
```

2. dry-run（変更予定のみ確認）

```bash
./scripts/run_backfill_codes.sh kansa-backend dry-run
```

3. apply（実際に更新）

```bash
./scripts/run_backfill_codes.sh kansa-backend apply
```

補完後は画面を再読み込みしてください。

## Frontend 配信
`frontend/` を Amplify Hosting か S3 Static Hosting に配置してください。

本番値は `frontend/config.js` で設定できます（`apiBase`, `photoBucket`）。
運用手順は `docs/production-ops.md` を参照してください。
会社PCでの初期構築は `docs/company-pc-setup.md` を参照してください。

### Cognito設定
`backend` デプロイ後、CloudFormation Outputs の以下を `frontend/config.js` に設定してください。
- `CognitoHostedUiDomain` からドメインプレフィックス
- `CognitoUserPoolClientId`
- リージョン（例: `ap-northeast-1`）

## 利用フロー
1. 初回はニックネーム入力（`localStorage`に`user_key`と`user_name`保存）
2. フォルダ作成（例: `〇〇工場_20260214`）
3. 写真を複数アップロード
4. 写真ごとにコメント追加
5. 自分が作成した写真/コメントのみ削除可
6. フォルダ単位でPowerPoint出力

利用者向けの詳細手順は `docs/user-guide.md` を参照してください。

## APIヘッダ
APIは `Authorization: Bearer <Cognito ID Token>` を必須とします。

## アラート通知（いつメールが来るか）
本番ではSNSメール通知で以下のCloudWatch Alarmが発報した時にメールが届きます。
注意: API Gatewayのスロットリングで `429` になっても、必ずしもこのメール通知に直結はしません（4XXのしきい値次第）。

- `Lambda Errors`（5分間に1回以上）
  - 例: Lambda内で例外が発生して `500 internal server error` を返した
  - 例: DynamoDB/S3権限不足、SDKエラー、JSON parse失敗などで処理が落ちた
- `Lambda Throttles`（5分間に1回以上）
  - 例: 同時実行が上限に当たってLambdaがスロットルされた（大量アクセス時）
- `API 5XXError`（5分間に1回以上）
  - 例: Lambdaが `500` を返した、または統合エラーが発生した
- `API 4XXError`（5分間に50回以上）
  - 例: 不正な部屋名/パスワードで `403` が短時間に大量発生
  - 例: 権限エラー `403` やリクエスト不備 `400` が短時間に集中

## 注意
ルームパスワードはクライアント保持のため、漏えい時は同一ルームへのアクセスが可能です。定期変更とアクセス制限（WAF/IP制限）を併用してください。
