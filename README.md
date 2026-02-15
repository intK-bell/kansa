# Kansa (監査写真コメントアプリ)

localStorageベースの利用者管理で、写真アップロード・コメント・本人のみ削除・フォルダ単位PowerPoint出力を行う構成です。

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

## 利用フロー
1. 初回はニックネーム入力（`localStorage`に`user_key`と`user_name`保存）
2. フォルダ作成（例: `〇〇工場_20260214`）
3. 写真を複数アップロード
4. 写真ごとにコメント追加
5. 自分が作成した写真/コメントのみ削除可
6. フォルダ単位でPowerPoint出力

## APIヘッダ
POST/DELETE時は以下ヘッダ必須:
- `x-user-key`
- `x-user-name`

## 注意
この方式は`localStorage`値を書き換え可能なため、厳密な本人性保証はできません。監査要件が厳しい場合はCognito等の認証導入を推奨します。
