# Cong | Container Log

Congは、港湾・物流の現場でコンテナ写真を記録・整理・共有するためのWebアプリです。

Cognito認証（MFA）で利用者を管理し、コンテナ番号ごとの写真アップロード、作業タグ、コメント、検索、クエスト形式の撮影依頼、PDF・PowerPoint出力に対応します。

## License

本リポジトリは `All rights reserved` です。  
著作権者の事前書面許可なしに、利用・複製・改変・再配布することを禁止します。詳細は `LICENSE` を参照してください。

## システム構成

- Frontend: `frontend/`（静的SPA）
- Backend: `backend/`（AWS SAM: Lambda + API Gateway + DynamoDB + S3）
- Authentication: Amazon Cognito
- Hosting: AWS Amplify Hosting または S3 Static Website Hosting
- Billing: Stripe（有料プランを利用する場合）

画面上では記録単位を「コンテナ」「コンテナ番号」と表記します。実装コストと既存データとの互換性を保つため、内部の変数名、APIパス、DynamoDBキーには `folder` が残っています。

## 主な機能

### お部屋とメンバー

- 企業・事業所単位で「お部屋」を作成
- 管理者が発行する招待URLからメンバーが参加
- 招待URLの有効期間は7日間
- 管理者によるメンバー、権限、コンテナの管理

### コンテナ記録

- コンテナ番号を記録単位として登録（例: `TCLU1234567`）
- 通常記録とクエスト記録の2モード
- コンテナ単位の任意パスワード設定
- 写真の複数同時アップロード
- 写真ごとのコメント追加

### 写真タグ

写真には次のタグを1つ設定します。

- コンテナ番号
- 搬入
- 搬出
- シール
- 損傷
- その他

タグの初期値は「コンテナ番号」です。写真名は利用者が入力せず、`コンテナ番号_タグ名_3桁連番` の形式で自動生成されます。

例:

```text
TCLU1234567_コンテナ番号_001
TCLU1234567_搬入_001
TCLU1234567_損傷_001
```

保存済み写真のタグは、写真の作成者または管理者が変更できます。変更時は写真名も再生成され、変更内容は監査ログへ記録されます。

### 検索と出力

- 現在のコンテナ内または現在のお部屋全体を検索
- タグ、コンテナ番号、コメント、投稿者による絞り込み
- コンテナ単位でPDF、軽量PowerPoint、高画質PowerPointを出力
- クエスト記録では完了済みクエストの写真を出力

### 権限

- 写真、コメント、クエストの作成者は自分の投稿を削除可能
- 管理者はお部屋内の投稿とコンテナを管理可能
- コンテナごとにメンバーの閲覧範囲を制御可能

## 基本的な利用フロー

1. `ログイン` からCognito Hosted UIへ移動してサインイン
2. 初回ログイン時に表示名を登録
3. 管理者がお部屋を作成、またはメンバーが招待URLから参加
4. コンテナ番号と記録モードを指定してコンテナを登録
5. 写真ごとにタグを選択してアップロード
6. 必要に応じてコメント、タグ検索、クエストを利用
7. コンテナ単位でPDFまたはPowerPointを出力

利用者向けの詳細手順は `docs/user-guide.md` を参照してください。

## Backendデプロイ

### 前提

- AWS CLI
- AWS SAM CLI
- Node.js
- デプロイ先AWSアカウントへの権限

### 最短デプロイ

リポジトリルートで次を実行します。

```bash
./scripts/deploy_backend.sh
```

このスクリプトは、Backend依存関係のインストール、`sam build`、`sam deploy` を実行します。完了後、動作確認用としてブラウザコンソールへ設定できる `localStorage.setItem(...)` が表示されます。

開発環境へデプロイする場合は、設定環境とスタック名を指定します。

```bash
SAM_CONFIG_ENV=dev STACK_NAME=kansa-backend-dev ./scripts/deploy_backend.sh
```

### Stripeを有効にする場合

Stripeの秘密値はリポジトリへコミットせず、デプロイ時に環境変数で渡します。

```bash
STRIPE_SECRET_KEY=sk_test_... \
STRIPE_WEBHOOK_SECRET=whsec_... \
./scripts/deploy_backend.sh
```

秘密値を指定しない場合、スクリプトは警告を表示してStripeなしでデプロイします。

### 手動デプロイ

`backend/samconfig.toml` を使うため、通常は `--guided` は不要です。

```bash
cd backend
npm --prefix src install
sam build
sam deploy
```

より詳しい手順は `docs/production-ops.md`、会社PCでの初期構築は `docs/company-pc-setup.md` を参照してください。

## Frontend配信

`amplify.yml` は `frontend/` を配信対象に設定しています。AWS Amplify Hostingを利用する場合は、リポジトリを接続してデプロイしてください。S3 Static Website Hostingへ `frontend/` を配置する構成も利用できます。

本番・開発環境の接続先は `frontend/config.js` で設定します。

- `apiBase`
- `photoBucket`
- `cognitoRegion`
- `cognitoDomain`
- `cognitoClientId`
- `cognitoRedirectUri`

Backendデプロイ後、CloudFormation Outputsの次の値を設定へ反映します。

- `ApiUrl`
- `PhotoBucketName`
- `CognitoHostedUiDomain`
- `CognitoUserPoolClientId`

## API認証

APIは原則として次のヘッダーを必須とします。

```http
Authorization: Bearer <Cognito ID Token>
```

パスワード付きコンテナへアクセスする場合は、Frontendがコンテナパスワードを追加ヘッダーで送信します。

## 既存データのコード補完

既存データで `F---` / `P---` 表示になる項目を補完するための一回限りの処理です。必要な環境でのみ実行してください。

まず最新のBackendをデプロイします。

```bash
./scripts/deploy_backend.sh
```

変更予定を確認します。

```bash
./scripts/run_backfill_codes.sh kansa-backend dry-run
```

内容を確認後、実際に更新します。

```bash
./scripts/run_backfill_codes.sh kansa-backend apply
```

処理後は画面を再読み込みしてください。

## 監視とアラート

本番環境では、CloudWatch AlarmからSNSメール通知を送信します。

- `Lambda Errors`: 5分間に1回以上
- `Lambda Throttles`: 5分間に1回以上
- `API 5XXError`: 5分間に1回以上
- `API 4XXError`: 5分間に50回以上

API Gatewayのスロットリングによる `429` は、4XXエラーのしきい値に達した場合に通知対象となります。

## セキュリティ上の注意

コンテナパスワードは、アクセス中のブラウザからAPIへ送信されます。漏えいすると対象コンテナへアクセスされる可能性があるため、定期的な変更と、必要に応じたWAF・IP制限を併用してください。

本番運用、監査ログ、独自ドメイン、レート制限の詳細は `docs/production-ops.md` を参照してください。
