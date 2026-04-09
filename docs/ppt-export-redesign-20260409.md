# PPT出力デザイン共通化・デプロイ記録 (2026-04-09)

## 概要
- デモ用PPTで作成した新レイアウトを、本番PPT出力にも適用できるよう共通化した。
- デモ画面の種データと、デモ用PPT生成の元データを共通化した。
- バックエンドを再デプロイし、独自APIドメインの疎通を確認した。

## 実装内容
- `backend/src/ppt-layout.js` を追加
  - 写真配置
  - コメントカード
  - フッター
  - フリープラン透かし
  を共通レイアウトとして切り出した。
- `backend/src/api.js`
  - `exportFolder` が `ppt-layout.js` を使ってPPTを生成するよう変更した。
- `frontend/demo-seed.mjs`
  - `demo.js` と `generate_demo.js` が同じデータを使うようにした。
- `frontend/generate_demo.js`
  - 共通種データから `frontend/demo-assets/demo-export-sample.pptx` を再生成できるようにした。
- `frontend/demo.js`
  - デモAPIの固定PPT参照は `frontend/demo-assets/demo-export-sample.pptx` を返すまま維持。

## 生成物
- デモ用PPT: `frontend/demo-assets/demo-export-sample.pptx`
- 再生成コマンド:

```bash
node frontend/generate_demo.js
```

## デプロイ結果
- 実行日: 2026-04-09
- 対象スタック: `kansa-backend`
- 結果: `UPDATE_COMPLETE`

CloudFormation Outputs:

- `ApiUrl`: `https://0nhz8sat7j.execute-api.ap-northeast-1.amazonaws.com`
- `PhotoBucketName`: `kansa-backend-photobucket-ufurvgtp4oqi`
- `ExportBucketName`: `kansa-backend-exportbucket-fwycsdeaagxq`
- `CognitoHostedUiDomain`: `https://photohub4kansa.auth.ap-northeast-1.amazoncognito.com`
- `CognitoUserPoolClientId`: `nlpccd2h79jr93rejmiv35eci`

## APIドメイン確認
本番運用上のAPIは `frontend/config.js` に合わせて `https://api.ph4k.aokigk.com` を使う前提。

確認結果:

- `https://api.ph4k.aokigk.com`
  - HTTP status: `404`
  - remote IP: `13.158.124.21`
- `https://0nhz8sat7j.execute-api.ap-northeast-1.amazonaws.com`
  - HTTP status: `404`
  - remote IP: `54.248.116.46`

補足:

- root (`/`) 直叩きで `404` になるのは想定内。
- 独自ドメイン側もHTTP応答しており、API Gateway 側へ向いていることは確認できた。
- 実機能の最終確認は、認証後にフォルダ一覧・写真表示・PPT出力で行う。

## 注意
- 今回のデプロイは `STRIPE_SECRET_KEY` と `STRIPE_WEBHOOK_SECRET` を明示指定せず実行した。
- Stripe系設定まで確実に反映確認したい場合は、必要な秘密値を渡して再デプロイする。
- 現運用では Stripe 秘密値は Lambda 側で管理済みのため、今回のPPT出力デザイン共通化に関してはこの点は実運用上のブロッカーではない。
