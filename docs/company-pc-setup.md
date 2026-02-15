# 会社PCセットアップ手順（kansa）

Amazon Q でもそのまま使えるように、最短の実行手順だけまとめています。

## 1. 前提ツール確認

```bash
git --version
node -v
npm -v
aws --version
sam --version
```

## 2. リポジトリ取得

```bash
git clone https://github.com/intK-bell/kansa.git
cd kansa
```

## 3. AWS認証（会社アカウント）

```bash
aws configure --profile company
aws sts get-caller-identity --profile company
```

## 4. Backendデプロイ（会社AWS）

```bash
cd backend
sam deploy --profile company
```

- `samconfig.toml` の設定でデプロイされます。
- 完了後、CloudFormation Outputs の以下を控えてください。
  - `ApiUrl`
  - `PhotoBucketName`
  - `CognitoHostedUiDomain`
  - `CognitoUserPoolClientId`

## 5. Frontend設定（会社環境）

`frontend/config.js` を会社環境の値に変更します。

```js
window.KANSA_CONFIG = {
  apiBase: 'https://<会社のAPI-ID>.execute-api.ap-northeast-1.amazonaws.com',
  photoBucket: '<会社のPhotoBucketName>',
  cognitoRegion: 'ap-northeast-1',
  cognitoDomain: '<CognitoHostedUiDomainのprefix部分>',
  cognitoClientId: '<CognitoUserPoolClientId>',
  cognitoRedirectUri: 'https://<公開URL>',
};
```

## 6. Frontend公開（Amplify）

- AmplifyでGitHub連携済み: `main` へpushで自動反映
- 連携未設定: Amplify Consoleで `kansa` リポジトリの `main` を接続してDeploy

## 7. 動作確認

1. フォルダ作成
2. 写真アップロード
3. コメント追加/修正/削除
4. PPT出力（画像比率維持）

## 8. 監査ログ確認（任意）

CloudWatch Logs Insights:

```sql
fields @timestamp, action, actorName, actor, folderId, photoId, commentId, result
| filter kind = "audit"
| sort @timestamp desc
| limit 100
```

## 日常の更新フロー

```bash
git add .
git commit -m "feat: xxx"
git push origin main
```

- Backend変更あり: `cd backend && sam deploy --profile company`
- Frontendのみ: pushでAmplify反映（連携済みの場合）
