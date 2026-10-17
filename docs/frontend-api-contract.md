# Frontend API Adapter Contract

更新日: 2026-08-11  
状態: Phase 2 / Batch 4で契約定義、adapter実装は次Batchから

## 目的

共通UIからHTTPパスとデモ用ストア操作を隠し、本番・デモを同じ意味APIで動かす。

契約の正本は`frontend/app-api-contract.js`の`APP_API_METHODS`とする。この文書は責務、既存経路、環境差分を説明する。

## 境界

```text
共通UI
  ↓ 意味API（getTeam / listFolders / uploadPhoto ...）
App API Contract
  ├─ api-live.js: HTTP・Cognito・Stripe
  └─ api-demo.js: インメモリストア・サンプル出力
```

共通UIは、`/folders`などのURL、HTTPメソッド、認証ヘッダー、デモストアの構造を参照しない。

## 操作グループ

| グループ | 操作 | 現在の主なBackend経路 |
|---|---|---|
| 利用者 | `getCurrentUser`, `saveDisplayName` | `GET /me`, `PUT /me/display-name` |
| ルーム | `listRooms`, `switchRoom`, `createRoom` | `/rooms/mine`, `/rooms/switch`, `/rooms/create` |
| チーム | `getTeam`, `listTeamMembers`, `updateTeamMember`, `leaveTeam`, `deleteTeam` | `/team/*` |
| アカウント | `deleteAccount` | `POST /account/delete` |
| コンテナ | `listFolders`, `createFolder`, `deleteFolder`, `setFolderPassword` | `/folders/*` |
| コンテナ権限 | `listFolderMembers`, `removeFolderMember` | `/folders/:id/members` |
| 写真 | `listPhotos`, `searchPhotos`, `uploadPhoto`, `updatePhoto`, `deletePhoto` | `/folders/:id/photos*`, `/rooms/:id/photos/search`, `/photos/:id` |
| 写真コメント | `listPhotoComments`, `createPhotoComment`, `updatePhotoComment`, `deletePhotoComment` | `/photos/:id/comments*` |
| クエスト | `listQuests`, `createQuest`, `updateQuest`, `deleteQuest` | `/folders/:id/quests`, `/quests/:id` |
| クエストコメント | `createQuestComment`, `deleteQuestComment` | `/quests/:id/comments*` |
| 招待 | `createInvite`, `acceptInvite`, `revokeInvite` | `/invites/*` |
| 課金 | `getSubscription`, `startSubscriptionCheckout`, `changeSubscription` | `/team/subscription*` |
| 出力 | `exportFolder` | `/folders/:id/export` |

## 環境固有動作

### 本番adapter

- IDトークンとコンテナパスワードをヘッダーへ付与する。
- 401時は認証状態を破棄し、403の`no active room`時はルーム状態を初期化する。
- 写真アップロードでは署名付きURLへバイナリを送信する。
- 課金・出力でBackendまたはStripeから返されたURLを扱う。
- 開発者ダッシュボードは共通契約に含めず、本番featureとして分離する。

### デモadapter

- 外部Backendへ通信しない。
- `demo-seed.mjs`のストアを操作し、本番と同じレスポンス形へ変換する。
- ルーム横断写真検索はデモストア内で実行する。
- 課金変更はデモ状態だけを更新する。
- 出力は`demo-assets`の既存サンプルを返す。

## 移行規則

1. 既存の`api(path, options)`呼び出しを、機能単位で意味APIへ置き換える。
2. 1 Batchにつき1グループを移行する。
3. 本番・デモadapterの両方を実装してから共通UI側を切り替える。
4. 切替済み経路をデモ後半の巨大な`api`上書きから削除する。
5. 各Batchでadapter契約テスト、共通関数テスト、構文、HTML同期を確認する。

## 移行順

1. 利用者・ルーム（依存が小さく初期表示で確認しやすい）
2. コンテナ一覧・選択
3. 写真・コメント
4. クエスト
5. 検索・出力
6. チーム管理・招待・課金
7. 認証と起動処理
