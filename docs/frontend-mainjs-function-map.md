# frontend/main.js 関数マップ

対象: `frontend/main.js`  
目的: 長い1ファイルでも「どこから読めばいいか」「どの関数がどれを呼ぶか」を素早く把握する。

## 1. 初期化の入口
- エントリーポイント: `initUser()`
- 呼び出し位置: ファイル末尾 `initUser().catch(...)`

初期化の大枠:
1. `initTheme()`
2. 認証情報確認 (`hasCognitoConfig`, `completeLoginFromCallback`, `parseJwt`)
3. ユーザー準備 (`ensureDisplayName`)
4. ルーム解決 (`/invites/accept` または `/team/me`)
5. 画面遷移 (`showRoomSetup` or `showApp`)

## 2. 主要フロー（呼び出し関係）

### 認証・入室
- `initUser`
  - `completeLoginFromCallback`
  - `ensureDisplayName`
  - `api('/invites/accept')`
  - `api('/team/me')`
  - `showRoomSetup` / `showApp`

### アプリ表示
- `showApp`
  - `loadTeamMe`
    - `setAdminUiVisibility`
    - `renderBillingBar`
      - `renderTopStorageGraph`
      - `computeStorageStats`
  - `handleStripePurchaseReturn`
  - `loadFolders`

### 管理画面（お部屋管理）
- `loadAdminPanel`
  - `api('/team/members')`
  - `api('/folders')`
  - `renderStorageGraph`
    - `computeStorageStats`
  - `maybePromptLowStorage`
    - `storagePromptKey`

### 課金（Stripe）
- `startSubscriptionCheckout`
  - `api('/team/subscription/checkout')`
  - 取得URLへ遷移
- `handleStripePurchaseReturn`
  - `api('/team/subscription')`
  - `loadTeamMe`
  - `loadAdminPanel`

### フォルダ・写真
- `loadFolders` -> `renderFolders`
- `selectFolder` -> `loadPhotos` -> `renderPhotos`
- `uploadFiles`
  - `api('/folders/:id/photos/upload-url')`
  - S3 `PUT`
  - `api('/folders/:id/photos')`

## 3. 関数グループ別の責務

### ユーティリティ
- `el`, `formatBytes`, `asMessage`, `safeAction`
- 認証補助: `parseJwt`, `sha256`, `base64UrlEncode`
- 既読管理: `readStateKey`, `getReadState`, `setReadState`, `markAsRead`

### UI制御
- モーダル閉じる系: `closeRoomSwitchModal`, `closeRoomCreateModal`, `closeHelpModal`, `closeLowStorageModal`
- 画面切替: `showAuthSetup`, `showRoomSetup`, `showApp`
- 管理画面表示: `setTeamAdminMode`, `setAdminUiVisibility`
- 容量表示: `renderTopStorageGraph`, `renderBillingBar`, `renderStorageGraph`

### APIラッパー
- `headers`, `folderPasswordHeader`, `api`

### データロード
- `loadTeamMe`, `loadAdminPanel`, `loadMyRooms`, `loadFolders`, `loadPhotos`, `loadComments`

## 4. イベントハンドラ配置の見方
- ファイル後半（`if (els.xxx)` が連続する区間）に UI イベント登録を集約。
- 主要ボタン（例）:
  - `teamAdminBtn` -> `loadAdminPanel`
  - `purchase-xxx` -> `purchaseSku`
  - `uploadBtn` -> `uploadFiles`
  - `createFolderBtn` -> フォルダ作成API

## 5. 変更時の読む順番（推奨）
1. `initUser`
2. `showApp`
3. 変更対象に応じて以下を読む
   - 課金UI: `renderBillingBar`, `renderStorageGraph`, `maybePromptLowStorage`, `purchaseSku`, `handleStripePurchaseReturn`
   - 管理画面: `loadAdminPanel`
   - 投稿系: `uploadFiles`, `loadPhotos`, `renderPhotos`

## 6. 注意点
- `main.js` は1ファイル集約のため、副作用点（`state` 更新）を先に追うと理解が速い。
- 課金反映は `handleStripePurchaseReturn` と `loadTeamMe` の両方を確認する。
- UI表示だけ変える場合でも、`state.uploadBlocked` と `state.billing` の更新元は必ず確認する。
