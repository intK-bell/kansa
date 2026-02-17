# frontend/main.js 関数マップ

対象: `frontend/main.js`  
更新日: 2026-02-18  
目的: 長い単一ファイルの読み順と、主要機能ごとの関数関係を素早く把握する。

## 1. 入口と全体像
- エントリーポイント: `initUser()`
- 主な遷移:
1. `initTheme()`
2. 認証復元 (`completeLoginFromCallback`, `parseJwt`)
3. ユーザー準備 (`ensureDisplayName`)
4. ルーム解決 (`/invites/accept` または `/team/me`)
5. `showRoomSetup()` か `showApp()`

## 2. 主要フロー

### 認証/起動
- `initUser`
- `showAuthSetup`
- `showRoomSetup`
- `showApp`

### ルーム切替/入室
- `openRoomSwitchModal`
- `renderMyRooms`
- `loadMyRooms`
- `createRoomAndEnter`

### 課金/容量表示
- `computeStorageStats`
- `renderTopStorageGraph`
- `renderBillingBar`
- `renderStorageGraph`
- `syncSubscriptionPlanButtons`
- `maybePromptLowStorage`
- `startSubscriptionCheckout`
- `handleStripePurchaseReturn`

### 管理画面
- `loadAdminPanel`
  - `/team/members`, `/folders` 読み込み
  - フォルダ容量表示 (`usageBytes`)
  - 容量グラフ/ステータス更新

### アカウント削除ガード（最新）
- `getOwnedRoomForGuard`
  - `/rooms/mine` から「作成者として所有する部屋」を判定
- `showOwnerDeleteGuard`
  - 作成部屋にいる場合: 「このお部屋を削除（全データ）」案内
  - 別部屋にいる場合: confirmで作成部屋へ移動提案
- `accountDeleteBtn` ハンドラ
  - 所有部屋チェック -> ブロック
  - 問題なければ二重確認 -> `/account/delete`

### 投稿/写真
- `loadFolders` -> `renderFolders`
- `selectFolder` / `selectFolderById`
- `loadPhotos` -> `renderPhotos`
- `uploadFiles`
- `loadComments`

## 3. APIラッパ
- `headers(method)`
- `folderPasswordHeader(folderId)`
- `api(path, options)`

## 4. 状態更新の起点
- `loadTeamMe()` が `state.billing`, `state.isAdmin`, `state.uploadBlocked`, `state.ownerUserKey` を更新
- 表示系は基本 `loadTeamMe` の結果を元に再描画
- ルーム切替直後は `resetRoomContext()` -> `showApp()` で再同期

## 5. イベント定義の場所
- ファイル後半の `if (els.xxx) { ... }` にボタン処理を集約
- 重要ハンドラ:
  - `deleteTeamBtn`: `/team/delete`
  - `accountDeleteBtn`: `/account/delete`（二重確認あり）
  - `subscribe*Btn`: `/team/subscription/checkout`
  - `subscribeFreeBtn`: `/team/subscription/change` (`action: free`)

## 6. 変更時の読む順（推奨）
1. `initUser`
2. `showApp`
3. `loadTeamMe`
4. 変更対象ごとの入口
   - 課金: `renderBillingBar` / `computeStorageStats` / `syncSubscriptionPlanButtons`
   - 管理画面: `loadAdminPanel`
   - アカウント削除: `getOwnedRoomForGuard` / `showOwnerDeleteGuard` / `accountDeleteBtn` ハンドラ
