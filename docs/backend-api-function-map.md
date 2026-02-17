# backend/src/api.js 関数マップ

対象: `backend/src/api.js`  
目的: 長い `api.js` の「全体構造」「入口」「主要依存」を短時間で把握できるようにする。

## 1. エントリーポイント
- `exports.handler`

処理の大枠:
1. `getUser(event)` でユーザー解決
2. ルーム不要エンドポイントを先に分岐
3. ルーム必須エンドポイントは `resolveRoomForRequest` + `requireActiveMember` を通す
4. 各 handler に委譲
5. 共通エラーを `401/403/400/500` に正規化

## 2. 主要ドメイン別の関数群

### 認証・ユーザー
- `getUserIdentity`, `ensureUserProfile`, `getUser`
- `getMe`, `updateDisplayName`

### ルーム解決・メンバーシップ
- `resolveActiveRoomForUser`, `listUserRoomMemberships`, `setActiveRoomForUser`
- `resolveRoomForRequest`
- `ensureRoomMember`, `requireActiveMember`
- `roomMemberKey`, `userRoomMemberKey`, `userRoomConstraintKey`
- `normalizeFolderScope`, `normalizeMemberStatus`, `isAdminRole`

### 招待
- `makeInviteToken`
- `createInvite`, `revokeInvite`, `acceptInvite`

### チーム/課金
- `teamMe`, `teamMeAuto`, `teamBilling`
- サブスク: `teamSubscription`, `teamSubscriptionCheckout`, `changeTeamSubscription`, `applyPendingSubscriptionIfDue`
- Stripe連携: `stripeGetSubscription`, `stripeUpdateSubscriptionPlan`, `stripeSetCancelAtPeriodEnd`
- メンバー管理: `listTeamMembers`, `updateTeamMember`, `teamLeave`, `teamDelete`
- 補助: `isUploadBlocked`

### フォルダ/写真/コメント
- フォルダ: `listFolders`, `createFolder`, `deleteFolder`, `updateFolderPassword`
- 写真: `listPhotos`, `createUploadUrl`, `finalizePhoto`, `deletePhoto`, `updatePhoto`
- コメント: `listComments`, `createComment`, `deleteComment`, `updateComment`
- エクスポート: `exportFolder`

### 削除・クリーンアップ
- `deleteAllByPk`, `deleteAllCommentsForPhoto`, `purgePhotoByItem`, `deleteS3Prefix`

### 共通ユーティリティ
- パスワード: `hashRoomPassword`, `verifyRoomPassword`, `verifyFolderPassword`
- 名前/文言: `normalizeDisplayName`, `decodeText`
- 監査: `auditLog`

## 3. 依存関係の要点（読む順）
1. `exports.handler`
2. `getUser` / `resolveRoomForRequest` / `requireActiveMember`
3. 変更対象の handler 本体
4. 削除系変更時は `purgePhotoByItem` と課金更新ロジックも確認

## 4. 入口分岐の実務ポイント
- ルーム不要:
  - `/me`
  - `/me/display-name`
  - `/team/me`
  - `/rooms/mine`
  - `/rooms/switch`
  - `/invites/accept`
  - `/rooms/create`
- それ以外はルーム必須（active membership が前提）

## 5. 変更時の注意
- `teamDelete` と `deleteFolder` はデータ削除影響が広いので、関連S3削除・課金メタ削除・監査ログまでセットで確認する。
- `uploadBlocked` の条件は `isUploadBlocked` を唯一の判断源に寄せる（フロント側で独自判定を増やさない）。
- 課金挙動を変えるときは `teamSubscriptionCheckout` / `changeTeamSubscription` / webhook 側実装（`backend/src/stripe-webhook.js`）を同時に確認する。
