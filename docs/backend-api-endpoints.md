# backend/src/api.js エンドポイント対応表

対象: `backend/src/api.js` の `exports.handler` 分岐  
目的: `method + path` から handler と前提条件を即把握する。

## 0. ユーザー/メンバー方針

- 永続的なユーザーキーは Cognito ID token の `sub` を使う。メールアドレスは表示・連絡用であり、DB主キーには使わない。
- ユーザー種別は分けない。Cognitoユーザーに対して、部屋ごとの `role` / `folderScope` / `folderIds` で権限を表現する。
- `role=admin`: 部屋管理者。常に全フォルダを閲覧できる。
- `role=member` + `folderScope=all`: お部屋招待メンバー。全フォルダを閲覧できる。
- `role=member` + `folderScope=own`: 自分が作成したフォルダを閲覧できる。
- `role=member` + `folderScope=invited`: フォルダ招待メンバー。`folderIds` に含まれるフォルダだけ閲覧できる。
- 1つのお部屋内では、ユーザーの立場は `admin` / お部屋メンバー / フォルダメンバーのどれか1つだけとする。
- お部屋メンバーはお部屋管理でだけ削除する。フォルダ管理では削除しない。
- フォルダメンバーは対象フォルダの管理でだけ外す。お部屋メンバー一覧では削除対象にしない。
- フォルダメンバーをフォルダから外す操作は、対象 `folderId` を `folderIds` から外す。残り `folderIds` が空になった場合は `status=left` としてお部屋からも外す。
- 既にお部屋メンバーのユーザーがフォルダ招待を受けた場合、お部屋メンバーのまま扱う。`folderScope=all` は変更せず、`folderScope=own` は対象フォルダを `folderIds` に追加して閲覧可能にする。
- フォルダメンバーが お部屋招待を受けた場合、お部屋メンバーへ昇格する。`folderScope=all` に変更し、`folderIds` は空にする。
- メンバー削除は物理削除ではなく `status=left` として保持する。再招待された場合は `active` に戻して再参加できる。
- `ROOM#... / MEMBER#...` は部屋からメンバーを引くため、`USER#... / ROOMMEMBER#...` はユーザーから所属部屋/active部屋を引くための逆引きとして使う。

## 1. ルーム不要エンドポイント

| Method | Path | Handler | 備考 |
|---|---|---|---|
| GET | `/me` | `getMe` | ログインユーザー情報 |
| PUT | `/me/display-name` | `updateDisplayName` | 表示名更新 |
| GET | `/team/me` | `teamMeAuto` | active room 自動解決 |
| POST | `/account/delete` | `accountDelete` | アカウント削除（作成者は先に部屋削除必須） |
| GET | `/rooms/mine` | `listMyRooms` | 所属ルーム一覧 |
| POST | `/rooms/switch` | `switchActiveRoom` | active room 切替 |
| POST | `/invites/accept` | `acceptInvite` | 招待受諾 |
| POST | `/rooms/create` | `createRoom` | ルーム作成（特別分岐） |

## 2. ルーム必須エンドポイント

前提: `resolveRoomForRequest` + `requireActiveMember` 通過後に実行。

### 招待
| Method | Path | Handler |
|---|---|---|
| POST | `/invites/create` | `createInvite` |
| POST | `/invites/revoke` | `revokeInvite` |

補足:
- `POST /invites/create` は body に `folderId` を渡すとフォルダ招待URLを発行する。
- フォルダ招待URLで参加したメンバーは、対象フォルダのみ閲覧できる。

### チーム/課金
| Method | Path | Handler |
|---|---|---|
| GET | `/team/billing` | `teamBilling` |
| GET | `/team/subscription` | `teamSubscription` |
| POST | `/team/subscription/checkout` | `teamSubscriptionCheckout` |
| POST | `/team/subscription/change` | `changeTeamSubscription` |
| GET | `/team/members` | `listTeamMembers` |
| PUT | `/team/members/{userKey}` | `updateTeamMember` |
| POST | `/team/leave` | `teamLeave` |
| POST | `/team/delete` | `teamDelete` |

補足:
- `GET /team/members` は管理画面表示用として `left` と `folderScope=invited` のメンバーを返さない。お部屋メンバー一覧には管理者とお部屋メンバーだけを返す。
- `GET /team/members` の `userKey` は、管理画面から `PUT /team/members/{userKey}` に渡す更新用キーとして返す。
- `PUT /team/members/{userKey}` の削除操作は `status:left` 更新であり、監査・再招待のためメンバー情報は残す。
- `folderScope=invited` かつ複数 `folderIds` を持つフォルダメンバーは、`PUT /team/members/{userKey}` の `status:left` では削除しない。必ず `DELETE /folders/{folderId}/members/{userKey}` を使う。
- 古いメンバー item で `userKey` 属性と `MEMBER#...` キーが一致しない場合は、`userKey` から同じ部屋の item を引き直して更新する。
- DynamoDB の更新では `status` を予約語衝突回避のため `#status` で指定する。

### フォルダ
| Method | Path | Handler |
|---|---|---|
| GET | `/folders` | `listFolders` |
| POST | `/folders` | `createFolder` |
| GET | `/folders/{folderId}/members` | `listFolderMembers` |
| DELETE | `/folders/{folderId}/members/{userKey}` | `removeFolderMember` |
| DELETE | `/folders/{folderId}` | `deleteFolder` |

補足:
- `GET /folders/{folderId}/members` はフォルダ管理用として、対象フォルダに紐づく `folderScope=invited` のフォルダメンバーだけを返す。
- `DELETE /folders/{folderId}/members/{userKey}` はフォルダメンバーだけを対象にし、対象 `folderId` を `folderIds` から外す。残りが空の場合のみ `status=left` にする。
| PUT | `/folders/{folderId}/password` | `updateFolderPassword` |

### 写真
| Method | Path | Handler |
|---|---|---|
| GET | `/folders/{folderId}/photos` | `listPhotos` |
| POST | `/folders/{folderId}/photos/upload-url` | `createUploadUrl` |
| POST | `/folders/{folderId}/photos` | `finalizePhoto` |
| DELETE | `/photos/{photoId}` | `deletePhoto` |
| PUT | `/photos/{photoId}` | `updatePhoto` |

### コメント
| Method | Path | Handler |
|---|---|---|
| GET | `/photos/{photoId}/comments` | `listComments` |
| POST | `/photos/{photoId}/comments` | `createComment` |
| DELETE | `/photos/{photoId}/comments/{commentId}` | `deleteComment` |
| PUT | `/photos/{photoId}/comments/{commentId}` | `updateComment` |

### エクスポート
| Method | Path | Handler |
|---|---|---|
| POST | `/folders/{folderId}/export` | `exportFolder` |

## 3. 共通エラーマッピング

| 条件 | 返却 |
|---|---|
| `MISSING_USER_KEY` | `401 unauthorized` |
| `MISSING_ROOM` | `403 no active room` |
| `INVALID_ROOM` | `403 invalid room credentials` |
| `INVALID_DISPLAY_NAME_LENGTH` | `400 bad request` |
| その他未処理例外 | `500 internal server error` |

## 4. 仕様メモ（2026-02-18時点）
- `POST /team/subscription/change` の `action`:
  - `upgrade`, `downgrade`, `cancel`, `resume`, `free`
- `POST /account/delete`:
  - 作成者で部屋が残っている場合: `400 {"message":"room owner must delete team first"}`
  - メンバーの場合: USER配下データ削除 + Cognitoユーザー削除

## 5. 参照ドキュメント
- 関数構造: `docs/backend-api-function-map.md`
- フロント関数構造: `docs/frontend-mainjs-function-map.md`
- 料金方針（サブスク）: `docs/billing-subscription-spec.md`
