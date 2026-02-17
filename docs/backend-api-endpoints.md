# backend/src/api.js エンドポイント対応表

対象: `backend/src/api.js` の `exports.handler` 分岐  
目的: `method + path` から handler と前提条件を即把握する。

## 1. ルーム不要エンドポイント

| Method | Path | Handler | 備考 |
|---|---|---|---|
| GET | `/me` | `getMe` | ログインユーザー情報 |
| PUT | `/me/display-name` | `updateDisplayName` | 表示名更新 |
| GET | `/team/me` | `teamMeAuto` | active room 自動解決 |
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

### フォルダ
| Method | Path | Handler |
|---|---|---|
| GET | `/folders` | `listFolders` |
| POST | `/folders` | `createFolder` |
| DELETE | `/folders/{folderId}` | `deleteFolder` |
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

## 4. 参照ドキュメント
- 関数構造: `docs/backend-api-function-map.md`
- フロント関数構造: `docs/frontend-mainjs-function-map.md`
- 料金方針（サブスク）: `docs/billing-subscription-spec.md`
