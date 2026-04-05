# backend/src/api.js 関数マップ

対象: `backend/src/api.js`  
更新日: 2026-04-05  
目的: `api.js` の関数をざっくり棚卸しして、あとで目次コメントや分割単位を決めやすくする。

## 1. 見方
- 行番号は関数定義の開始位置。
- 役割ごとにゆるくまとめている。厳密なアーキテクチャ境界ではない。
- `exports.handler` の分岐詳細は `docs/backend-api-endpoints.md` と合わせて見る前提。

## 2. 共通レスポンス・日付・小物ユーティリティ
- `58: getHeaderValue`
- `66: resolveCorsOrigin`
- `71: applyCorsHeaders`
- `83: json`
- `91: badRequest`
- `95: formatJstCompactTimestamp`
- `109: formatJstDisplayDateTime`
- `126: sanitizeDownloadFileName`
- `136: planRank`
- `240: isBillingCycleDue`
- `246: nextBillingBoundaryIsoJst`
- `302: auditLog`
- `312: isConditionalCheckFailed`
- `955: pad3`
- `1429: isoFromUnixSec`

## 3. フリープラン制約・課金補助
- `142: countRoomFolders`
- `157: freePlanConstraintSummary`
- `173: freePlanConstraintMessage`
- `184: isFreePlanBilling`
- `218: isPhotoArchivedForFreePlan`
- `224: splitArchivedPhotosForFreePlan`
- `870: applyPendingSubscriptionIfDue`
- `951: isUploadBlocked`
- `1412: subscriptionPriceIdForPlan`
- `1420: planCodeFromSubscriptionPriceId`
- `1769: stripeCheckoutUrls`
- `1776: parseAllowedReturnOrigins`
- `1784: normalizeReturnUrl`
- `1798: isAllowedReturnUrl`

## 4. パスワード・トークン・識別子生成
- `265: base64UrlFromBuffer`
- `273: makeInviteToken`
- `278: hashRoomPassword`
- `285: verifyRoomPassword`
- `624: getFolderPassword`
- `629: verifyFolderPassword`
- `637: folderHasPassword`
- `641: roomMemberKey`
- `645: userRoomMemberKey`
- `649: userRoomConstraintKey`

## 5. S3・エクスポート・クリーンアップ補助
- `192: addFreePlanWatermarks`
- `316: photoHashKey`
- `320: sha256ForS3Object`
- `333: readS3ObjectBuffer`
- `352: resolveExportSlideLayout`
- `368: tryDeleteUploadedObjects`
- `385: tryDeletePhotoHashMapping`
- `3146: deleteAllCommentsForPhoto`
- `3168: purgePhotoByItem`
- `3203: deleteS3Prefix`

## 6. ユーザー解決・プロフィール
- `399: getUserIdentity`
- `427: normalizeDisplayName`
- `434: ensureUserProfile`
- `475: getUser`
- `501: decodeText`
- `1096: getActiveRoomIdForUser`
- `1101: getMe`
- `1109: updateDisplayName`
- `1969: accountDelete`

## 7. ルーム解決・メンバーシップ・認可
- `510: isRoomMatch`
- `514: resolveActiveRoomForUser`
- `551: listUserRoomMemberships`
- `568: setActiveRoomForUser`
- `617: resolveRoomForRequest`
- `653: isAdminRole`
- `657: normalizeFolderScope`
- `663: normalizeMemberStatus`
- `672: upsertUserRoomMemberIndex`
- `708: maybeUpsertUserRoomMemberIndex`
- `743: ensureRoomMember`
- `829: requireActiveMember`
- `938: folderScopeForMember`
- `943: canAccessFolder`

## 8. ルーム作成・参加・切替
- `959: nextFolderCode`
- `973: nextPhotoCode`
- `987: createRoom`
- `1145: teamMe`
- `1159: teamMeAuto`
- `1170: listMyRooms`
- `1185: switchActiveRoom`
- `1214: createInvite`
- `1262: revokeInvite`
- `1310: acceptInvite`

## 9. Stripe・サブスク・チーム運用
- `1406: teamBilling`
- `1435: stripeGetSubscription`
- `1443: stripeUpdateSubscriptionPlan`
- `1459: stripeSetCancelAtPeriodEnd`
- `1470: stripeCancelSubscriptionNow`
- `1478: cancelStripeSubscriptionForTeamDelete`
- `1523: teamSubscription`
- `1533: teamSubscriptionCheckout`
- `1584: changeTeamSubscription`
- `1807: listTeamMembers`
- `1834: updateTeamMember`
- `1918: teamLeave`
- `2028: deleteAllByPk`
- `2051: teamDelete`

## 10. フォルダ・写真・コメント本体
- `2222: loadDisplayNameMap`
- `2250: applyResolvedDisplayName`
- `2257: listFolders`
- `2285: sumFolderUsageBytes`
- `2314: createFolder`
- `2371: listPhotos`
- `2429: createUploadUrl`
- `2486: finalizePhoto`
- `2666: deletePhoto`
- `2722: updatePhoto`
- `2776: listComments`
- `2806: createComment`
- `2868: deleteComment`
- `2918: updateComment`
- `2978: exportFolder`
- `3231: deleteFolder`
- `3294: updateFolderPassword`

## 11. 最初に読む場所
1. `exports.handler`
2. `475: getUser`
3. `617: resolveRoomForRequest`
4. `829: requireActiveMember`
5. 対象機能の handler

## 12. 次にコード側へ入れる目次案
- 共通ユーティリティ
- ユーザー/認証
- ルーム/メンバーシップ
- 招待
- 課金/Stripe
- フォルダ/写真/コメント
- エクスポート/削除クリーンアップ
