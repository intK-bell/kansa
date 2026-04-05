# frontend/main.js 関数マップ

対象: `frontend/main.js`  
更新日: 2026-04-05  
目的: `main.js` の関数をざっくり棚卸しして、あとで目次コメントやファイル分割をしやすくする。

## 1. 見方
- 行番号は関数定義の開始位置。
- 役割ごとにゆるくまとめている。厳密な責務分離ではなく、読む順の補助を優先。
- イベントバインドや DOM 定数は対象外。関数だけを列挙。

## 2. 起動・認証まわり
- `6: normalizeCognitoDomain`
- `114: hasCognitoConfig`
- `118: parseJwt`
- `130: clearAuth`
- `168: supportsPkce`
- `172: randomString`
- `186: sha256`
- `193: base64UrlEncode`
- `201: startLogin`
- `227: startSignup`
- `252: completeLoginFromCallback`
- `837: fetchMe`
- `841: saveDisplayName`
- `848: ensureDisplayName`
- `1209: initUser`

## 3. 状態・共通ユーティリティ
- `52: el`
- `65: detectCurrentSeason`
- `73: normalizeSeason`
- `77: readStateKey`
- `81: getReadState`
- `89: setReadState`
- `93: getLatestIncomingCommentAt`
- `99: isUnread`
- `105: markAsRead`
- `571: showError`
- `577: clearError`
- `583: formatBytes`
- `591: parseApiErrorBody`
- `1103: asMessage`
- `1109: safeAction`
- `1121: scrollToPhotoList`
- `1202: preserveCurrentView`

## 4. モーダル・画面表示切替
- `140: resetRoomContext`
- `404: closeMenu`
- `410: closeTeamAdminPanel`
- `415: closeRoomCreateModal`
- `421: closeFolderCreateModal`
- `427: closeFolderPasswordModal`
- `433: closeThemeModal`
- `439: closeHelpModal`
- `445: closeLowStorageModal`
- `451: closePhotoPreviewModal`
- `463: openPhotoPreview`
- `475: showAuthSetup`
- `488: openHelpModal`
- `493: openRoomCreateModal`
- `502: openFolderCreateModal`
- `516: openThemeModal`
- `527: openFolderPasswordModal`
- `540: setTeamAdminMode`
- `546: setMenuActionVisibility`
- `1275: showRoomSetup`
- `1406: showApp`

## 5. 課金・テーマ・上部ステータス
- `605: currentFolderLimit`
- `611: folderUsageSummary`
- `617: freePlanGuideText`
- `624: freePlanRequirementDialogText`
- `636: renderPhotoArchiveNote`
- `646: storagePromptKey`
- `651: computeStorageStats`
- `664: syncTopStorageGraphWidth`
- `674: renderTopStorageGraph`
- `697: renderBillingBar`
- `725: setAdminUiVisibility`
- `737: renderStorageGraph`
- `755: syncSubscriptionPlanButtons`
- `778: maybePromptLowStorage`
- `800: applyTheme`
- `811: applySeason`
- `820: initTheme`
- `827: showToast`
- `1128: planToProductLabel`
- `1136: planToDisplayLabel`
- `1144: clearPurchaseParamsFromUrl`
- `1150: handleStripePurchaseReturn`
- `2694: startSubscriptionCheckout`

## 6. ルーム・チーム管理
- `1294: renderMyRooms`
- `1322: renderRoomSelect`
- `1350: loadMyRooms`
- `1361: switchRoomById`
- `1371: getOwnedRoomForGuard`
- `1383: showOwnerDeleteGuard`
- `1487: loadTeamMe`
- `1513: loadAdminPanel`
- `1665: setInviteUrlText`
- `2562: createRoomAndEnter`

## 7. API ラッパ
- `1424: headers`
- `1440: folderPasswordHeader`
- `1446: api`

## 8. アップロード下書き・投稿準備
- `870: setUploadLoading`
- `888: sanitizePhotoName`
- `896: revokeUploadDraftPreview`
- `905: revokeAllUploadDraftPreviews`
- `911: clearUploadDrafts`
- `918: rebuildUploadDrafts`
- `931: padSequenceNumber`
- `935: syncUploadDraftsFromDom`
- `950: validateUploadDrafts`
- `968: renderUploadDrafts`
- `1065: applyBulkComment`
- `1080: applySequencedPhotoNames`
- `1097: cancelUploadDrafts`
- `1875: uploadFiles`

## 9. フォルダ・写真・コメント表示
- `1709: loadFolders`
- `1727: computeFolderUnread`
- `1739: refreshFolderUnread`
- `1760: renderFolders`
- `1797: selectFolder`
- `1836: selectFolderById`
- `1851: loadPhotos`
- `2037: loadComments`
- `2042: canDelete`
- `2046: formatDateTime`
- `2051: renderPhotos`

## 10. 最初に読む場所
1. `1209: initUser`
2. `1406: showApp`
3. `1487: loadTeamMe`
4. 対象機能のセクション

## 11. 次にコード側へ入れる目次案
- 起動・認証
- UI 共通
- 課金表示
- ルーム/チーム管理
- API ラッパ
- アップロード下書き
- フォルダ/写真/コメント
