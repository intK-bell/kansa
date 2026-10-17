import {
  DEFAULT_LOG_TAG, LOG_TAGS, appendFolderAdminActions, appendPhotoCardComments, appendQuestPhotoArea, asMessage, bindAppControlEvents, bindAuthControlEvents, bindBillingControlEvents, bindExportControlEvents, bindGlobalAppEvents, bindInviteControlEvents, bindManagementControlEvents, bindModalDismissEvents, bindMutationControlEvents, bindPhotoCardEditing, bindPhotoCommentsAccordionLifecycle, bindUploadControlEvents, collectAppElements, computeStorageStats, createAdminPanelUi, createAppErrorUi, createBillingStatusUi, createFolderAdminOverview, createFolderCreationUi, createFolderManagementUi, createFreePlanUi, createLogTagUi, createPhotoCardShell, createPhotoCommentRow, createPhotoCommentsAccordion, createPhotoPreviewImage, createQuestCardHeader, createQuestCommentsSection, createRoomCreationUi, createUploadDraftRow, downloadFileNameFromResponse, el, formatBytes,
  createManagementUi, createSubscriptionPlanUi, normalizeCognitoDomain, normalizeFolderMode, normalizeLogTag, parseApiErrorBody, renderBillingBarInto, renderCurrentRoomHeaderInto, renderFolderMembersInto, renderFolderModePanels, renderFolderSelectInto, renderLogTagSummaryInto, renderMyRoomsInto, renderPhotoArchiveNoteInto, renderRentalComparisonInto, renderRoomSelectInto, renderSearchResultsInto, renderStorageGraphInto, renderTeamMembersInto, renderTopStorageGraphInto, syncSearchControlsInto,
  parseJwt, planToProductLabel, questReadKey, questStatusText, renderUploadDraftContainerInto, resizeImageToJpeg, sortQuests, subscriptionPlanLimitBytes, subscriptionPlanRank, syncSubscriptionPlanButtonsInto, syncUploadDraftsFromRows, validateUploadDraftItems,
} from './app-core.js';
import { createCognitoClient, createLiveApi, createLiveRequest, resolveLiveEnvironment } from './api-live.js';
import { clearFolderSelectionState, computeFolderUnreadState, copyInviteText, createAccountDeleteHandler, createActionBoundary, createAdminPanelOptions, createAppViewController, createBillingUiController, createCommentReadController, createDisplayNameChangeHandler, createExportProgressController, createExportResultController, createFolderCreationHandler, createFolderDeleteHandler, createFolderDetailController, createFolderPasswordHandler, createInitialAppState, createInviteHandlers, createLowStorageController, createPhotoCommentAddHandler, createPhotoCommentMutationActions, createPhotoMutationActions, createPhotoPreviewController, createQuestCommentMutationActions, createQuestMutationActions, createReadTracker, createRoomCreationHandler, createRoomDeleteHandler, createRoomLeaveHandler, createScreenController, createStorageGraphController, createTeamAdminController, createUploadDraftController, createUploadDraftEditor, createUploadLoadingController, ensureFolderPasswordState, ensureUserDisplayName, handleFolderListError, handleInvalidFolderPassword, loadFolderContentState, loadFolderListState, loadPhotoState, loadQuestState, loadRoomListState, loadTeamState, refreshFolderUnreadState, renderAdminPanel, renderBillingAdminState, renderFolderListState, resetRoomState, runActionWithHandledErrors, runFolderChange, runFolderExport, runFreePlanChange, runOwnerRoomSwitch, runPhotoSearchState, runQuestCreation, runRoomChange, runSubscriptionPlanChange, runUploadBatch, selectFolderState, startAppInitialization, switchRoomState } from './app-runtime.js';

const liveEnvironment = resolveLiveEnvironment(window);
const I18N = window.KANSA_I18N || null;
const t = (key) => (I18N && typeof I18N.t === 'function' ? I18N.t(key) : key);
const tf = (key, values = {}) =>
  I18N && typeof I18N.format === 'function'
    ? I18N.format(key, values)
    : String(key).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name) =>
        Object.prototype.hasOwnProperty.call(values, name) ? String(values[name]) : match
      );
const appLocale = I18N?.language || 'ja-JP';
const { createLogTagBadge, createLogTagSelect } = createLogTagUi(t);
const subscriptionPlanUi = createSubscriptionPlanUi({ translate: t, formatMessage: tf });
const freePlanUi = createFreePlanUi({ translate: t, formatMessage: tf, formatSize: formatBytes });
const planToDisplayLabel = subscriptionPlanUi.displayLabel;
const billingStatusUi = createBillingStatusUi({ formatMessage: tf, formatSize: formatBytes, planLabel: planToDisplayLabel });
const adminPanelUi = createAdminPanelUi({ translate: t, formatMessage: tf, formatSize: formatBytes, describeError: asMessage });
const roomCreationUi = createRoomCreationUi({ translate: t, formatMessage: tf, describeError: asMessage });
const folderCreationUi = createFolderCreationUi({ translate: t, formatMessage: tf });
const managementUi = createManagementUi({ translate: t });
const folderManagementUi = createFolderManagementUi({ translate: t });
const appErrorUi = createAppErrorUi({ translate: t, formatMessage: tf, describeError: asMessage });
const subscriptionPlanChangeConfirmText = subscriptionPlanUi.confirmText;
const freePlanGuideText = () => freePlanUi.guideText(currentFolderLimit());
const freePlanRequirementDialogText = freePlanUi.requirementText;
const freePlanReturnConfirmText = freePlanUi.confirmText;
const freePlanReturnSuccessText = freePlanUi.successText;
const cognitoClient = createCognitoClient({ ...liveEnvironment.cognito, windowRef: window, translate: t, formatMessage: tf });
const liveRequest = createLiveRequest({
  baseUrl: liveEnvironment.apiBase,
  getHeaders: (method) => headers(method),
  clearError,
  onUnauthorized: () => { clearAuth(); showAuthSetup(); },
  onNoActiveRoom: () => { resetRoomContext(); showRoomSetup(); },
  formatNetworkError: (message) => tf('ネットワークエラー: {message}', { message }),
});
const appApi = createLiveApi(liveRequest, (folderId) => folderPasswordHeader(folderId));
const state = createInitialAppState();

const readTracker = createReadTracker({ storage: localStorage, getUserKey: () => state.userKey });
const commentReadController = createCommentReadController(appApi, state, {
  readTracker, refreshFolderUnread, renderFolders,
});
const isUnread = (key, latestIncomingAt) => commentReadController.isUnread(key, latestIncomingAt);

const hasCognitoConfig = cognitoClient.isConfigured;

function clearAuth() {
  localStorage.removeItem('kansa_id_token');
  localStorage.removeItem('kansa_oauth_state');
  localStorage.removeItem('kansa_oauth_code_verifier');
  localStorage.removeItem('kansa_room_name');
  state.idToken = null;
  state.userKey = null;
  state.userName = null;
  state.isDeveloper = false;
}

function resetRoomContext() {
  localStorage.removeItem('kansa_room_name');
  resetRoomState(state);
  if (els.folderDetail) els.folderDetail.classList.add('hidden');
  renderPhotoArchiveNote();
  closeLowStorageModal();
  renderBillingBar();
  setAdminUiVisibility();
  renderRoomSelect();
  renderFolders();
}

function currentFolderMode() {
  return normalizeFolderMode(state.selectedFolder?.mode);
}

const startLogin = cognitoClient.startLogin;
const startSignup = cognitoClient.startSignup;
const completeLoginFromCallback = cognitoClient.completeLogin;

const els = collectAppElements(document);
const {
  closeMenu, closeTeamAdminPanel, closeRoomCreateModal, closeFolderCreateModal,
  closeFolderPasswordModal, closeHelpModal, closeDeveloperModal, closeLowStorageModal,
  closeExportOptionsModal,
} = createAppViewController(els, { onTeamAdminMode: setTeamAdminMode });
const exportProgress = createExportProgressController(els.exportLoadingBar, window);
const exportResultController = createExportResultController({
  elements: els, windowRef: window, documentRef: document, urlRef: URL,
  readyTitle: () => t('生成完了'),
  readyMessage: (label) => tf('{formatLabel} の生成が完了しました。操作を選んでください。', { formatLabel: label }),
  copiedMessage: (label) => tf('{formatLabel} のリンクをコピーしました。', { formatLabel: label }),
  onCopied: () => showToast(t('リンクをコピーしました。')),
});
const photoPreviewController = createPhotoPreviewController(els, {
  emptyTitle: () => t('写真全体表示'),
  altFor: (photo) => {
    const tagLabel = photo?.logTag ? logTagMeta(photo.logTag).label : '';
    return tagLabel || photo?.originalName || photo?.photoId || t('写真プレビュー');
  },
  titleFor: (photo) => {
    const tagLabel = photo?.logTag ? logTagMeta(photo.logTag).label : '';
    return tagLabel ? `${t(tagLabel)} ${photo?.photoCode || ''}`.trim() : t('写真全体表示');
  },
});
const screenController = createScreenController(els);
const folderDetailController = createFolderDetailController(state, els, {
  renderMode: renderFolderMode,
  renderSearchControls: (criteria) => syncSearchControlsInto(els, criteria, t),
});
const uploadLoadingController = createUploadLoadingController(state, els, {
  getExtraFileInputs: () => document.querySelectorAll('.js-quest-files'),
  idleLabel: () => t('アップロード'), loadingLabel: () => t('アップロード中...'),
});
const uploadDraftController = createUploadDraftController(state, {
  urlRef: URL, defaultLogTag: DEFAULT_LOG_TAG, onRender: renderUploadDrafts,
  clearFileInputs: () => {
    if (els.photoFiles) els.photoFiles.value = '';
    document.querySelectorAll('.js-quest-files').forEach((input) => { input.value = ''; });
  },
});
const uploadDraftEditor = createUploadDraftEditor(state, {
  sync: () => syncUploadDraftsFromRows(els.uploadMetaList, state.uploadDrafts),
  validate: (drafts) => validateUploadDraftItems(drafts, {
    invalidTagMessage: (row) => tf('{row}行目: タグを選択してください。', { row }),
    longCommentMessage: (row) => tf('{row}行目: 初回コメントは50文字以内にしてください。', { row }),
  }),
  onRender: renderUploadDrafts, onClear: () => uploadDraftController.clear(),
  alertMissingComment: () => window.alert(t('1つ目のコメントを先に入力してください。')),
  confirmBulkComment: () => window.confirm(t('1つ目のコメントを全件に反映してよかですか？既存入力は上書きされます。')),
  confirmCancel: () => window.confirm(t('選択した写真と入力内容を破棄してよかですか？')),
});
const actionBoundary = createActionBoundary({
  clearError,
  showError,
  formatError: ({ label, error }) => tf('{label}失敗: {message}', {
    label: t(label || '処理'), message: asMessage(error),
  }),
  onError: (error) => console.error(error),
});
const lowStorageController = createLowStorageController(state, els, {
  storage: localStorage, computeStats: computeStorageStats, formatSize: formatBytes,
  planLabel: planToDisplayLabel,
  formatMessage: ({ remain, plan }) => tf('容量を追加しますか？（現在の残り: {remain} / 現在プラン: {plan}）', { remain, plan }),
});
const storageGraphController = createStorageGraphController(state, els, {
  renderTop: renderTopStorageGraphInto, renderAdmin: renderStorageGraphInto,
  formatSize: formatBytes, folderUsage: folderUsageSummary,
  topLabels: {
    usedLabel: (size) => tf('使用量 {size}', { size }),
    remainingLabel: (size) => tf('残り {size}', { size }),
  },
  adminLabels: {
    used: (size) => tf('使用量 {size}', { size }),
    remaining: (size) => tf('残り {size}', { size }),
  },
});
const syncTopStorageGraphWidth = () => storageGraphController.syncTopWidth();
const renderTopStorageGraph = () => storageGraphController.renderTop();
const renderStorageGraph = () => storageGraphController.renderAdmin();
const billingUiController = createBillingUiController(state, els, {
  renderTopGraph: renderTopStorageGraph, renderBillingBarInto,
  planLabel: planToDisplayLabel, translate: t,
  formatPlan: (plan) => tf('プラン:{plan}', { plan: planToDisplayLabel(plan) }),
  closeLowStorage: closeLowStorageModal, closeFolderPassword: closeFolderPasswordModal,
});
const renderBillingBar = () => billingUiController.renderBar();
const setAdminUiVisibility = () => billingUiController.syncAdminVisibility();
const teamAdminController = createTeamAdminController(state, els, {
  closeMenu, renderCurrentRoomHeader, loadPanel: loadAdminPanel,
});
const setUploadLoading = (isLoading) => uploadLoadingController.set(isLoading);
const clearUploadDrafts = () => uploadDraftController.clear();
const rebuildUploadDrafts = (files, questId = null) => uploadDraftController.rebuild(files, questId);
const syncUploadDraftsFromDom = () => uploadDraftEditor.sync();
const applyBulkComment = () => uploadDraftEditor.applyBulkComment();
const cancelUploadDrafts = () => uploadDraftEditor.cancel();
const loadComments = (photoId) => commentReadController.loadPhotoComments(photoId);
const setFolderDetailTab = (tab) => folderDetailController.setTab(tab);
const syncSearchControls = () => folderDetailController.syncSearchControls();

function openExportLoadingModal(message = t('ダウンロードを開始しています...')) {
  if (els.exportLoadingTitle) els.exportLoadingTitle.textContent = t('出力中');
  if (els.exportLoadingText) els.exportLoadingText.textContent = message;
  if (els.exportLoadingBar) {
    els.exportLoadingBar.style.width = '0%';
    els.exportLoadingBar.classList.remove('is-indeterminate');
  }
  if (els.exportLoadingActions) els.exportLoadingActions.classList.add('hidden');
  if (els.exportLoadingCloseBtn) els.exportLoadingCloseBtn.classList.add('hidden');
  if (els.exportLoadingModal) els.exportLoadingModal.classList.remove('hidden');
}

function startExportLoadingProgress() {
  exportProgress.start();
}

function updateExportLoadingProgress(loaded, total) {
  exportProgress.update(loaded, total);
  if (els.exportLoadingText) {
    if (total > 0) {
      els.exportLoadingText.textContent = tf('PDFをダウンロード中... {percent}%', {
        percent: Math.round((loaded / total) * 100),
      });
    } else {
      els.exportLoadingText.textContent = tf('PDFをダウンロード中... {kb}KB', { kb: Math.round(loaded / 1024) });
    }
  }
}

function closeExportLoadingModal() {
  if (els.exportLoadingModal) els.exportLoadingModal.classList.add('hidden');
  exportProgress.reset();
  if (els.exportLoadingBar) {
    els.exportLoadingBar.style.width = '0%';
    els.exportLoadingBar.classList.remove('is-indeterminate');
  }
  if (els.exportLoadingActions) els.exportLoadingActions.classList.add('hidden');
  if (els.exportLoadingCloseBtn) els.exportLoadingCloseBtn.classList.add('hidden');
  exportResultController.clear();
}

function markExportLoadingDownloadReady() {
  exportProgress.markDownloadReady();
  if (els.exportLoadingText) {
    els.exportLoadingText.textContent = t('PDFのダウンロードを開始しています...');
  }
}

function completeExportLoadingProgress() {
  exportProgress.complete();
}

function showExportReadyActions({ formatLabel, downloadUrl, fileName = '', objectUrl = null }) {
  exportResultController.show({ formatLabel, downloadUrl, fileName, objectUrl });
}

function triggerExportDownload() {
  exportResultController.download();
}

function openExportInNewTab() {
  exportResultController.openInNewTab();
}

async function copyExportLink() {
  await exportResultController.copyLink();
}

function triggerBlobDownload(blob, fileName) {
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  if (fileName) link.download = fileName;
  link.rel = 'noopener';
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000);
}

function closePhotoPreviewModal() {
  photoPreviewController.close();
}

function openPhotoPreview(photo) {
  photoPreviewController.open(photo);
}

function showAuthSetup() {
  screenController.showAuth();
  setMenuActionVisibility(false);
  closeMenu();
  closeFolderCreateModal();
  closeFolderPasswordModal();
  closeDeveloperModal();
}

function openHelpModal() {
  if (!els.helpModal) return;
  els.helpModal.classList.remove('hidden');
}

function renderDeveloperSummary(data) {
  if (!els.developerSummary) return;
  const totals = data?.totals || {};
  const rooms = Array.isArray(data?.rooms) ? data.rooms : [];
  const plans = Array.isArray(data?.planBreakdown) ? data.planBreakdown : [];

  els.developerSummary.innerHTML = '';
  const metrics = el('div', { class: 'developer-metrics' });
  [
    [t('全ユーザー'), totals.users || 0],
    [t('管理者'), totals.admins || 0],
    [t('お部屋メンバー'), totals.activeRoomMembers || 0],
    [t('コンテナメンバー'), totals.folderMembers || 0],
    [t('お部屋'), totals.rooms || 0],
    [t('コンテナ'), totals.folders || 0],
    [t('総容量'), formatBytes(totals.usageBytes || 0)],
  ].forEach(([label, value]) => {
    const item = el('div', { class: 'developer-metric' });
    item.appendChild(el('span', {}, label));
    item.appendChild(el('strong', {}, value));
    metrics.appendChild(item);
  });
  els.developerSummary.appendChild(metrics);

  const planBox = el('div', { class: 'developer-section' });
  planBox.appendChild(el('h4', {}, t('有料プラン内訳')));
  if (!plans.length) {
    planBox.appendChild(el('p', { class: 'muted' }, t('有料プランのお部屋はまだありません。')));
  } else {
    const list = el('div', { class: 'developer-plan-list' });
    plans.forEach((plan) => {
      const row = el('div', { class: 'developer-plan-row' });
      row.appendChild(el('span', {}, plan.label || plan.plan));
      row.appendChild(
        el(
          'strong',
          {},
          tf('{count}件 / 有料内 {paidPercent}% / 全体 {totalPercent}%', {
            count: plan.count || 0,
            paidPercent: plan.percent || 0,
            totalPercent: plan.percentOfAllRooms || 0,
          })
        )
      );
      list.appendChild(row);
    });
    planBox.appendChild(list);
  }
  els.developerSummary.appendChild(planBox);

  const roomBox = el('div', { class: 'developer-section' });
  roomBox.appendChild(el('h4', {}, t('お部屋と容量')));
  const tableWrap = el('div', { class: 'developer-table-wrap' });
  const table = el('table', { class: 'developer-table' });
  const thead = el('thead');
  const headRow = el('tr');
  ['お部屋', '容量', 'コンテナ', 'お部屋メンバー', 'コンテナメンバー', 'メンバー（合計）', 'プラン', '作成者'].forEach((label) => {
    headRow.appendChild(el('th', {}, t(label)));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = el('tbody');
  rooms.forEach((room) => {
    const row = el('tr');
    row.appendChild(el('td', {}, room.roomName || '-'));
    row.appendChild(el('td', {}, room.usageLabel || formatBytes(room.usageBytes || 0)));
    row.appendChild(el('td', {}, room.folderCount || 0));
    row.appendChild(el('td', {}, room.roomMemberCount || 0));
    row.appendChild(el('td', {}, room.folderMemberCount || 0));
    row.appendChild(el('td', {}, room.memberCount || 0));
    row.appendChild(el('td', {}, room.planLabel || room.plan || 'FREE'));
    row.appendChild(el('td', {}, room.createdByName || room.createdBy || '-'));
    tbody.appendChild(row);
  });
  if (!rooms.length) {
    const row = el('tr');
    const cell = el('td', { colspan: '8', class: 'muted' }, t('お部屋がありません。'));
    row.appendChild(cell);
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  roomBox.appendChild(tableWrap);
  if (data?.generatedAt) {
    roomBox.appendChild(
      el('p', { class: 'muted developer-generated-at' }, tf('更新: {datetime}', { datetime: formatJstDateTime(data.generatedAt) }))
    );
  }
  els.developerSummary.appendChild(roomBox);
}

async function openDeveloperDashboard() {
  if (!state.isDeveloper || !els.developerModal || !els.developerSummary) return;
  closeMenu();
  els.developerSummary.innerHTML = '';
  els.developerSummary.appendChild(el('p', { class: 'muted' }, t('読み込み中...')));
  els.developerModal.classList.remove('hidden');
  try {
    const data = await liveRequest('/developer/summary', { method: 'GET' });
    renderDeveloperSummary(data);
  } catch (error) {
    els.developerSummary.innerHTML = '';
    els.developerSummary.appendChild(el('p', { class: 'muted' }, tf('取得失敗: {message}', { message: asMessage(error) })));
  }
}

function openRoomCreateModal() {
  if (!els.roomCreateModal) return;
  els.roomCreateModal.classList.remove('hidden');
  if (els.roomCreateName) {
    els.roomCreateName.value = '';
    els.roomCreateName.focus();
  }
}

function openFolderCreateModal() {
  if (!els.folderCreateModal) return;
  els.folderCreateModal.classList.remove('hidden');
  if (els.folderTitle) {
    els.folderTitle.value = '';
  }
  if (els.folderTitleError) {
    els.folderTitleError.classList.add('hidden');
  }
  if (els.folderMode) {
    els.folderMode.value = 'photo';
  }
  if (els.folderPassword) {
    els.folderPassword.value = '';
  }
  if (els.folderTitle) {
    els.folderTitle.focus();
  }
}

function openFolderPasswordModal() {
  if (!els.folderPasswordModal) return;
  if (!state.selectedFolder) {
    window.alert(t('先にコンテナを選択してください。'));
    return;
  }
  if (els.folderPasswordTargetName) {
    const folder = state.selectedFolder;
    els.folderPasswordTargetName.textContent = `${folder.title || folder.folderId}`;
  }
  if (els.folderPasswordSet) {
    els.folderPasswordSet.value = '';
    els.folderPasswordSet.focus();
  }
  els.folderPasswordModal.classList.remove('hidden');
}

function openExportOptionsModal() {
  if (!els.exportOptionsModal) return;
  els.exportOptionsModal.classList.remove('hidden');
}

function renderCurrentRoomHeader() {
  renderCurrentRoomHeaderInto(els.currentRoomName, state.roomName, t('未選択'));
}

async function requestFolderExport(format) {
  return runFolderExport(appApi, state, format, {
    getFormatLabel: (value) => value === 'pdf' ? 'PDF' : value === 'pptx_light' ? t('軽量PPT') : t('高画質PPT'),
    onMissingFolder: () => window.alert(t('先にコンテナを選択してください。')),
    confirmExport: (label) => window.confirm(tf('{formatLabel}で出力します。よろしいですか？', { formatLabel: label })),
    onStart: (label) => { openExportLoadingModal(tf('{formatLabel} を生成しています...', { formatLabel: label })); startExportLoadingProgress(); },
    onDownloadReady: markExportLoadingDownloadReady,
    fetchDownload: (url) => fetch(url),
    downloadError: (status) => new Error(tf('PDFダウンロード失敗({status})', { status })),
    getFileName: downloadFileNameFromResponse,
    createBlob: (chunks) => new Blob(chunks, { type: 'application/pdf' }),
    createObjectUrl: (blob) => URL.createObjectURL(blob),
    onProgress: updateExportLoadingProgress,
    onComplete: completeExportLoadingProgress,
    onReady: showExportReadyActions,
    onFallback: (url) => { window.location.href = url; },
    onClose: closeExportLoadingModal,
  });
}

function setTeamAdminMode(isOpen) {
  return teamAdminController.syncMode(isOpen);
}

function setMenuActionVisibility(showActions, options = {}) {
  const { showAccountDelete = showActions } = options;
  if (els.resetUserBtn) {
    els.resetUserBtn.classList.toggle('hidden', !showActions);
  }
  if (els.createRoomMenuBtn) {
    els.createRoomMenuBtn.classList.toggle('hidden', !showActions);
  }
  if (els.leaveRoomBtn) {
    els.leaveRoomBtn.classList.toggle('hidden', !showActions);
  }
  if (els.accountDeleteBtn) {
    els.accountDeleteBtn.classList.toggle('hidden', !showAccountDelete);
  }
  if (els.openFolderCreateBtn) {
    els.openFolderCreateBtn.classList.toggle('hidden', !showActions);
  }
  if (els.openFolderPasswordBtn) {
    els.openFolderPasswordBtn.classList.toggle('hidden', !showActions || !state.isAdmin);
  }
  if (els.developerDashboardBtn) {
    els.developerDashboardBtn.classList.toggle('hidden', !state.isDeveloper);
  }
}

function showError(message) {
  if (!els.errorBox) return;
  els.errorBox.textContent = message;
  els.errorBox.classList.remove('hidden');
}

function clearError() {
  if (!els.errorBox) return;
  els.errorBox.textContent = '';
  els.errorBox.classList.add('hidden');
}

function formatJstDateTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return new Intl.DateTimeFormat('ja-JP', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

function uploadErrorMessage(error, fileName = '') {
  const body = parseApiErrorBody(error);
  const message = String(body?.message || asMessage(error) || '');
  const prefix = fileName ? `${fileName}: ` : '';
  if (message.includes('duplicate photo already exists')) {
    return `${prefix}${t('同じ写真は同じコンテナにアップロードできません（重複を検知しました）。')}`;
  }
  if (
    message.includes('file is too large') ||
    message.includes('original object size is invalid') ||
    message.includes('preview object size is invalid')
  ) {
    return `${prefix}${t('画像サイズが上限を超えています。25MB以下の画像を選んでください。')}`;
  }
  if (
    message.includes('unsupported image content type') ||
    message.includes('content type') ||
    message.includes('preview object')
  ) {
    return `${prefix}${t('JPEGまたはPNGの画像を選んでください。')}`;
  }
  if (message.includes('upload session')) {
    return `${prefix}${t('アップロードの有効期限が切れました。もう一度アップロードしてください。')}`;
  }
  if (message.includes('storage credits depleted') || (error && error.status === 402)) {
    return `${prefix}${t('アップロード停止中です（残量不足）。管理者が容量チケットを追加するか、写真を削除してください。')}`;
  }
  return `${prefix}${tf('写真アップロード失敗: {message}', { message })}`;
}

function currentFolderLimit() {
  return billingStatusUi.folderLimit(state.billing);
}

function folderUsageSummary() {
  return billingStatusUi.folderUsage(state.folders, state.billing);
}

function renderPhotoArchiveNote() {
  renderPhotoArchiveNoteInto(els.photoArchiveNote, state.selectedFolderArchive, (values) => tf(
    '{count}件の写真は{days}日保存後にアーカイブされ、現在は非表示です。アーカイブ済みデータも容量に含まれます。有料プランにすると再表示されます。', values
  ));
}

function syncSubscriptionPlanButtons() {
  syncSubscriptionPlanButtonsInto(els, state.billing, {
    translate: t,
    formatCurrent: (label) => tf('{label}（現在のプラン）', { label }),
  });
}

function maybePromptLowStorage() {
  return lowStorageController.prompt();
}

function initFixedAppearance() {
  document.body.classList.add('dark');
}

function showToast(message) {
  if (!els.toast) return;
  els.toast.textContent = message;
  els.toast.classList.remove('hidden');
  window.clearTimeout(showToast.timerId);
  showToast.timerId = window.setTimeout(() => {
    els.toast.classList.add('hidden');
  }, 2500);
}

async function ensureDisplayName() {
  return ensureUserDisplayName(appApi, state, {
    promptName: () => window.prompt(t('表示名を入力してください。メニューからいつでも変更可能です。')),
    onLoaded: (me) => { state.isDeveloper = Boolean(me.isDeveloper); },
    onInvalid: () => window.alert(t('表示名は必須です。')),
    onSaved: () => showToast(t('表示名を設定しました。')),
  });
}

function setUploadMetaStatus(message) {
  if (!els.uploadMetaStatus) return;
  els.uploadMetaStatus.textContent = message || '';
}

function removeUploadedDrafts(uploadedDraftIds) {
  uploadDraftController.remove(uploadedDraftIds);
}

function validateUploadDrafts() {
  return uploadDraftEditor.validate();
}

function moveUploadMetaCardToActiveSlot() {
  if (!els.uploadMetaCard) return;
  if (state.uploadTargetQuestId) {
    const slots = Array.from(document.querySelectorAll('.quest-upload-slot[data-quest-id]'));
    const slot = slots.find((node) => node.getAttribute('data-quest-id') === state.uploadTargetQuestId);
    if (slot) {
      slot.appendChild(els.uploadMetaCard);
      return;
    }
  }
  if (els.photoUploadMetaSlot) els.photoUploadMetaSlot.appendChild(els.uploadMetaCard);
}

function renderUploadDrafts() {
  moveUploadMetaCardToActiveSlot();
  renderUploadDraftContainerInto(els, state.uploadDrafts, {
    uploadTargetQuestId: state.uploadTargetQuestId,
    formatStatus: (count) => tf('{count}件の写真をアップロード対象に追加しています。', { count }),
    createRow: (draft, index) => createUploadDraftRow(draft, index, {
      translate: t,
      createTagSelect: createLogTagSelect,
      onPreview: openPhotoPreview,
      onRemove: (removedDraft) => {
        uploadDraftController.remove([removedDraft.localId]);
      },
    }),
  });
}

function safeAction(fn, label) {
  return actionBoundary.wrap(fn, label);
}

async function scrollToPhotoList() {
  if (!els.photoList) return;
  // Wait a frame so DOM updates from renderPhotos are reflected before scrolling.
  await new Promise((r) => window.requestAnimationFrame(() => r()));
  els.photoList.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function scrollToActiveList() {
  await new Promise((r) => window.requestAnimationFrame(() => r()));
  const target = currentFolderMode() === 'quest' ? els.questList : els.photoList;
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function clearPurchaseParamsFromUrl() {
  const url = new URL(window.location.href);
  ['subscription', 'plan', 'session_id', 'sessionId'].forEach((k) => url.searchParams.delete(k));
  window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
}

async function handleStripePurchaseReturn() {
  // Stripe Checkout success redirect for subscription mode.
  const url = new URL(window.location.href);
  const subscription = url.searchParams.get('subscription');
  if (!subscription) return;
  if (subscription !== 'success') {
    clearPurchaseParamsFromUrl();
    return;
  }

  const plan = url.searchParams.get('plan') || '';
  const label = planToProductLabel(plan);
  if (!label) {
    clearPurchaseParamsFromUrl();
    return;
  }
  if (!state.isAdmin) {
    clearPurchaseParamsFromUrl();
    return;
  }

  // Navigate to the room admin screen (within the same page).
  await teamAdminController.open();

  // Poll until subscription info reflects the selected plan.
  const maxAttempts = 45; // ~45s
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const res = await appApi.getSubscription();
      const currentPlan = String(res?.subscription?.currentPlan || '').toUpperCase();
      if (currentPlan === String(plan).toUpperCase()) {
        await loadTeamMe();
        await loadAdminPanel();
        showToast(tf('プランを{label}へ更新しました。', { label }));
        clearPurchaseParamsFromUrl();
        return;
      }
    } catch (_) {
      // Ignore transient API errors while polling.
    }
    await new Promise((r) => setTimeout(r, 1000));
  }

  // Timed out. Don't loop on refresh.
  clearPurchaseParamsFromUrl();
  showToast(t('決済反映に少し時間がかかっとるばい。しばらくしてプラン表示ば確認してね。'));
}

function preserveCurrentView(photoId) {
  if (photoId) {
    state.openAccordions.add(photoId);
  }
  state.restoreScrollY = window.scrollY;
}

async function initUser() {
  initFixedAppearance();
  setMenuActionVisibility(false);
  if (els.logoutBtn) els.logoutBtn.classList.add('hidden');
  if (els.globalMenuWrap) els.globalMenuWrap.classList.add('hidden');
  if (!hasCognitoConfig()) {
    showAuthSetup();
    showError(t('Cognito設定が不足しています。config.jsにdomain/clientId/regionを設定してください。'));
    return;
  }

  // Preserve invite token across Cognito redirects (redirect_uri cannot keep arbitrary query params).
  const currentUrl = new URL(window.location.href);
  const inviteFromUrl = currentUrl.searchParams.get('invite');
  if (inviteFromUrl) {
    localStorage.setItem('kansa_pending_invite', inviteFromUrl);
  }

  await completeLoginFromCallback();
  const idToken = localStorage.getItem('kansa_id_token');
  const inviteToken = inviteFromUrl || localStorage.getItem('kansa_pending_invite');
  const claims = parseJwt(idToken);
  const now = Math.floor(Date.now() / 1000);

  if (idToken && claims && claims.sub && (!claims.exp || claims.exp > now)) {
    state.idToken = idToken;
    state.userKey = claims.sub;
    state.userName =
      claims['cognito:username'] || claims.name || claims.email || claims.preferred_username || 'unknown';
    await ensureDisplayName();
    if (inviteToken) {
      try {
        const res = await appApi.acceptInvite(inviteToken);
        state.roomName = res.roomName || null;
        localStorage.removeItem('kansa_pending_invite');
        const url = new URL(window.location.href);
        url.searchParams.delete('invite');
        window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
        showApp();
        showToast(t('お部屋に参加しました。'));
        return;
      } catch (error) {
        showError(tf('招待URLの処理に失敗しました: {message}', { message: asMessage(error) }));
        // The token may be expired/invalid; avoid retry loops.
        localStorage.removeItem('kansa_pending_invite');
        // Fall through to normal room discovery/setup.
      }
    }
    // Resolve room solely from membership; don't trust local cache across users.
    try {
      const data = await appApi.getTeam();
      if (!data || data.hasRoom === false || !data.roomName) {
        showRoomSetup();
        return;
      }
      state.roomName = data.roomName || null;
      showApp();
    } catch (_) {
      showRoomSetup();
    }
    return;
  }
  clearAuth();
  showAuthSetup();
}

function showRoomSetup() {
  screenController.showRoomSetup({ authenticated: Boolean(state.userKey) });
  if (state.userKey) {
    loadMyRooms().catch(() => {});
  }
  setMenuActionVisibility(false, { showAccountDelete: Boolean(state.userKey) });
  closeMenu();
  closeFolderCreateModal();
  closeFolderPasswordModal();
  closeDeveloperModal();
}

function renderMyRooms(items, activeRoomId) {
  renderMyRoomsInto(els.myRoomsList, items, activeRoomId, {
    translate: t,
    onSwitch: safeAction(async (room) => {
      await switchRoomById(room.roomId, room.roomName);
    }, 'お部屋切替'),
  });
}

function renderRoomSelect() {
  renderRoomSelectInto(els.currentRoomSelect, state.availableRooms, {
    roomId: state.roomId, roomName: state.roomName, translate: t,
  });
  renderCurrentRoomHeader();
}

async function loadMyRooms() {
  if (!state.idToken) return;
  if (els.myRoomsList) {
    els.myRoomsList.textContent = t('読み込み中...');
  }
  const res = await loadRoomListState(appApi, state);
  renderMyRooms(state.availableRooms, res.activeRoomId || null);
  renderRoomSelect();
}

async function switchRoomById(roomId, fallbackRoomName = '') {
  await switchRoomState(appApi, state, roomId, fallbackRoomName, {
    beforeReset: closeTeamAdminPanel, reset: resetRoomContext, onReady: showApp,
  });
}

async function getOwnedRoomForGuard() {
  if (!state.idToken) return false;
  const res = await appApi.listRooms();
  const items = Array.isArray(res?.items) ? res.items : [];
  const owned = items.find((r) => {
    const role = String(r?.role || '').toLowerCase();
    const memberStatus = String(r?.memberStatus || 'active').toLowerCase();
    return role === 'admin' && memberStatus !== 'left' && memberStatus !== 'disabled';
  });
  return owned || null;
}

async function showOwnerDeleteGuard(ownedRoom) {
  return runOwnerRoomSwitch(appApi, state, ownedRoom, {
    onCurrentRoom: () => window.alert(t('作成者は先に「このお部屋を削除（全データ）」を実行してください。')),
    confirmSwitch: () => window.confirm(tf('作成者は先に「お部屋を削除（全データ）」を実行してください。\n「{roomName}」へ移動しますか？', {
      roomName: ownedRoom?.roomName || t('自分の部屋'),
    })),
    closeAdmin: closeTeamAdminPanel,
    resetRoom: resetRoomContext,
    showApp,
    onSwitched: () => showToast(tf('「{roomName}」へ移動しました。', { roomName: ownedRoom.roomName })),
  });
}

function showApp() {
  screenController.showApp({ userName: state.userName });
  setMenuActionVisibility(true);
  closeMenu();
  renderCurrentRoomHeader();
  renderRoomSelect();
  loadTeamMe().then(async () => {
    if (els.uploadBtn) els.uploadBtn.disabled = Boolean(state.uploadBlocked);
    await handleStripePurchaseReturn();
  });
  loadMyRooms().catch(() => {});
  loadFolders();
}

function headers(method = 'GET') {
  const upper = String(method || 'GET').toUpperCase();
  const authHeader = state.idToken ? { Authorization: `Bearer ${state.idToken}` } : {};
  const languageHeader = I18N?.language ? { 'x-kansa-language': I18N.language } : {};
  // Room headers are deprecated. Room is inferred from membership (/team/me, invite accept).
  const roomHeaders = {};
  if (upper === 'GET') return { ...authHeader, ...languageHeader, ...roomHeaders };
  const safeUserName = encodeURIComponent(state.userName || 'unknown');
  return {
    ...authHeader,
    ...languageHeader,
    'content-type': 'application/json',
    'x-user-key': state.userKey,
    'x-user-name': safeUserName,
    ...roomHeaders,
  };
}

function folderPasswordHeader(folderId) {
  const pw = state.folderPasswordById[folderId];
  if (!pw) return {};
  return { 'x-folder-password': encodeURIComponent(pw) };
}

async function loadTeamMe() {
  await loadTeamState(appApi, state, { onError: (error) => {
    showError(
      tf('チーム情報取得失敗: {message}（バックエンド/フロントのデプロイ差分やキャッシュの可能性）', {
        message: asMessage(error),
      })
    );
  } });
  setAdminUiVisibility();
  renderBillingBar();
  syncSubscriptionPlanButtons();
  renderCurrentRoomHeader();
  renderRoomSelect();
}

const adminPanelOptions = createAdminPanelOptions(state, {
    isVisible: () => Boolean(els.teamAdminCard && !els.teamAdminCard.classList.contains('hidden')),
    member: {
      api: appApi,
      target: els.memberList,
      renderMembers: renderTeamMembersInto,
      translate: t,
      safeAction,
      confirmScopeChange: (m) => window.confirm(adminPanelUi.confirmScopeChange(m)),
      confirmRemove: (m) => window.confirm(adminPanelUi.confirmMemberRemove(m)),
      onScopeUpdated: () => window.alert(adminPanelUi.scopeUpdated()),
      onRemoved: () => window.alert(adminPanelUi.memberRemoved()),
      reload: loadAdminPanel,
      renderError: (error) => {
        if (els.memberList) {
          els.memberList.innerHTML = '';
          els.memberList.appendChild(el('div', { class: 'muted' }, adminPanelUi.memberLoadError(error)));
        }
      },
      scopeActionLabel: '権限更新',
      removeActionLabel: 'メンバー削除',
    },

    folder: {
      target: els.folderAdminList,
      createOverview: createFolderAdminOverview,
      translate: t,
      formatCount: adminPanelUi.folderCount,
      formatHeader: adminPanelUi.folderHeader,
      safeAction,
      reload: loadAdminPanel,
      renderNoFolders: (target) => target.appendChild(el('div', { class: 'muted' }, adminPanelUi.noFolders())),
      selected: {
        api: appApi,
        appendActions: appendFolderAdminActions,
        renderMembers: renderFolderMembersInto,
        createMembersBox: () => el('div', { class: 'folder-admin-members' }, t('メンバー読み込み中...')),
        translate: t,
        safeAction,
        copyInvite: copyInviteUrlFromInput,
        buildInviteUrl: (token) => `${window.location.origin}${window.location.pathname}?invite=${encodeURIComponent(token)}`,
        missingTokenError: () => new Error(adminPanelUi.missingInviteToken()),
        showInviteUrl: async ({ url, inviteInput, revokeButton }) => {
          if (revokeButton) revokeButton.classList.remove('hidden');
          await setInviteUrlText(url, inviteInput);
        },
        confirmRevoke: (folder) => window.confirm(adminPanelUi.confirmInviteRevoke(folder)),
        onMissingInvite: () => showError(adminPanelUi.missingInvite()),
        onInviteRevoked: ({ inviteInput, revokeButton }) => {
          inviteInput.value = '';
          revokeButton.classList.add('hidden');
          showToast(adminPanelUi.inviteRevoked());
        },
        confirmPassword: (folder, password) => window.confirm(adminPanelUi.confirmPassword(folder, password)),
        onPasswordUpdated: ({ password, passwordInput }) => {
          passwordInput.value = '';
          window.alert(adminPanelUi.passwordUpdated(password));
        },
        confirmDelete: (folder) => window.confirm(adminPanelUi.confirmFolderDelete(folder)),
        onDeleted: () => window.alert(adminPanelUi.folderDeleted()),
        confirmMemberRemove: (m) => window.confirm(adminPanelUi.confirmFolderMemberRemove(m)),
        onMemberRemoved: () => window.alert(adminPanelUi.folderMemberRemoved()),
        formatMemberLoadError: adminPanelUi.memberLoadError,
        reloadFolders: loadFolders,
        reloadTeam: loadTeamMe,
        reloadPanel: loadAdminPanel,
      },
      renderError: (error) => {
        if (els.folderAdminList) {
          els.folderAdminList.innerHTML = '';
          els.folderAdminList.appendChild(el('div', { class: 'muted' }, adminPanelUi.folderLoadError(error)));
        }
      },
      selectActionLabel: '管理コンテナ選択',
    },
    renderBilling: () => renderBillingAdminState(state, els, {
      buildStatus: (billing) => billingStatusUi.statusText(billing, state.folders),
      guideText: freePlanGuideText,
      archiveNote: adminPanelUi.archiveNote,
      renderGraph: renderStorageGraph,
      promptLowStorage: maybePromptLowStorage,
      syncPlanButtons: syncSubscriptionPlanButtons,
    }),
});

async function loadAdminPanel() {
  await renderAdminPanel(appApi, state, adminPanelOptions);
}

async function setInviteUrlText(url, targetInput = els.inviteUrl) {
  if (targetInput) targetInput.value = url || '';
  if (!url) return;
  await copyInviteUrl(url, true);
}

async function copyInviteUrl(url, showFallbackPrompt = false) {
  return copyInviteText(url, {
    writeText: navigator.clipboard?.writeText?.bind(navigator.clipboard),
    allowFallback: showFallbackPrompt,
    onMissing: () => showError(folderManagementUi.copyMissing()),
    onCopied: () => showToast(folderManagementUi.copied()),
    onFallback: (text) => window.prompt(folderManagementUi.copyPrompt(), text),
    onDenied: () => showError(folderManagementUi.copyDenied()),
  });
}

async function copyInviteUrlFromInput(targetInput) {
  await copyInviteUrl(targetInput?.value || '', true);
}

const inviteHandlers = createInviteHandlers(appApi, {
  getCopyValue: () => els.inviteUrl?.value,
  copyOptions: {
    writeText: navigator.clipboard?.writeText?.bind(navigator.clipboard),
    onMissing: () => showError(folderManagementUi.copyMissing()),
    onCopied: () => showToast(folderManagementUi.copied()),
    onFallback: (text) => window.prompt(folderManagementUi.copyPrompt(), text),
    onDenied: () => showError(folderManagementUi.copyDenied()),
  },
  createOptions: {
      saveToken: (token) => { state.lastInviteToken = token; },
      buildInviteUrl: (token) => `${window.location.origin}${window.location.pathname}?invite=${encodeURIComponent(token)}`,
      missingTokenError: () => new Error(folderManagementUi.missingInviteToken()),
      onCreated: async ({ url }) => { if (els.revokeInviteBtn) els.revokeInviteBtn.classList.remove('hidden'); await setInviteUrlText(url); },
  },
  getToken: () => state.lastInviteToken,
  revokeOptions: {
      onMissing: () => showError(folderManagementUi.revokeMissing()),
      confirmRevoke: () => window.confirm(folderManagementUi.confirmRevoke()),
      clearToken: () => { state.lastInviteToken = null; },
      onRevoked: () => { if (els.inviteUrl) els.inviteUrl.value = ''; els.revokeInviteBtn.classList.add('hidden'); showToast(folderManagementUi.revoked()); },
  },
});

bindInviteControlEvents(els, {
  onCopyInviteUrl: safeAction(inviteHandlers.copy, '招待URLコピー'),
  onCreateInvite: safeAction(inviteHandlers.create, '招待URL発行'),
  onRevokeInvite: safeAction(inviteHandlers.revoke, '招待URL失効'),
});

async function loadFolders() {
  await loadFolderListState(appApi, state, { refreshUnread: refreshFolderUnread, onError: (error) => handleFolderListError(error, {
    onNetworkError: () => showError(appErrorUi.folderNetwork()),
    onError: (_message, error) => showError(appErrorUi.folder(error)),
  }) });
  renderFolders();
}

async function computeFolderUnread(folderId) {
  return computeFolderUnreadState(appApi, state, folderId, {
    normalizeMode: normalizeFolderMode, isUnread, questKey: questReadKey,
  });
}

async function refreshFolderUnread(folderIds = null) {
  return refreshFolderUnreadState(state, folderIds, { computeUnread: computeFolderUnread });
}

function renderFolders() {
  const clearMissingSelection = () => clearFolderSelectionState(state, {
    hideDetail: () => els.folderDetail.classList.add('hidden'),
  });
  renderFolderListState(state, {
    renderList: ({ folders, unreadById, selectedFolderId }) =>
      renderFolderSelectInto(els.currentFolderSelect, folders, { unreadById, selectedFolderId, translate: t }),
    onEmpty: clearMissingSelection,
    onSelectionMissing: clearMissingSelection,
  });
}

async function selectFolder(folder) {
  clearUploadDrafts();
  const folderId = folder.folderId;
  const hasPassword = ensureFolderPasswordState(state, folder, {
    prompt: () => window.prompt(t('このコンテナは鍵付きです。パスワードを入力してください。'), ''),
    onCancel: renderFolders,
    onMissing: () => { showError(t('コンテナパスワードが必要です。')); renderFolders(); },
  });
  if (!hasPassword) return;
  await runActionWithHandledErrors(() => selectFolderState(state, folder, {
      renderFolders,
      showDetail: () => els.folderDetail.classList.remove('hidden'),
      setRecordTab: () => setFolderDetailTab('record'),
      setDetailTitle: (selected) => {
        const modeLabel = normalizeFolderMode(selected.mode) === 'quest' ? t('クエスト') : t('フォト');
        els.folderDetailTitle.textContent = `${t('コンテナ')}: ${selected.title} [${modeLabel}]`;
      },
      loadContent: loadFolderContent,
    }), {
    handleError: (error) => handleInvalidFolderPassword(error, state, folderId, {
      isInvalidPassword: (caught) => caught?.status === 403 && parseApiErrorBody(caught)?.message === 'invalid folder password',
      cleanup: () => clearFolderSelectionState(state, {
        hideDetail: () => els.folderDetail.classList.add('hidden'),
        renderArchive: renderPhotoArchiveNote, renderFolders,
      }),
      onInvalid: () => showError(t('コンテナパスワードが違います。')),
    }),
  });
}

async function selectFolderById(folderId) {
  return runFolderChange(state, folderId, {
    clearSelection: () => clearFolderSelectionState(state, {
      clearDrafts: clearUploadDrafts,
      hideDetail: () => els.folderDetail.classList.add('hidden'),
      renderArchive: renderPhotoArchiveNote, renderFolders,
    }),
    selectFolder,
  });
}

async function loadPhotos() {
  const folderId = state.selectedFolder.folderId;
  await loadPhotoState(appApi, state, folderId);
  renderPhotoArchiveNote();
  await renderPhotos();
  if (state.folderDetailTab === 'search' && state.photoSearchScope === 'folder') {
    state.searchPhotos = filteredFolderPhotos();
    renderSearchResults();
  }
  await refreshFolderUnread([state.selectedFolder.folderId]);
  renderFolders();
  await loadTeamMe();
  if (els.uploadBtn) els.uploadBtn.disabled = Boolean(state.uploadBlocked);
  if (state.restoreScrollY !== null) {
    window.scrollTo(0, state.restoreScrollY);
    state.restoreScrollY = null;
  }
}

async function loadQuests() {
  const folderId = state.selectedFolder.folderId;
  await loadQuestState(appApi, state, folderId);
  renderQuests();
  await refreshFolderUnread([folderId]);
  renderFolderMode();
  renderFolders();
}

async function loadFolderContent() {
  await loadFolderContentState(state, {
    mode: currentFolderMode(), loadQuests, loadPhotos,
    onQuestMode: renderPhotoArchiveNote, onRendered: renderFolderMode,
  });
}

async function uploadFiles() {
  await runUploadBatch(state, {
    syncDrafts: syncUploadDraftsFromDom,
    validateDrafts: validateUploadDrafts,
    setLoading: setUploadLoading,
    isDuplicate: (error) => asMessage(error).includes('APIエラー(409)'),
    onValidationError: setUploadMetaStatus,
    uploadDraft: async (draft, _index, targetQuestId) => {
      const file = draft.file;
      const previewBlob = await resizeImageToJpeg(file, 2048, 0.82);
      await appApi.uploadPhoto({
        folderId: state.selectedFolder.folderId, file, previewBlob,
        logTag: normalizeLogTag(draft.logTag),
        initialComment: String(draft.initialComment || '').trim() || null,
        questId: targetQuestId,
      });
    },
    onUploaded: async ({ totalFiles, uploadedCount, duplicateCount, uploadedDraftIds }) => {
      if (duplicateCount > 0) removeUploadedDrafts(uploadedDraftIds);
      else clearUploadDrafts();
      await loadFolderContent();
      await scrollToActiveList();
      if (duplicateCount > 0) {
        setUploadMetaStatus(tf('{uploaded}/{total}件アップロード完了。{duplicate}件は重複のためスキップしました。', {
          uploaded: uploadedCount,
          total: totalFiles,
          duplicate: duplicateCount,
        }));
      } else {
        showToast(tf('{uploaded}/{total}件アップロード完了。', { uploaded: uploadedCount, total: totalFiles }));
      }
    },
    onComplete: ({ totalFiles, uploadedCount, duplicateCount }) => {
      if (duplicateCount > 0) {
        if (totalFiles === 1) {
          setUploadMetaStatus(t('同じ写真は同じコンテナにアップロードできません（重複を検知しました）。'));
          return;
        }
        if (duplicateCount === totalFiles) {
          setUploadMetaStatus(t('すべて重複なのでアップロードができません。'));
          return;
        }
        if (uploadedCount === 0) {
          setUploadMetaStatus(tf('{duplicate}件は重複のためスキップしました。', { duplicate: duplicateCount }));
        }
      }
    },
    onError: async (error, activeDraft) => {
      if (error && error.status === 402) {
        await loadTeamMe();
        if (els.uploadBtn) els.uploadBtn.disabled = Boolean(state.uploadBlocked);
      }
      setUploadMetaStatus(uploadErrorMessage(error, activeDraft?.originalName || ''));
      console.error(error);
    },
  });
}

function canDelete(item) {
  return item.createdBy === state.userKey || state.isAdmin;
}

function formatDateTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString(appLocale);
}

function renderFolderMode() {
  renderFolderModePanels(els, currentFolderMode());
}

function photosForCurrentSummary() {
  if (currentFolderMode() === 'quest') {
    return (state.quests || []).flatMap((quest) => quest.photos || []);
  }
  return state.photos || [];
}

function renderLogTagSummary(photos = photosForCurrentSummary()) {
  renderLogTagSummaryInto(els.logTagSummary, photos, t);
}

function renderRentalComparison(photos = photosForCurrentSummary()) {
  renderRentalComparisonInto(els.rentalComparison, els.rentalComparisonGrid, photos, {
    enabled: Boolean(window.KANSA_MARKET?.isRental), translate: t,
    createTagBadge: createLogTagBadge, onPreview: openPhotoPreview,
  });
}

function photoMatchesSearch(photo) {
  const tag = state.photoSearchTag || 'all';
  if (tag !== 'all' && normalizeLogTag(photo.logTag, 'other') !== tag) return false;
  const keyword = String(state.photoSearchKeyword || '').trim().toLowerCase();
  if (!keyword) return true;
  return [
    photo.containerNumber,
    photo.folderTitle,
    photo.fileName,
    photo.createdByName,
    photo.createdBy,
    photo.questText,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
    .includes(keyword);
}

function filteredFolderPhotos() {
  return (photosForCurrentSummary() || []).filter(photoMatchesSearch);
}

async function runPhotoSearch() {
  const result = await runPhotoSearchState(appApi, state, {
    tag: els.logTagFilter?.value,
    keyword: els.photoSearchKeyword?.value,
    filterFolder: filteredFolderPhotos,
    onCriteriaChanged: syncSearchControls,
  });
  if (!result) return;
  renderSearchResults();
}

function renderSearchResults() {
  syncSearchControls();
  renderSearchResultsInto(els.searchPhotoList, state.searchPhotos, {
    translate: t, createTagBadge: createLogTagBadge, onPreview: openPhotoPreview,
  });
}

async function renderQuests() {
  if (!els.questList) return;
  els.questList.innerHTML = '';
  renderLogTagSummary();
  const quests = sortQuests(state.quests || [], state.questSort);
  if (!quests.length) {
    els.questList.appendChild(el('div', { class: 'muted' }, t('クエストはまだなかです。')));
    return;
  }
  quests.forEach((quest) => {
    const questActions = createQuestMutationActions(appApi, quest, {
      confirmDelete: () => window.confirm(t('このクエストを削除してよかですか？写真も消えます。')),
      reloadQuests: loadQuests,
      reloadFolder: loadFolderContent,
    });
    const commentActions = createQuestCommentMutationActions(appApi, quest, {
      confirmDelete: () => window.confirm(t('このコメントを削除してよかですか？')),
      reload: loadQuests,
    });
    const card = createQuestCardHeader(quest, {
      translate: t, formatDateTime, isAdmin: state.isAdmin, canDelete: canDelete(quest),
      onComplete: safeAction(questActions.complete, 'クエスト完了'),
      onDelete: safeAction(questActions.remove, 'クエスト削除'),
    });

    appendQuestPhotoArea(card, quest, {
      translate: t,
      createTagBadge: createLogTagBadge,
      canDelete,
      onPreview: openPhotoPreview,
      onDelete: safeAction((photo) => createPhotoMutationActions(appApi, photo, {
        confirmDelete: () => window.confirm(t('この写真を削除してよかですか？')),
        reload: loadFolderContent,
      }).remove(), '写真削除'),
      onFiles: (files) => rebuildUploadDrafts(files, quest.questId),
    });

    const commentWrap = createQuestCommentsSection(quest, {
      translate: t,
      formatDateTime,
      canDelete,
      onDelete: safeAction(commentActions.remove, 'コメント削除'),
      onAdd: safeAction(commentActions.add, 'コメント追加'),
    });
    card.appendChild(commentWrap);
    if (currentFolderMode() === 'quest') {
      const latestAt = quest.latestCommentAt || '';
      const latestBy = quest.latestCommentBy || '';
      const latestIncoming = latestAt && latestBy && latestBy !== state.userKey ? latestAt : '';
      if (latestIncoming) commentReadController.markAsRead(questReadKey(quest.questId), latestIncoming);
    }
    els.questList.appendChild(card);
  });
  if (state.uploadTargetQuestId) renderUploadDrafts();
  renderLogTagSummary();
  renderRentalComparison();
}

async function renderPhotos() {
  els.photoList.innerHTML = '';
  syncSearchControls();
  const photos = state.photos || [];
  renderLogTagSummary(photosForCurrentSummary());
  renderRentalComparison(photosForCurrentSummary());
  if (!photos.length) {
    const archived = state.selectedFolderArchive || null;
    const emptyText =
      archived && Number(archived.archivedCount || 0) > 0 && archived.archiveMode === 'hidden'
        ? t('表示中の写真はなかです。30日を過ぎた写真はアーカイブされとるばい。')
        : t('写真はまだなかです。');
    els.photoList.appendChild(el('div', { class: 'muted' }, emptyText));
    return;
  }
  for (const photo of photos) {
    const photoActions = createPhotoMutationActions(appApi, photo, {
      confirmDelete: () => window.confirm(t('この写真を削除してよかですか？')),
      beforeUpdate: () => preserveCurrentView(photo.photoId),
      reload: loadPhotos,
    });
    const photoCommentActions = createPhotoCommentMutationActions(appApi, photo, {
      confirmDelete: () => window.confirm(t('このコメントを削除してよかですか？')),
      beforeEdit: () => preserveCurrentView(photo.photoId),
      reload: loadPhotos,
    });
    const { card, editWrap: photoEditWrap } = createPhotoCardShell(photo, {
      translate: t, createTagBadge: createLogTagBadge, canEdit: canDelete(photo),
      ariaLabel: tf('{name} を全体表示', { name: photo.fileName || photo.photoId }),
      onPreview: openPhotoPreview,
    });

    const latestAt = photo.latestCommentAt || '';
    const latestBy = photo.latestCommentBy || '';
    const latestIncomingCommentAt = latestAt && latestBy && latestBy !== state.userKey ? latestAt : '';
    const unread = isUnread(photo.photoId, latestIncomingCommentAt);

    const {
      accordion, summary, commentLabel, commentWrap, textArea, addButton: addBtn,
    } = createPhotoCommentsAccordion({ unread, translate: t });
    const renderLoadedComments = (comments) => {
      commentWrap.innerHTML = '';
      comments.forEach((comment) => {
        commentWrap.appendChild(createPhotoCommentRow(comment, {
          translate: t,
          formatDateTime,
          editable: canDelete(comment),
          onEdit: photoCommentActions.edit,
          onDelete: photoCommentActions.remove,
        }));
      });
    };
    bindPhotoCommentsAccordionLifecycle({
      accordion, summary, commentWrap, commentLabel, photoId: photo.photoId,
      initiallyOpen: state.openAccordions.has(photo.photoId), translate: t,
      formatCommentLabel: (count) => tf('コメント ({count})', { count }),
      loadComments: () => loadComments(photo.photoId),
      getLatestIncoming: (comments) => commentReadController.latestIncoming(comments),
      renderComments: renderLoadedComments,
      onOpenChange: (open) => open ? state.openAccordions.add(photo.photoId) : state.openAccordions.delete(photo.photoId),
      onRead: (latest) => commentReadController.markAsRead(photo.photoId, latest),
      onAfterToggle: () => commentReadController.refreshSelectedFolder(),
    });

    addBtn.onclick = createPhotoCommentAddHandler(appApi, photo, {
      getText: () => textArea.value,
      setBusy: (busy) => { addBtn.disabled = busy; textArea.disabled = busy; },
      beforeAdd: () => {
        state.openAccordions.add(photo.photoId);
        state.restoreScrollY = window.scrollY;
      },
      reload: loadPhotos,
    });

    bindPhotoCardEditing({
      card, editWrap: photoEditWrap, photo, translate: t, createTagSelect: createLogTagSelect,
      onSave: (_photo, nextLogTag) => photoActions.updateLogTag(nextLogTag),
      onDelete: photoActions.remove,
    });

    appendPhotoCardComments(card, accordion, unread, t);
    els.photoList.appendChild(card);
  }
}

bindAuthControlEvents(els, {
  onLogin: safeAction(startLogin, 'ログイン'),
  onSignup: safeAction(startSignup, '新規登録'),
  onResetUser: safeAction(createDisplayNameChangeHandler(appApi, state, {
    promptName: (current) => window.prompt(t('新しい表示名を入力してください。'), current),
    onInvalid: () => window.alert(t('表示名は必須です。')),
    onSaved: () => {
      if (els.currentName) els.currentName.textContent = state.userName;
      renderTopStorageGraph();
      showToast(t('表示名を更新しました。'));
    },
    onFinished: closeMenu,
  }), '名前変更'),
  onLogout: () => {
    resetRoomContext();
    clearAuth();
    closeMenu();
    closeRoomCreateModal();
    closeFolderCreateModal();
    closeFolderPasswordModal();
    closeHelpModal();
    closeExportOptionsModal();
    closePhotoPreviewModal();
    if (hasCognitoConfig()) {
      window.location.href = cognitoClient.logoutUrl();
      return;
    }
    showAuthSetup();
  },
});

bindModalDismissEvents(els, [
  { modalKey: 'roomCreateModal', closeKey: 'roomCreateCloseBtn', close: closeRoomCreateModal },
  { modalKey: 'folderCreateModal', closeKey: 'folderCreateCloseBtn', close: closeFolderCreateModal },
  { modalKey: 'folderPasswordModal', closeKey: 'folderPasswordCloseBtn', close: closeFolderPasswordModal },
  { modalKey: 'helpModal', closeKey: 'helpCloseBtn', close: closeHelpModal },
  { modalKey: 'developerModal', closeKey: 'developerCloseBtn', close: closeDeveloperModal },
  { modalKey: 'photoPreviewModal', closeKey: 'photoPreviewCloseBtn', close: closePhotoPreviewModal },
  { modalKey: 'lowStorageModal', closeKey: 'lowStorageCloseBtn', close: closeLowStorageModal },
  { modalKey: 'exportOptionsModal', closeKey: 'exportOptionsCloseBtn', close: closeExportOptionsModal },
]);

bindExportControlEvents(els, {
  onCloseLoading: closeExportLoadingModal,
  onDownload: triggerExportDownload,
  onOpenTab: openExportInNewTab,
  onCopyLink: safeAction(copyExportLink, '出力リンクコピー'),
  onHighQuality: safeAction(async () => {
    closeExportOptionsModal();
    await requestFolderExport('pptx_high');
  }, '高画質PPT出力'),
  onLightweight: safeAction(async () => {
    closeExportOptionsModal();
    await requestFolderExport('pptx_light');
  }, '軽量PPT出力'),
  onPdf: safeAction(async () => {
    closeExportOptionsModal();
    await requestFolderExport('pdf');
  }, 'PDF出力'),
});

const leaveRoomHandler = createRoomLeaveHandler(appApi, {
      onAdminBlocked: () => window.alert(managementUi.leaveAdminBlocked()),
      onWarning: () => window.alert(managementUi.leaveWarning()),
      confirmLeave: () => window.confirm(managementUi.confirmLeave()),
      closeMenu, resetRoom: resetRoomContext, showSetup: showRoomSetup, reloadRooms: loadMyRooms,
});

bindManagementControlEvents(els, {
  onLeaveRoom: safeAction(leaveRoomHandler, '脱退'),
});

bindManagementControlEvents(els, {
  onRefreshRooms: safeAction(loadMyRooms, '一覧更新'),
  onOpenRoomCreate: safeAction(async () => { closeMenu(); openRoomCreateModal(); }, 'お部屋作成'),
  onOpenFolderCreate: safeAction(async () => { closeMenu(); openFolderCreateModal(); }, 'コンテナ登録'),
  onOpenFolderPassword: safeAction(async () => { closeMenu(); openFolderPasswordModal(); }, 'コンテナパスワード'),
  onOpenDeveloperDashboard: safeAction(openDeveloperDashboard, '開発者ダッシュボード'),
  onOpenHelpMenu: safeAction(async () => { closeMenu(); openHelpModal(); }, '使い方表示'),
  onOpenHelpUser: safeAction(openHelpModal, '使い方表示'),
});

const createRoomHandler = createRoomCreationHandler(appApi, state, () => els.roomCreateName?.value, {
      onInvalid: () => window.alert(roomCreationUi.invalid()),
      closeAdmin: closeTeamAdminPanel, resetRoom: resetRoomContext, showApp,
      onCreated: (roomName) => { closeRoomCreateModal(); window.alert(roomCreationUi.created(roomName)); },
      describeError: asMessage,
      onExistingRoom: () => window.alert(roomCreationUi.existingRoom()),
      onNameConflict: () => window.alert(roomCreationUi.nameConflict()),
      onError: (error) => window.alert(roomCreationUi.error(error)),
});

const createInitialRoomHandler = createRoomCreationHandler(appApi, state, () => els.createRoomName.value, {
    before: clearError,
    onInvalid: () => showError(roomCreationUi.invalid()),
    closeAdmin: closeTeamAdminPanel, resetRoom: resetRoomContext, showApp,
    onCreated: (roomName) => window.alert(roomCreationUi.created(roomName)),
    describeError: asMessage,
    onExistingRoom: () => window.alert(roomCreationUi.existingRoom()),
    onNameConflict: () => window.alert(roomCreationUi.nameConflict()),
    onError: (error) => showError(roomCreationUi.error(error)),
});

const createFolderHandler = createFolderCreationHandler(appApi, () => ({
  title: els.folderTitle.value, mode: els.folderMode?.value, password: els.folderPassword?.value,
}), {
    normalizeMode: normalizeFolderMode,
    onInvalid: () => {
      if (els.folderTitleError) { els.folderTitleError.textContent = folderCreationUi.invalid(); els.folderTitleError.classList.remove('hidden'); }
      if (els.folderTitle) els.folderTitle.focus();
    },
    onValid: () => els.folderTitleError?.classList.add('hidden'),
    getPlanLimit: (error) => { const body = parseApiErrorBody(error); return body?.code === 'FREE_PLAN_FOLDER_LIMIT_EXCEEDED' ? body : null; },
    onPlanLimit: (body) => window.alert(folderCreationUi.planLimit(body)),
    onCreated: (created) => {
      els.folderTitle.value = '';
      if (els.folderMode) els.folderMode.value = 'photo';
      if (els.folderPassword) els.folderPassword.value = '';
      closeFolderCreateModal();
      showToast(folderCreationUi.created(created));
    },
    reloadFolders: loadFolders, selectFolder: selectFolderById,
});

bindMutationControlEvents(els, {
  onCreateRoom: safeAction(createRoomHandler, 'お部屋作成'),
  onCreateInitialRoom: createInitialRoomHandler,
  onCreateFolder: safeAction(createFolderHandler, 'コンテナ登録'),
});

bindMutationControlEvents(els, {
  onUpload: safeAction(async () => {
    if (state.isUploading) return;
    await uploadFiles();
  }, '写真アップロード'),
  onCreateQuest: safeAction(async () => {
    await runQuestCreation(state, els, {
      text: els.questText?.value,
      createQuest: (folderId, text) => appApi.createQuest(folderId, text),
      onCreated: loadQuests,
    });
  }, 'クエスト作成'),
  onExport: safeAction(async () => {
    if (!state.selectedFolder) {
      window.alert(t('先にコンテナを選択してください。'));
      return;
    }
    closeMenu();
    openExportOptionsModal();
  }, 'PPT出力'),
});

bindUploadControlEvents(els, {
  onFilesChange: (event) => {
    const files = Array.from(event.target.files || []);
    rebuildUploadDrafts(files);
  },
  onFolderTitleInput: () => {
    if (els.folderTitle.value.trim() && els.folderTitleError) {
      els.folderTitleError.classList.add('hidden');
    }
  },
  onQuestSortChange: (event) => {
    state.questSort = event.target.value || 'status';
    renderQuests();
  },
  onApplyBulkComment: applyBulkComment,
  onCancelDrafts: cancelUploadDrafts,
});

bindManagementControlEvents(els, {
  onOpenTeamAdmin: safeAction(() => teamAdminController.toggle(), 'お部屋管理'),
  onCloseTeamAdmin: () => teamAdminController.close(),
});

async function startSubscriptionCheckout(plan) {
  const base = window.location.origin + window.location.pathname;
  const successUrl = `${base}?subscription=success&plan=${encodeURIComponent(plan)}&session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl = base;
  const res = await appApi.startSubscriptionCheckout({ plan, successUrl, cancelUrl });
  if (res && res.url) {
    window.location.href = res.url;
    return;
  }
  throw new Error(t('Stripe決済URLが取得できませんでした。'));
}

async function changeSubscriptionPlan(targetPlan) {
  return runSubscriptionPlanChange(state, targetPlan, {
    planRank: subscriptionPlanRank,
    confirmChange: ({ currentPlan, targetPlan: nextPlan, action }) =>
      window.confirm(subscriptionPlanChangeConfirmText(currentPlan, nextPlan, action)),
    startCheckout: startSubscriptionCheckout,
    changeSubscription: (change) => appApi.changeSubscription(change),
    reload: async () => { await loadTeamMe(); await loadAdminPanel(); },
    onChanged: ({ action, targetPlan: nextPlan }) => {
      window.alert(subscriptionPlanUi.successText(nextPlan, action));
    },
    invalidPlanError: () => new Error(t('プランが不正です。')),
  });
}

bindBillingControlEvents(els, {
  onBasic: safeAction(() => changeSubscriptionPlan('BASIC'), 'プラン変更'),
  onPlus: safeAction(() => changeSubscriptionPlan('PLUS'), 'プラン変更'),
  onPro: safeAction(() => changeSubscriptionPlan('PRO'), 'プラン変更'),
  onFree: safeAction(() => runFreePlanChange({
    confirmChange: () => window.confirm(freePlanReturnConfirmText()),
    changeSubscription: (change) => appApi.changeSubscription(change),
    getRequirements: (error) => {
      const body = parseApiErrorBody(error);
      return body?.code === 'FREE_PLAN_REQUIREMENTS_NOT_MET' ? body.constraints || {} : null;
    },
    showRequirements: (constraints) => window.alert(freePlanRequirementDialogText(constraints)),
    reload: async () => { await loadTeamMe(); await loadFolders(); await loadAdminPanel(); },
    onChanged: () => window.alert(freePlanReturnSuccessText()),
  }), 'フリープラン変更'),
  onLowStorageCharge: safeAction(() => lowStorageController.charge({
    closeModal: closeLowStorageModal,
    openAdmin: () => teamAdminController.open({ load: false }),
    loadAdmin: loadAdminPanel,
    changePlan: changeSubscriptionPlan,
  }), '容量チャージ'),
});

const deleteRoomHandler = createRoomDeleteHandler(appApi, {
      confirmDelete: () => window.confirm(managementUi.confirmRoomDelete()),
      confirmFinal: () => window.confirm(managementUi.confirmRoomDeleteFinal()),
      onDeleted: () => window.alert(managementUi.roomDeleted()),
      resetRoom: resetRoomContext,
      showSetup: showRoomSetup,
});
const deleteAccountHandler = createAccountDeleteHandler(appApi, {
      getOwnedRoom: getOwnedRoomForGuard,
      onOwnerBlocked: showOwnerDeleteGuard,
      confirmDelete: () => window.confirm(managementUi.confirmAccountDelete()),
      confirmFinal: () => window.confirm(managementUi.confirmAccountDeleteFinal()),
      isOwnerConflict: (error) => asMessage(error).includes('room owner must delete team first'),
      onOwnerConflict: () => window.alert(managementUi.accountOwnerConflict()),
      onDeleted: () => window.alert(managementUi.accountDeleted()),
      closeMenu, resetRoom: resetRoomContext, clearAuth, showAuth: showAuthSetup,
});

bindMutationControlEvents(els, {
  onDeleteTeam: safeAction(deleteRoomHandler, 'お部屋削除'),
  onDeleteAccount: safeAction(deleteAccountHandler, '削除'),
});
const deleteFolderHandler = createFolderDeleteHandler(appApi, state, () => state.selectedFolder, {
      confirmDelete: () => window.confirm(folderManagementUi.confirmDelete()),
      onDeleted: () => {
        window.alert(folderManagementUi.deleted());
        clearFolderSelectionState(state, {
          clearDrafts: clearUploadDrafts,
          hideDetail: () => els.folderDetail.classList.add('hidden'),
          renderArchive: renderPhotoArchiveNote,
        });
      },
      reloadFolders: loadFolders,
      reloadTeam: loadTeamMe,
      reloadPanel: loadAdminPanel,
});
const updateFolderPasswordHandler = createFolderPasswordHandler(appApi, state, () => ({
  folderId: state.selectedFolder?.folderId,
  password: els.folderPasswordSet?.value,
}), {
      onUpdated: () => {
        if (els.folderPasswordSet) els.folderPasswordSet.value = '';
        closeFolderPasswordModal();
        showToast(folderManagementUi.passwordUpdated());
      },
      reloadFolders: loadFolders,
});

bindMutationControlEvents(els, {
  onDeleteFolder: safeAction(deleteFolderHandler, 'コンテナ削除'),
  onSetFolderPassword: safeAction(updateFolderPasswordHandler, '鍵設定'),
});

bindGlobalAppEvents({
  elements: els,
  onUnhandledRejection: (event) => showError(appErrorUi.unhandled(event.reason)),
  onError: (event) => showError(appErrorUi.runtime(event.error || event.message)),
  onResize: syncTopStorageGraphWidth,
});

bindAppControlEvents(els, {
  onFolderChange: safeAction((event) => selectFolderById(event.target.value), 'コンテナ選択'),
  onRoomChange: safeAction((event) => runRoomChange(state, event.target.value, {
    confirmSwitch: () => window.confirm(t('現在のお部屋を切り替えます。よろしいですか？')),
    renderRoomSelect,
    switchRoom: switchRoomById,
  }), 'お部屋切替'),
  onRecordTab: () => setFolderDetailTab('record'),
  onSearchTab: safeAction(async () => {
    setFolderDetailTab('search');
    await runPhotoSearch();
  }, '検索タブ切替'),
  onSearchScopeFolder: safeAction(async () => {
    folderDetailController.setSearchScope('folder');
    await runPhotoSearch();
  }, '検索範囲切替'),
  onSearchScopeRoom: safeAction(async () => {
    folderDetailController.setSearchScope('room');
    await runPhotoSearch();
  }, '検索範囲切替'),
  onPhotoSearch: safeAction(async () => {
    await runPhotoSearch();
  }, '写真検索'),
  onLogTagChange: safeAction(async () => {
    await runPhotoSearch();
  }, 'タグ検索'),
});

startAppInitialization(initUser, { onError: (error) => {
  console.error(error);
  showError(appErrorUi.initialization(error));
} });
