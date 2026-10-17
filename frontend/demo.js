import { DEMO_PLAN_BYTES, DEMO_USER_KEY, createDemoPhoto, createDemoStore, demoNow, demoSvg } from './demo-seed.mjs?v=20260606-cong2';
import {
  DEFAULT_LOG_TAG, LOG_TAGS, appendFolderAdminActions, appendPhotoCardComments, appendQuestPhotoArea, asMessage, bindAppControlEvents, bindAuthControlEvents, bindBillingControlEvents, bindExportControlEvents, bindGlobalAppEvents, bindInviteControlEvents, bindManagementControlEvents, bindModalDismissEvents, bindMutationControlEvents, bindPhotoCardEditing, bindPhotoCommentsAccordionLifecycle, bindUploadControlEvents, collectAppElements, computeStorageStats, createAdminPanelUi, createAppErrorUi, createBillingStatusUi, createFolderAdminOverview, createFolderCreationUi, createFolderManagementUi, createFreePlanUi, createLogTagUi, createPhotoCardShell, createPhotoCommentRow, createPhotoCommentsAccordion, createPhotoPreviewImage, createQuestCardHeader, createQuestCommentsSection, createRoomCreationUi, createUploadDraftRow, downloadFileNameFromResponse, el, formatBytes,
  createManagementUi, createSubscriptionPlanUi, normalizeFolderMode, normalizeLogTag, parseApiErrorBody, renderBillingBarInto, renderCurrentRoomHeaderInto, renderFolderMembersInto, renderFolderModePanels, renderFolderSelectInto, renderLogTagSummaryInto, renderMyRoomsInto, renderPhotoArchiveNoteInto, renderRentalComparisonInto, renderRoomSelectInto, renderSearchResultsInto, renderStorageGraphInto, renderTeamMembersInto, renderTopStorageGraphInto, syncSearchControlsInto,
  planToProductLabel, questReadKey, questStatusText, renderUploadDraftContainerInto, resizeImageToJpeg, sortQuests, subscriptionPlanLimitBytes, subscriptionPlanRank, syncSubscriptionPlanButtonsInto, syncUploadDraftsFromRows, validateUploadDraftItems,
} from './app-core.js';
import { createDemoApi, createDemoBackend, createDemoRequest } from './api-demo.js';
import { clearFolderSelectionState, computeFolderUnreadState, copyInviteText, createActionBoundary, createAdminPanelOptions, createAppViewController, createBillingUiController, createCommentReadController, createDisplayNameChangeHandler, createExportProgressController, createExportResultController, createFolderCreationHandler, createFolderDeleteHandler, createFolderDetailController, createFolderPasswordHandler, createInitialAppState, createInviteHandlers, createLowStorageController, createPhotoCommentAddHandler, createPhotoCommentMutationActions, createPhotoMutationActions, createPhotoPreviewController, createQuestCommentMutationActions, createQuestMutationActions, createReadTracker, createRoomCreationHandler, createRoomDeleteHandler, createRoomLeaveHandler, createScreenController, createStorageGraphController, createTeamAdminController, createUploadDraftController, createUploadDraftEditor, createUploadLoadingController, ensureFolderPasswordState, ensureUserDisplayName, handleFolderListError, handleInvalidFolderPassword, loadFolderContentState, loadFolderListState, loadPhotoState, loadQuestState, loadRoomListState, loadTeamState, refreshFolderUnreadState, renderAdminPanel, renderBillingAdminState, renderFolderListState, resetRoomState, runActionWithHandledErrors, runFolderChange, runFolderExport, runFreePlanChange, runOwnerRoomSwitch, runPhotoSearchState, runQuestCreation, runRoomChange, runSubscriptionPlanChange, runUploadBatch, selectFolderState, startAppInitialization, switchRoomState } from './app-runtime.js';

const DEMO_EXPORT_ASSET_VERSION = '20260607-cong-i18n1';
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
let demoRequest;
const appApi = createDemoApi((path, options) => demoRequest(path, options), (folderId) => folderPasswordHeader(folderId));
if (I18N && !window.__KANSA_DEMO_DIALOG_I18N__) {
  window.__KANSA_DEMO_DIALOG_I18N__ = true;
  const nativeAlert = window.alert.bind(window);
  const nativeConfirm = window.confirm.bind(window);
  const nativePrompt = window.prompt.bind(window);
  window.alert = (message) => nativeAlert(t(String(message)));
  window.confirm = (message) => nativeConfirm(t(String(message)));
  window.prompt = (message, defaultValue) => nativePrompt(t(String(message)), defaultValue);
}

const state = createInitialAppState();

const readTracker = createReadTracker({ storage: localStorage, getUserKey: () => state.userKey });
const commentReadController = createCommentReadController(appApi, state, {
  readTracker, refreshFolderUnread, renderFolders,
});
const isUnread = (key, latestIncomingAt) => commentReadController.isUnread(key, latestIncomingAt);

function currentFolderMode() {
  return normalizeFolderMode(state.selectedFolder?.mode);
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

async function startLogin() {
  window.alert(t('デモではログイン不要です。このまま画面を触ってみてください。'));
}

async function startSignup() {
  window.alert(t('デモでは新規登録不要です。気になる動きだけそのまま試せます。'));
}

const els = collectAppElements(document);
const {
  closeMenu, closeTeamAdminPanel, closeRoomCreateModal, closeFolderCreateModal,
  closeFolderPasswordModal, closeThemeModal, closeHelpModal, closeLowStorageModal,
  closeExportOptionsModal,
} = createAppViewController(els, { onTeamAdminMode: setTeamAdminMode });
const exportProgress = createExportProgressController(els.exportLoadingBar, window);
const exportResultController = createExportResultController({
  elements: els, windowRef: window, documentRef: document, urlRef: URL,
  onCopied: () => showToast('リンクをコピーしました。'),
});
const photoPreviewController = createPhotoPreviewController(els);
const screenController = createScreenController(els);
const folderDetailController = createFolderDetailController(state, els, {
  renderMode: renderFolderMode,
  renderSearchControls: (criteria) => syncSearchControlsInto(els, criteria, t),
});
const uploadLoadingController = createUploadLoadingController(state, els);
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
    invalidTagMessage: (row) => `${row}行目: タグは必須です。`,
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
});
const syncTopStorageGraphWidth = () => storageGraphController.syncTopWidth();
const renderTopStorageGraph = () => storageGraphController.renderTop();
const renderStorageGraph = () => storageGraphController.renderAdmin();
const billingUiController = createBillingUiController(state, els, {
  renderTopGraph: renderTopStorageGraph, renderBillingBarInto,
  planLabel: planToDisplayLabel, translate: t,
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

function openExportLoadingModal(message = 'ダウンロードを開始しています...') {
  if (els.exportLoadingTitle) els.exportLoadingTitle.textContent = '出力中';
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
      els.exportLoadingText.textContent = `PDFをダウンロード中... ${Math.round((loaded / total) * 100)}%`;
    } else {
      els.exportLoadingText.textContent = `PDFをダウンロード中... ${Math.round(loaded / 1024)}KB`;
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
    els.exportLoadingText.textContent = 'PDFのダウンロードを開始しています...';
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
  closeThemeModal();
}

function openHelpModal() {
  if (!els.helpModal) return;
  els.helpModal.classList.remove('hidden');
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
    els.folderPasswordTargetName.textContent = `${folder.folderCode || 'F---'} ${folder.title || folder.folderId}`;
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

function buildDemoExportUrl(format) {
  const language = I18N?.language || 'ja';
  const languageSuffix = language === 'ja' ? '' : `-${String(language).toLowerCase()}`;
  const fileName =
    format === 'pdf'
      ? `demo-export-sample${languageSuffix}.pdf`
      : format === 'pptx_light'
        ? `demo-export-light-sample${languageSuffix}.pptx`
        : `demo-export-high-sample${languageSuffix}.pptx`;
  const url = new URL(`./demo-assets/${fileName}`, window.location.href);
  url.searchParams.set('v', DEMO_EXPORT_ASSET_VERSION);
  return url.href;
}

async function requestFolderExport(format) {
  return runFolderExport(appApi, state, format, {
    getFormatLabel: (value) => value === 'pdf' ? 'PDF' : value === 'pptx_light' ? t('軽量PPT') : t('高画質PPT'),
    onMissingFolder: () => window.alert(t('先にコンテナを選択してください。')),
    confirmExport: (label) => window.confirm(tf('{formatLabel}で出力します。よろしいですか？', { formatLabel: label })),
    onStart: (label) => { openExportLoadingModal(tf('{formatLabel} を生成しています...', { formatLabel: label })); startExportLoadingProgress(); },
    onDownloadReady: markExportLoadingDownloadReady,
    fetchDownload: (url) => fetch(url),
    downloadError: (status) => new Error(`PDFダウンロード失敗(${status})`),
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
}

function showError(message) {
  if (!els.errorBox) return;
  els.errorBox.textContent = t(String(message || ''));
  els.errorBox.classList.remove('hidden');
}

function clearError() {
  if (!els.errorBox) return;
  els.errorBox.textContent = '';
  els.errorBox.classList.add('hidden');
}

function currentFolderLimit() {
  return billingStatusUi.folderLimit(state.billing);
}

function folderUsageSummary() {
  return billingStatusUi.folderUsage(state.folders, state.billing);
}

function renderPhotoArchiveNote() {
  renderPhotoArchiveNoteInto(els.photoArchiveNote, state.selectedFolderArchive);
}

function syncSubscriptionPlanButtons() {
  syncSubscriptionPlanButtonsInto(els, state.billing, { translate: t });
}

function maybePromptLowStorage() {
  return lowStorageController.prompt();
}

function showToast(message) {
  if (!els.toast) return;
  els.toast.textContent = t(String(message || ''));
  els.toast.classList.remove('hidden');
  window.clearTimeout(showToast.timerId);
  showToast.timerId = window.setTimeout(() => {
    els.toast.classList.add('hidden');
  }, 2500);
}

async function ensureDisplayName() {
  return ensureUserDisplayName(appApi, state, {
    promptName: () => window.prompt(t('表示名を入力してください。メニューからいつでも変更可能です。')),
    onInvalid: () => window.alert(t('表示名は必須です。')),
    onSaved: () => showToast('表示名を設定しました。'),
  });
}

function padSequenceNumber(value) {
  return String(value).padStart(3, '0');
}

function buildDemoPhotoFileName(draft, index) {
  const container = String(state.selectedFolder?.title || 'CONTAINER').trim() || 'CONTAINER';
  const tag = logTagMeta(draft.logTag).label;
  return `${container}_${tag}_${padSequenceNumber(index + 1)}`;
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
        showToast(`プランを${label}へ更新しました。`);
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
  showToast('決済反映に少し時間がかかっとるばい。しばらくしてプラン表示ば確認してね。');
}

function preserveCurrentView(photoId) {
  if (photoId) {
    state.openAccordions.add(photoId);
  }
  state.restoreScrollY = window.scrollY;
}

async function initUser() {
  demoRecalculate();
  state.idToken = 'demo-token';
  state.userKey = DEMO_USER_KEY;
  state.userName = demoStore.me.displayName;
  if (!demoStore.activeRoomId) {
    const fallback = demoStore.rooms.find((room) => {
      const member = room.members.find((item) => item.userKey === DEMO_USER_KEY);
      return member && member.status === 'active';
    });
    demoStore.activeRoomId = fallback ? fallback.roomId : null;
  }
  if (els.logoutBtn) els.logoutBtn.textContent = 'LPに戻る';
  if (els.loginBtn) els.loginBtn.textContent = 'デモ中';
  if (els.signupBtn) els.signupBtn.textContent = '登録不要';
  if (demoStore.activeRoomId) showApp();
  else showRoomSetup();
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
  closeThemeModal();
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
    els.myRoomsList.textContent = '読み込み中...';
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

function folderPasswordHeader(folderId) {
  const pw = state.folderPasswordById[folderId];
  if (!pw) return {};
  return { 'x-folder-password': encodeURIComponent(pw) };
}

async function loadTeamMe() {
  await loadTeamState(appApi, state, { onError: (error) => {
    showError(`チーム情報取得失敗: ${asMessage(error)}（バックエンド/フロントのデプロイ差分やキャッシュの可能性）`);
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
    renderList: ({ folders, unreadById, selectedFolderId }) => renderFolderSelectInto(
      els.currentFolderSelect, folders, { unreadById, selectedFolderId, translate: t, photoModeLabel: '通常' }
    ),
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
    onMissing: () => { showError('コンテナパスワードが必要です。'); renderFolders(); },
  });
  if (!hasPassword) return;
  await runActionWithHandledErrors(() => selectFolderState(state, folder, {
      renderFolders,
      showDetail: () => els.folderDetail.classList.remove('hidden'),
      setRecordTab: () => setFolderDetailTab('record'),
      setDetailTitle: (selected) => {
        const modeLabel = normalizeFolderMode(selected.mode) === 'quest' ? 'クエスト' : '通常';
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
      onInvalid: () => showError('コンテナパスワードが違います。'),
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
  renderLogTagSummary();
  renderRentalComparison();
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
  renderLogTagSummary();
  renderRentalComparison();
  await refreshFolderUnread([folderId]);
  renderFolderMode();
  renderFolders();
}

async function loadFolderContent() {
  await loadFolderContentState(state, {
    mode: currentFolderMode(), loadQuests, loadPhotos,
    onQuestMode: renderPhotoArchiveNote, onRendered: renderFolderMode, onSearch: runPhotoSearch,
  });
}

async function uploadFiles() {
  await runUploadBatch(state, {
    syncDrafts: syncUploadDraftsFromDom,
    validateDrafts: validateUploadDrafts,
    onValidationError: (message) => { throw new Error(message); },
    setLoading: setUploadLoading,
    isDuplicate: (error) => asMessage(error).includes('APIエラー(409)'),
    uploadDraft: (draft, index, targetQuestId) => appApi.uploadPhoto({
      folderId: state.selectedFolder.folderId,
      file: draft.file,
      fileName: buildDemoPhotoFileName(draft, index),
      logTag: normalizeLogTag(draft.logTag),
      initialComment: String(draft.initialComment || '').trim() || null,
      questId: targetQuestId,
    }),
    onUploaded: async ({ totalFiles, uploadedCount, duplicateCount }) => {
      clearUploadDrafts();
      await loadFolderContent();
      await scrollToActiveList();
      if (duplicateCount > 0) {
        showToast(`${uploadedCount}/${totalFiles}件アップロード完了。${duplicateCount}件は重複のためスキップしました。`);
      } else {
        showToast(`${uploadedCount}/${totalFiles}件アップロード完了。`);
      }
    },
    onComplete: ({ totalFiles, uploadedCount, duplicateCount }) => {
      if (uploadedCount === 0) clearUploadDrafts();
      if (duplicateCount > 0) {
        if (totalFiles === 1) {
          showError('同じ写真は同じコンテナにアップロードできません（重複を検知しました）。');
          return;
        }
        if (duplicateCount === totalFiles) {
          showError('すべて重複なのでアップロードができません。');
          return;
        }
        if (uploadedCount === 0) showToast(`${duplicateCount}件は重複のためスキップしました。`);
      }
    },
    onError: async (error) => {
      const message = asMessage(error);
      if (message.includes('APIエラー(402)')) {
        await loadTeamMe();
        if (els.uploadBtn) els.uploadBtn.disabled = Boolean(state.uploadBlocked);
        showError('アップロード停止中です（残量不足）。管理者が容量チケットを追加するか、写真を削除してください。');
        return;
      }
      throw error;
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
    photo.originalName,
    photo.createdByName,
    photo.createdBy,
    photo.questText,
    photo.commentText,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase()
    .includes(keyword);
}

function filteredFolderPhotos() {
  const folderTitle = state.selectedFolder?.title || '';
  return (photosForCurrentSummary() || [])
    .map((photo) => ({ ...photo, containerNumber: folderTitle, folderTitle }))
    .filter(photoMatchesSearch);
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
  const quests = sortQuests(state.quests || [], state.questSort);
  if (!quests.length) {
    els.questList.appendChild(el('div', { class: 'muted' }, 'クエストはまだなかです。'));
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
}

async function renderPhotos() {
  els.photoList.innerHTML = '';
  if (!state.photos.length) {
    const archived = state.selectedFolderArchive || null;
    const emptyText =
      archived && Number(archived.archivedCount || 0) > 0 && archived.archiveMode === 'hidden'
        ? '表示中の写真はなかです。30日を過ぎた写真はアーカイブされとるばい。'
        : '写真はまだなかです。';
    els.photoList.appendChild(el('div', { class: 'muted' }, emptyText));
    return;
  }
  for (const photo of state.photos) {
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
      translate: t, createTagBadge: createLogTagBadge, canEdit: canDelete(photo), onPreview: openPhotoPreview,
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
      showToast('表示名を更新しました。');
    },
    onFinished: closeMenu,
  }), '名前変更'),
  onLogout: () => {
    window.location.href = './landing.html';
  },
  onDeleteAccount: () => {
    closeMenu();
    window.alert(t('デモではアカウント削除は行いません。'));
  },
});

bindModalDismissEvents(els, [
  { modalKey: 'roomCreateModal', closeKey: 'roomCreateCloseBtn', close: closeRoomCreateModal },
  { modalKey: 'folderCreateModal', closeKey: 'folderCreateCloseBtn', close: closeFolderCreateModal },
  { modalKey: 'folderPasswordModal', closeKey: 'folderPasswordCloseBtn', close: closeFolderPasswordModal },
  { modalKey: 'helpModal', closeKey: 'helpCloseBtn', close: closeHelpModal },
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
  onExport: safeAction(openExportForSelectedContainer, 'PPT出力'),
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

async function openExportForSelectedContainer() {
  if (!state.selectedFolder) {
    window.alert(t('先にコンテナを選択してください。'));
    return;
  }

  // クエスト記録は出力不可
  if (normalizeFolderMode(state.selectedFolder.mode) === 'quest') {
    window.alert(t('デモではクエスト記録は出力できません。'));
    return;
  }

  closeMenu();
  openExportOptionsModal();
}

bindManagementControlEvents(els, {
  onOpenTeamAdmin: safeAction(() => teamAdminController.toggle(), 'お部屋管理'),
  onCloseTeamAdmin: () => teamAdminController.close(),
});

async function startSubscriptionCheckout(plan) {
  const activeRoom = demoGetActiveRoom();
  if (!activeRoom) throw new Error('お部屋がありません。');
  activeRoom.subscriptionPlan = String(plan || 'FREE').toUpperCase();
  demoRecalculate();
  await loadTeamMe();
  await loadFolders();
  await loadAdminPanel();
  window.alert(tf('デモでは {plan} に切り替えた状態を表示します。', {
    plan: planToDisplayLabel(activeRoom.subscriptionPlan),
  }));
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
    invalidPlanError: () => new Error('プランが不正です。'),
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

bindMutationControlEvents(els, {
  onDeleteTeam: safeAction(deleteRoomHandler, 'お部屋削除'),
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
  onSearchKeywordKeydown: (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    safeAction(async () => {
      await runPhotoSearch();
    }, '写真検索')();
  },
  onRoomChange: safeAction((event) => runRoomChange(state, event.target.value, {
    confirmSwitch: () => window.confirm(t('現在のお部屋を切り替えます。よろしいですか？')),
    renderRoomSelect,
    switchRoom: switchRoomById,
  }), 'お部屋切替'),
});

const demoStore = createDemoStore();

function applyRentalDemoStore(store) {
  if (!window.KANSA_MARKET?.isRental) return store;
  const replacements = [
    ['港湾デモ管理者', '賃貸デモ管理者'],
    ['〇〇港運株式会社', 'さくら不動産管理'],
    ['△△コンテナ株式会社', '青葉原状回復サービス'],
    ['TCLU1234567', '桜町マンション 203号室'],
    ['MSCU7654321', '青葉コーポ 105号室'],
    ['NYKU2468101', '若葉ハイツ 301号室'],
    ['ゲート担当', '入居点検担当'],
    ['ヤード担当', '退去立会担当'],
    ['シール確認担当', '設備確認担当'],
    ['損傷確認担当', '原状回復担当'],
    ['事務所確認者', '管理会社確認者'],
    ['乙仲担当', '修繕業者'],
  ];
  const transformText = (value) => {
    const specific = replacements.reduce(
      (result, [from, to]) => result.split(from).join(to),
      String(value || '')
    );
    return window.KANSA_MARKET.translate(specific, 'ja', specific);
  };
  const transform = (value, key = '') => {
    if (Array.isArray(value)) return value.map((item) => transform(item));
    if (value && typeof value === 'object') {
      Object.entries(value).forEach(([childKey, childValue]) => {
        value[childKey] = transform(childValue, childKey);
      });
      return value;
    }
    if (typeof value === 'string' && !['viewUrl', 'previewUrl'].includes(key)) return transformText(value);
    return value;
  };
  transform(store);

  const photoVisuals = {
    container_number: ['部屋全体', '#06224A', '#dcecff'],
    inbound: ['入居時', '#1E90FF', '#dcecff'],
    outbound: ['退去時', '#2E7D32', '#d9f0df'],
    seal: ['設備', '#7C4DFF', '#e7ddff'],
    damage: ['傷・汚れ', '#E53935', '#ffe0de'],
    other: ['その他', '#607D8B', '#e5e7eb'],
  };
  (store.rooms || []).forEach((room) => {
    (room.folders || []).forEach((folder) => {
      (folder.photos || []).forEach((photo) => {
        const [label, toneA, toneB] = photoVisuals[photo.logTag] || photoVisuals.other;
        photo.viewUrl = demoSvg(label, toneA, toneB);
        photo.previewUrl = photo.viewUrl;
      });
    });
  });
  return store;
}

applyRentalDemoStore(demoStore);

const demoBackend = createDemoBackend({
  store: demoStore,
  planBytes: DEMO_PLAN_BYTES,
  userKey: DEMO_USER_KEY,
  now: demoNow,
  createPhoto: createDemoPhoto,
  createPhotoVisual: demoSvg,
  buildExportUrl: buildDemoExportUrl,
  planRank: subscriptionPlanRank,
  translate: t,
  defaultLogTag: DEFAULT_LOG_TAG,
  normalizeFolderMode,
  normalizeLogTag,
  questStatusText,
});
const { getActiveRoom: demoGetActiveRoom, recalculate: demoRecalculate } = demoBackend;

demoRequest = createDemoRequest({
  clearError,
  demoBackend,
});

startAppInitialization(initUser, { onError: (error) => {
  console.error(error);
  showError(appErrorUi.initialization(error));
} });
