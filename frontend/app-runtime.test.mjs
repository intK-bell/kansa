import assert from 'node:assert/strict';
import test from 'node:test';
import { clearFolderSelectionState, computeFolderUnreadState, copyInviteText, createAccountDeleteHandler, createActionBoundary, createAdminFolderInvite, createAdminFolderSection, createAdminMemberSection, createAdminPanelOptions, createAdminSelectedFolderRenderer, createAppViewController, createBillingUiController, createCommentReadController, createDisplayNameChangeHandler, createExportProgressController, createExportResultController, createFolderCreationHandler, createFolderDeleteHandler, createFolderDetailController, createFolderPasswordHandler, createInitialAppState, createInviteHandlers, createInviteToken, createLowStorageController, createPhotoCommentAddHandler, createPhotoCommentMutationActions, createPhotoMutationActions, createPhotoPreviewController, createQuestCommentMutationActions, createQuestMutationActions, createReadTracker, createRoomCreationHandler, createRoomDeleteHandler, createRoomLeaveHandler, createScreenController, createStorageGraphController, createTeamAdminController, createUploadDraftController, createUploadDraftEditor, createUploadLoadingController, ensureFolderPasswordState, ensureUserDisplayName, handleFolderListError, handleInvalidFolderPassword, loadAdminFolderMembers, loadAdminPanelState, loadFolderContentState, loadFolderListState, loadPhotoState, loadQuestState, loadRoomListState, loadTeamState, refreshFolderUnreadState, renderAdminPanel, renderAdminPanelSection, renderBillingAdminState, renderFolderListState, resetRoomState, revokeAdminFolderInvite, revokeInviteToken, runAccountDelete, runActionWithHandledErrors, runAdminFolderDelete, runAdminFolderMemberRemove, runFolderChange, runFolderCreation, runFolderDelete, runFolderExport, runFolderPasswordUpdate, runFreePlanChange, runOwnerRoomSwitch, runPhotoSearchState, runQuestCreation, runRoomChange, runRoomCreation, runRoomDelete, runRoomLeave, runSubscriptionPlanChange, runTeamMemberUpdate, runUploadBatch, saveUserDisplayName, selectAdminFolder, selectFolderState, startAppInitialization, switchRoomState } from './app-runtime.js';

test('creates isolated application state', () => {
  const first = createInitialAppState();
  const second = createInitialAppState({ userKey: 'demo-user' });
  first.folders.push({ folderId: 'f1' });
  first.openAccordions.add('p1');
  assert.equal(second.userKey, 'demo-user');
  assert.deepEqual(second.folders, []);
  assert.equal(second.openAccordions.size, 0);
});

test('tracks incoming comment reads per user', () => {
  const values = new Map();
  const storage = {
    getItem: (key) => values.get(key) || null,
    setItem: (key, value) => values.set(key, value),
  };
  let userKey = 'user-1';
  const tracker = createReadTracker({ storage, getUserKey: () => userKey });
  const latest = tracker.latestIncomingAt([
    { createdBy: 'user-1', createdAt: '2026-08-11T10:00:00Z' },
    { createdBy: 'user-2', createdAt: '2026-08-11T11:00:00Z' },
  ]);
  assert.equal(latest, '2026-08-11T11:00:00Z');
  assert.equal(tracker.isUnread('photo-1', latest), true);
  tracker.markAsRead('photo-1', latest);
  assert.equal(tracker.isUnread('photo-1', latest), false);
  userKey = 'user-2';
  assert.equal(tracker.isUnread('photo-1', latest), true);
});

test('closes shared views through the runtime controller', () => {
  const hidden = [];
  const element = (key) => ({ classList: { add: (name) => hidden.push([key, name]) } });
  const elements = {
    menuPanel: element('menu'), teamAdminCard: element('team'), folderPasswordModal: element('password'),
    folderPasswordTargetName: { textContent: 'Container' }, themeModal: element('theme'), developerModal: element('developer'),
  };
  let adminMode = true;
  const controller = createAppViewController(elements, { onTeamAdminMode: (value) => { adminMode = value; } });
  controller.closeMenu();
  controller.closeTeamAdminPanel();
  controller.closeFolderPasswordModal();
  controller.closeThemeModal();
  controller.closeDeveloperModal();
  assert.equal(adminMode, false);
  assert.equal(elements.folderPasswordTargetName.textContent, '-');
  assert.deepEqual(hidden, [
    ['menu', 'hidden'], ['team', 'hidden'], ['password', 'hidden'], ['theme', 'hidden'], ['developer', 'hidden'],
  ]);
});

test('controls export progress and clears timers', () => {
  let intervalHandler = null;
  let cleared = 0;
  const windowRef = {
    setInterval(handler) { intervalHandler = handler; return 7; },
    clearInterval(id) { if (id === 7) cleared += 1; },
  };
  const bar = { style: {}, classList: { remove() {} } };
  const progress = createExportProgressController(bar, windowRef);
  progress.start();
  assert.equal(bar.style.width, '0%');
  intervalHandler();
  assert.equal(bar.style.width, '0.9%');
  progress.update(50, 100);
  assert.equal(bar.style.width, '80%');
  progress.markDownloadReady();
  assert.equal(bar.style.width, '60%');
  progress.complete();
  assert.equal(bar.style.width, '100%');
  assert.equal(cleared, 1);
});

test('controls export results and browser actions', async () => {
  const opened = [];
  const copied = [];
  const revoked = [];
  const link = { style: {}, clickCount: 0, click() { this.clickCount += 1; } };
  const elements = {
    exportLoadingTitle: {}, exportLoadingText: {}, exportLoadingBar: { style: {} },
    exportLoadingActions: { classList: { remove() {} } }, exportLoadingCloseBtn: { classList: { remove() {} } },
  };
  const controller = createExportResultController({
    elements,
    windowRef: { location: {}, open: (...args) => opened.push(args) },
    documentRef: { createElement: () => link, body: { appendChild() {}, removeChild() {} } },
    urlRef: { revokeObjectURL: (url) => revoked.push(url) },
    clipboard: { writeText: async (value) => copied.push(value) },
  });
  controller.show({ formatLabel: 'PDF', downloadUrl: 'https://download', fileName: 'report.pdf', objectUrl: 'blob:report' });
  assert.equal(elements.exportLoadingTitle.textContent, '生成完了');
  controller.download();
  assert.equal(link.clickCount, 1);
  assert.equal(link.download, 'report.pdf');
  controller.openInNewTab();
  assert.equal(opened[0][0], 'blob:report');
  await controller.copyLink();
  assert.deepEqual(copied, ['https://download']);
  controller.clear();
  assert.deepEqual(revoked, ['blob:report']);
});

test('opens and closes photo previews with injected labels', () => {
  const classes = [];
  const image = { removeAttribute: (name) => { image.removed = name; } };
  const elements = {
    photoPreviewModal: { classList: { add: (name) => classes.push(['add', name]), remove: (name) => classes.push(['remove', name]) } },
    photoPreviewImage: image,
    photoPreviewTitle: {},
  };
  const controller = createPhotoPreviewController(elements, {
    emptyTitle: () => 'Empty', titleFor: (photo) => `Title ${photo.photoId}`, altFor: () => 'Preview alt',
  });
  assert.equal(controller.open({ photoId: 'p1', previewUrl: 'preview.jpg' }), true);
  assert.equal(image.src, 'preview.jpg');
  assert.equal(image.alt, 'Preview alt');
  assert.equal(elements.photoPreviewTitle.textContent, 'Title p1');
  controller.close();
  assert.equal(image.removed, 'src');
  assert.equal(elements.photoPreviewTitle.textContent, 'Empty');
  assert.deepEqual(classes, [['remove', 'hidden'], ['add', 'hidden']]);
});

test('switches authentication, room setup, and app screens', () => {
  const element = () => ({ hidden: null, classList: { toggle(_name, value) { this.owner.hidden = value; }, owner: null } });
  const elements = Object.fromEntries(['userSetup', 'roomSetup', 'app', 'globalMenuWrap', 'logoutBtn', 'currentName'].map((key) => [key, element()]));
  Object.values(elements).forEach((node) => { node.classList.owner = node; });
  const controller = createScreenController(elements);
  controller.showAuth();
  assert.deepEqual([elements.userSetup.hidden, elements.roomSetup.hidden, elements.app.hidden], [false, true, true]);
  controller.showRoomSetup({ authenticated: true });
  assert.equal(elements.globalMenuWrap.hidden, false);
  assert.equal(elements.logoutBtn.hidden, false);
  controller.showApp({ userName: 'Aoki' });
  assert.deepEqual([elements.userSetup.hidden, elements.roomSetup.hidden, elements.app.hidden], [true, true, false]);
  assert.equal(elements.currentName.textContent, 'Aoki');
});

test('resets room-scoped state without clearing the user', () => {
  const state = createInitialAppState({ userKey: 'user-1', roomId: 'room-1', roomName: 'Room', photos: [{ photoId: 'p1' }] });
  state.openAccordions.add('p1');
  resetRoomState(state);
  assert.equal(state.userKey, 'user-1');
  assert.equal(state.roomId, null);
  assert.deepEqual(state.photos, []);
  assert.equal(state.openAccordions.size, 0);
  assert.equal(state.photoSearchScope, 'folder');
});

test('runs application initialization with shared error handling', async () => {
  let errorMessage = '';
  assert.equal(await startAppInitialization(async () => undefined), true);
  assert.equal(await startAppInitialization(async () => { throw new Error('broken'); }, {
    onError: (error) => { errorMessage = error.message; },
  }), false);
  assert.equal(errorMessage, 'broken');
});

test('absorbs handled domain errors and rethrows unhandled errors', async () => {
  const handledError = new Error('handled');
  const handled = await runActionWithHandledErrors(async () => { throw handledError; }, {
    handleError: (error) => error === handledError,
  });
  assert.equal(handled.ok, false);
  assert.equal(handled.handled, true);
  await assert.rejects(runActionWithHandledErrors(async () => { throw new Error('unhandled'); }, {
    handleError: () => false,
  }), /unhandled/);
  assert.deepEqual(await runActionWithHandledErrors(async () => 42), { ok: true, value: 42 });
});

test('validates, confirms, and switches room changes', async () => {
  const state = createInitialAppState({
    roomId: 'r1', availableRooms: [
      { roomId: 'r2', roomName: 'Room 2', memberStatus: 'active' },
      { roomId: 'r3', roomName: 'Room 3', memberStatus: 'disabled' },
    ],
  });
  const calls = [];
  const options = {
    confirmSwitch: (room) => { calls.push(`confirm:${room.roomId}`); return true; },
    renderRoomSelect: () => calls.push('render'),
    switchRoom: async (roomId, roomName) => calls.push(`switch:${roomId}:${roomName}`),
  };
  assert.equal((await runRoomChange(state, 'r1', options)).status, 'unchanged');
  assert.equal((await runRoomChange(state, 'r3', options)).status, 'unavailable');
  assert.equal((await runRoomChange(state, 'r2', options)).status, 'switched');
  assert.deepEqual(calls, ['render', 'render', 'confirm:r2', 'switch:r2:Room 2']);
});

test('restores room selection after cancellation and switch errors', async () => {
  const state = createInitialAppState({ roomId: 'r1', availableRooms: [{ roomId: 'r2', roomName: 'Room 2' }] });
  let renders = 0;
  const cancelled = await runRoomChange(state, 'r2', {
    confirmSwitch: () => false, renderRoomSelect: () => { renders += 1; },
  });
  assert.equal(cancelled.status, 'cancelled');
  await assert.rejects(runRoomChange(state, 'r2', {
    confirmSwitch: () => true,
    renderRoomSelect: () => { renders += 1; },
    switchRoom: async () => { throw new Error('switch failed'); },
  }), /switch failed/);
  assert.equal(renders, 2);
});

test('resolves folder change IDs and handles clear or missing selections', async () => {
  const state = createInitialAppState({ folders: [{ folderId: 'f1', title: 'Folder' }] });
  const calls = [];
  const options = {
    clearSelection: () => calls.push('clear'),
    selectFolder: (folder) => calls.push(`select:${folder.folderId}`),
    onMissing: (folderId) => calls.push(`missing:${folderId}`),
  };
  assert.equal((await runFolderChange(state, '', options)).status, 'cleared');
  assert.equal((await runFolderChange(state, 'unknown', options)).status, 'missing');
  const selected = await runFolderChange(state, 'f1', options);
  assert.equal(selected.status, 'selected');
  assert.equal(selected.folder, state.folders[0]);
  assert.deepEqual(calls, ['clear', 'missing:unknown', 'select:f1']);
});

test('orchestrates subscription checkout and plan changes', async () => {
  const rank = (plan) => ({ FREE: 0, BASIC: 1, PLUS: 2 }[plan] || 0);
  const calls = [];
  const prepaid = createInitialAppState({ billing: { billingMode: 'prepaid', subscription: { currentPlan: 'FREE' } } });
  const checkout = await runSubscriptionPlanChange(prepaid, 'basic', {
    planRank: rank,
    confirmChange: ({ action }) => { calls.push(`confirm:${action}`); return true; },
    startCheckout: (plan) => calls.push(`checkout:${plan}`),
  });
  assert.equal(checkout.status, 'checkout');

  const subscribed = createInitialAppState({ billing: { billingMode: 'subscription', subscription: { currentPlan: 'BASIC' } } });
  const changed = await runSubscriptionPlanChange(subscribed, 'PLUS', {
    planRank: rank,
    confirmChange: ({ action }) => { calls.push(`confirm:${action}`); return true; },
    changeSubscription: (change) => { calls.push(`change:${change.action}:${change.targetPlan}`); return { ok: true }; },
    reload: () => calls.push('reload'),
    onChanged: ({ action }) => calls.push(`changed:${action}`),
  });
  assert.deepEqual(changed, { status: 'changed', action: 'upgrade', targetPlan: 'PLUS', result: { ok: true } });
  assert.deepEqual(calls, ['confirm:checkout', 'checkout:BASIC', 'confirm:upgrade', 'change:upgrade:PLUS', 'reload', 'changed:upgrade']);
});

test('guards unchanged, cancelled, and invalid subscription plans', async () => {
  const state = createInitialAppState({ billing: { billingMode: 'subscription', subscription: { currentPlan: 'BASIC' } } });
  const rank = (plan) => ({ BASIC: 1, PLUS: 2 }[plan] || 0);
  assert.equal((await runSubscriptionPlanChange(state, 'BASIC', { planRank: rank })).status, 'unchanged');
  assert.equal((await runSubscriptionPlanChange(state, 'PLUS', {
    planRank: rank, confirmChange: () => false,
  })).status, 'cancelled');
  await assert.rejects(runSubscriptionPlanChange(state, 'UNKNOWN', {
    planRank: rank, invalidPlanError: () => new Error('bad plan'),
  }), /bad plan/);
});

test('orchestrates free plan changes and reloads state', async () => {
  const calls = [];
  const result = await runFreePlanChange({
    confirmChange: () => true,
    changeSubscription: (change) => { calls.push(change.action); return { plan: 'FREE' }; },
    reload: () => calls.push('reload'),
    onChanged: (changed) => calls.push(`changed:${changed.plan}`),
  });
  assert.deepEqual(result, { status: 'changed', result: { plan: 'FREE' } });
  assert.deepEqual(calls, ['free', 'reload', 'changed:FREE']);
});

test('handles free plan cancellation, requirements, and unknown errors', async () => {
  assert.equal((await runFreePlanChange({ confirmChange: () => false })).status, 'cancelled');
  let shown;
  const requirements = await runFreePlanChange({
    changeSubscription: async () => { throw new Error('requirements'); },
    getRequirements: () => ({ folders: 3 }),
    showRequirements: (value) => { shown = value; },
  });
  assert.equal(requirements.status, 'requirements-not-met');
  assert.deepEqual(shown, { folders: 3 });
  await assert.rejects(runFreePlanChange({
    changeSubscription: async () => { throw new Error('network'); }, getRequirements: () => null,
  }), /network/);
});

test('loads team, room, and folder state through shared orchestration', async () => {
  const state = createInitialAppState({ idToken: 'token' });
  const api = {
    getTeam: async () => ({ roomId: 'r1', roomName: 'Room', role: 'admin', isAdmin: true, billing: { usageBytes: 1 } }),
    listRooms: async () => ({ activeRoomId: 'r1', items: [
      { roomId: 'r1', roomName: 'Room', memberStatus: 'active' },
      { roomId: 'r2', roomName: 'Left', memberStatus: 'left' },
    ] }),
    listFolders: async () => ({ items: [{ folderId: 'f1' }] }),
  };
  await loadTeamState(api, state);
  const rooms = await loadRoomListState(api, state);
  let refreshed = 0;
  await loadFolderListState(api, state, { refreshUnread: () => { refreshed += 1; } });
  assert.equal(state.roomName, 'Room');
  assert.equal(state.isAdmin, true);
  assert.equal(rooms.activeRoomId, 'r1');
  assert.deepEqual(state.availableRooms.map((room) => room.roomId), ['r1']);
  assert.deepEqual(state.folders, [{ folderId: 'f1' }]);
  assert.equal(refreshed, 1);
});

test('resets failed team and folder loads', async () => {
  const state = createInitialAppState({ roomId: 'r1', isAdmin: true, folders: [{ folderId: 'f1' }] });
  const api = { getTeam: async () => { throw new Error('team'); }, listFolders: async () => { throw new Error('folders'); } };
  const errors = [];
  await loadTeamState(api, state, { onError: (error) => errors.push(error.message) });
  await loadFolderListState(api, state, { onError: (error) => errors.push(error.message) });
  assert.equal(state.roomId, null);
  assert.equal(state.isAdmin, false);
  assert.deepEqual(state.folders, []);
  assert.deepEqual(errors, ['team', 'folders']);
});

test('switches room state after resetting old context', async () => {
  const state = createInitialAppState({ roomId: 'old', photos: [{ photoId: 'p1' }] });
  const order = [];
  await switchRoomState({ switchRoom: async () => ({ roomName: 'New Room' }) }, state, 'new', '', {
    beforeReset: () => order.push('before'),
    reset: () => { order.push('reset'); resetRoomState(state); },
    onReady: ({ roomName }) => order.push(`ready:${roomName}`),
  });
  assert.equal(state.roomId, 'new');
  assert.equal(state.roomName, 'New Room');
  assert.deepEqual(state.photos, []);
  assert.deepEqual(order, ['before', 'reset', 'ready:New Room']);
});

test('loads folder content by mode and optional search state', async () => {
  const state = createInitialAppState({ photos: [{ photoId: 'old' }], folderDetailTab: 'search' });
  const order = [];
  await loadFolderContentState(state, {
    mode: 'quest', loadQuests: () => order.push('quests'), loadPhotos: () => order.push('photos'),
    onQuestMode: () => order.push('archive'), onRendered: () => order.push('render'), onSearch: () => order.push('search'),
  });
  assert.deepEqual(state.photos, []);
  assert.equal(state.selectedFolderArchive, null);
  assert.deepEqual(order, ['archive', 'quests', 'render', 'search']);
});

test('loads photo archive and quest state', async () => {
  const state = createInitialAppState();
  const api = {
    listPhotos: async () => ({ items: [{ photoId: 'p1' }], archivedCount: '2', archiveMode: '', archiveDays: 0 }),
    listQuests: async () => ({ items: [{ questId: 'q1' }] }),
  };
  await loadPhotoState(api, state, 'f1');
  await loadQuestState(api, state, 'f1');
  assert.deepEqual(state.photos, [{ photoId: 'p1' }]);
  assert.deepEqual(state.selectedFolderArchive, { archivedCount: 2, archiveMode: 'visible', archiveDays: 30 });
  assert.deepEqual(state.quests, [{ questId: 'q1' }]);
});

test('updates folder and room photo search state', async () => {
  const state = createInitialAppState({ photoSearchScope: 'folder' });
  let criteriaUpdates = 0;
  await runPhotoSearchState({}, state, {
    tag: '', keyword: '  pipe  ', filterFolder: () => [{ photoId: 'folder-photo' }],
    onCriteriaChanged: () => { criteriaUpdates += 1; },
  });
  assert.equal(state.photoSearchTag, 'all');
  assert.equal(state.photoSearchKeyword, 'pipe');
  assert.deepEqual(state.searchPhotos, [{ photoId: 'folder-photo' }]);

  state.photoSearchScope = 'room';
  state.roomId = 'r1';
  const api = { searchPhotos: async (query) => ({ items: [{ photoId: query.keyword }], nextToken: 'next-1' }) };
  await runPhotoSearchState(api, state, { tag: 'other', keyword: ' bolt ' });
  assert.deepEqual(state.searchPhotos, [{ photoId: 'bolt' }]);
  assert.equal(state.roomSearchNextToken, 'next-1');
  assert.equal(criteriaUpdates, 1);
});

test('runs upload batches and aggregates duplicates', async () => {
  const state = createInitialAppState({
    uploadDrafts: [{ localId: 'a' }, { localId: 'b' }], uploadTargetQuestId: 'q1',
  });
  const loading = [];
  let completed;
  const result = await runUploadBatch(state, {
    uploadDraft: async (draft, index, questId) => {
      assert.equal(questId, 'q1');
      if (index === 1) throw new Error('duplicate');
      assert.equal(draft.localId, 'a');
    },
    isDuplicate: (error) => error.message === 'duplicate',
    setLoading: (value) => { state.isUploading = value; loading.push(value); },
    onUploaded: (summary) => { assert.equal(summary.uploadedCount, 1); },
    onComplete: (summary) => { completed = summary; },
  });
  assert.equal(result.duplicateCount, 1);
  assert.deepEqual(result.uploadedDraftIds, ['a']);
  assert.equal(completed.totalFiles, 2);
  assert.deepEqual(loading, [true, false]);
});

test('stops invalid upload batches before loading state changes', async () => {
  const state = createInitialAppState({ uploadDrafts: [{ localId: 'a' }] });
  let validationMessage = '';
  const result = await runUploadBatch(state, {
    validateDrafts: () => ['invalid tag'],
    uploadDraft: () => { throw new Error('must not upload'); },
    onValidationError: (message) => { validationMessage = message; },
  });
  assert.equal(result.status, 'invalid');
  assert.equal(validationMessage, 'invalid tag');
  assert.equal(state.isUploading, false);
});

test('manages upload draft previews and target lifecycle', () => {
  const state = createInitialAppState({ uploadDrafts: [{ localId: 'old', previewUrl: 'blob:old' }] });
  const revoked = [];
  let renders = 0;
  const controller = createUploadDraftController(state, {
    urlRef: { createObjectURL: (file) => `blob:${file.name}`, revokeObjectURL: (url) => revoked.push(url) },
    now: () => 123, defaultLogTag: 'general', onRender: () => { renders += 1; },
  });
  controller.rebuild([{ name: 'a.jpg' }, { name: 'b.jpg' }], 'q1');
  assert.equal(state.uploadTargetQuestId, 'q1');
  assert.equal(state.uploadDrafts[0].localId, '123_0_a.jpg');
  controller.remove(['123_0_a.jpg']);
  assert.deepEqual(revoked, ['blob:old', 'blob:a.jpg']);
  controller.clear();
  assert.deepEqual(state.uploadDrafts, []);
  assert.equal(state.uploadTargetQuestId, null);
  assert.equal(renders, 3);
});

test('toggles upload loading controls', () => {
  const node = () => ({ disabled: false, textContent: '', classList: { values: [], toggle(name, value) { this.values.push([name, value]); } } });
  const state = createInitialAppState();
  const elements = { uploadBtn: node(), photoFiles: node(), applyCommentBulkBtn: node(), cancelUploadDraftsBtn: node(), uploadLoading: node() };
  const extra = node();
  const controller = createUploadLoadingController(state, elements, { getExtraFileInputs: () => [extra] });
  controller.set(true);
  assert.equal(state.isUploading, true);
  assert.equal(elements.uploadBtn.textContent, 'アップロード中...');
  assert.equal(elements.photoFiles.disabled, true);
  assert.equal(extra.disabled, true);
  controller.set(false);
  assert.equal(elements.uploadBtn.textContent, 'アップロード');
});

test('validates and bulk-edits upload draft comments', () => {
  const state = createInitialAppState({ uploadDrafts: [{ initialComment: ' first ' }, { initialComment: 'old' }] });
  let renders = 0;
  const editor = createUploadDraftEditor(state, {
    sync: () => { state.uploadDrafts[0].initialComment = 'shared'; },
    validate: (drafts) => drafts.length === 2 ? [] : ['missing'],
    confirmBulkComment: () => true,
    onRender: () => { renders += 1; },
  });
  assert.deepEqual(editor.validate(), []);
  assert.equal(editor.applyBulkComment(), true);
  assert.deepEqual(state.uploadDrafts.map((draft) => draft.initialComment), ['shared', 'shared']);
  assert.equal(renders, 1);
});

test('guards empty bulk comments and confirms draft cancellation', () => {
  const state = createInitialAppState({ uploadDrafts: [{ initialComment: '' }] });
  let alerted = 0;
  let cleared = 0;
  const editor = createUploadDraftEditor(state, {
    alertMissingComment: () => { alerted += 1; },
    confirmCancel: () => true,
    onClear: () => { cleared += 1; },
  });
  assert.equal(editor.applyBulkComment(), false);
  assert.equal(alerted, 1);
  assert.equal(editor.cancel(), true);
  assert.equal(cleared, 1);
});

test('syncs folder detail tabs and search scope controls', () => {
  const node = () => ({
    toggles: [], attrs: {},
    classList: { owner: null, toggle(name, value) { this.owner.toggles.push([name, value]); } },
    setAttribute(name, value) { this.attrs[name] = value; },
  });
  const elements = Object.fromEntries(['recordTabBtn', 'searchTabBtn', 'recordPanel', 'searchPanel'].map((key) => [key, node()]));
  Object.values(elements).forEach((element) => { element.classList.owner = element; });
  const state = createInitialAppState({ roomSearchNextToken: 'next-1', photoSearchTag: 'damage' });
  let modeRenders = 0;
  let criteria;
  const controller = createFolderDetailController(state, elements, {
    renderMode: () => { modeRenders += 1; },
    renderSearchControls: (value) => { criteria = value; },
  });
  assert.equal(controller.setTab('search'), 'search');
  assert.equal(elements.searchTabBtn.attrs['aria-selected'], 'true');
  assert.equal(modeRenders, 1);
  assert.equal(controller.setSearchScope('folder'), 'folder');
  assert.equal(state.roomSearchNextToken, null);
  assert.deepEqual(criteria, { scope: 'folder', tag: 'damage', keyword: '' });
});

test('initializes folder selection and detail flow', async () => {
  const state = createInitialAppState({
    folderDetailTab: 'search', photoSearchScope: 'room', photoSearchTag: 'damage',
    photoSearchKeyword: 'door', searchPhotos: [{ photoId: 'p1' }], roomSearchNextToken: 'next-1',
  });
  const order = [];
  const folder = { folderId: 'f1', title: 'Container' };
  await selectFolderState(state, folder, {
    renderFolders: () => order.push('folders'),
    showDetail: () => order.push('show'),
    setRecordTab: () => order.push('tab'),
    setDetailTitle: (selected) => order.push(`title:${selected.folderId}`),
    loadContent: () => order.push('load'),
  });
  assert.equal(state.selectedFolder, folder);
  assert.equal(state.folderDetailTab, 'record');
  assert.equal(state.photoSearchScope, 'folder');
  assert.equal(state.photoSearchTag, 'all');
  assert.equal(state.photoSearchKeyword, '');
  assert.deepEqual(state.searchPhotos, []);
  assert.equal(state.roomSearchNextToken, null);
  assert.deepEqual(order, ['folders', 'show', 'tab', 'title:f1', 'load']);
});

test('clears folder selection content and runs cleanup callbacks', () => {
  const state = createInitialAppState({
    selectedFolder: { folderId: 'f1' }, selectedFolderArchive: { archivedCount: 2 },
    photos: [{ photoId: 'p1' }], quests: [{ questId: 'q1' }], searchPhotos: [{ photoId: 'p2' }],
    folderDetailTab: 'search', photoSearchScope: 'room', photoSearchTag: 'damage',
    photoSearchKeyword: 'door', roomSearchNextToken: 'next-1',
  });
  const order = [];
  clearFolderSelectionState(state, {
    clearDrafts: () => order.push('drafts'), hideDetail: () => order.push('hide'),
    renderArchive: () => order.push('archive'), renderFolders: () => order.push('folders'),
  });
  assert.equal(state.selectedFolder, null);
  assert.equal(state.selectedFolderArchive, null);
  assert.deepEqual([state.photos, state.quests, state.searchPhotos], [[], [], []]);
  assert.deepEqual(
    [state.folderDetailTab, state.photoSearchScope, state.photoSearchTag, state.photoSearchKeyword, state.roomSearchNextToken],
    ['record', 'folder', 'all', '', null],
  );
  assert.deepEqual(order, ['drafts', 'hide', 'archive', 'folders']);
});

test('prompts for missing folder passwords and stores trimmed values', () => {
  const state = createInitialAppState();
  const folder = { folderId: 'f1', hasPassword: true };
  assert.equal(ensureFolderPasswordState(state, folder, { prompt: () => '  secret  ' }), true);
  assert.equal(state.folderPasswordById.f1, 'secret');
  let prompted = 0;
  assert.equal(ensureFolderPasswordState(state, folder, { prompt: () => { prompted += 1; return 'other'; } }), true);
  assert.equal(prompted, 0);
});

test('guards cancelled passwords and handles invalid password cleanup', () => {
  const state = createInitialAppState({ folderPasswordById: { f1: 'wrong' } });
  let cancelled = 0;
  assert.equal(ensureFolderPasswordState(state, { folderId: 'f2', hasPassword: true }, {
    prompt: () => null, onCancel: () => { cancelled += 1; },
  }), false);
  let cleaned = 0;
  let notified = 0;
  const handled = handleInvalidFolderPassword({ status: 403 }, state, 'f1', {
    isInvalidPassword: (error) => error.status === 403,
    cleanup: () => { cleaned += 1; }, onInvalid: () => { notified += 1; },
  });
  assert.equal(handled, true);
  assert.equal(state.folderPasswordById.f1, undefined);
  assert.deepEqual([cancelled, cleaned, notified], [1, 1, 1]);
});

test('renders folder lists and detects missing selections', () => {
  const state = createInitialAppState({
    folders: [{ folderId: 'f1' }], selectedFolder: { folderId: 'missing' },
    folderUnreadMap: { f1: true },
  });
  let context;
  let missing = 0;
  const result = renderFolderListState(state, {
    renderList: (value) => { context = value; return true; },
    onSelectionMissing: () => { missing += 1; },
  });
  assert.equal(context.selectedFolderId, 'missing');
  assert.deepEqual(context.unreadById, { f1: true });
  assert.deepEqual(result, { hasFolders: true, selectionMissing: true });
  assert.equal(missing, 1);
});

test('handles empty folder list rendering', () => {
  const state = createInitialAppState({ selectedFolder: { folderId: 'f1' } });
  let emptied = 0;
  const result = renderFolderListState(state, {
    renderList: () => false,
    onEmpty: () => { emptied += 1; },
  });
  assert.deepEqual(result, { hasFolders: false, selectionMissing: true });
  assert.equal(emptied, 1);
});

test('aggregates targeted folder unread state with failure fallback', async () => {
  const state = createInitialAppState({
    folders: [{ folderId: 'f1' }, { folderId: 'f2' }, { folderId: 'f3' }],
  });
  const visited = [];
  const entries = await refreshFolderUnreadState(state, ['f1', 'f2'], {
    computeUnread: async (folderId) => {
      visited.push(folderId);
      if (folderId === 'f2') throw new Error('unavailable');
      return { photo: 1, quest: 0 };
    },
  });
  assert.deepEqual(visited, ['f1', 'f2']);
  assert.equal(entries.length, 2);
  assert.deepEqual(state.folderModeUnreadMap.f1, { photo: true, quest: false });
  assert.deepEqual(state.folderModeUnreadMap.f2, { photo: false, quest: false });
  assert.equal(state.folderUnreadMap.f1, true);
  assert.equal(state.folderUnreadMap.f2, false);
  assert.equal(state.folderUnreadMap.f3, undefined);
});

test('computes photo and quest folder unread state', async () => {
  const state = createInitialAppState({
    userKey: 'me',
    folders: [{ folderId: 'photos', mode: 'photo' }, { folderId: 'quests', mode: 'quest' }],
  });
  const api = {
    listPhotos: async () => ({ items: [
      { photoId: 'p1', latestCommentAt: '2026-01-01', latestCommentBy: 'me' },
      { photoId: 'p2', latestCommentAt: '2026-01-02', latestCommentBy: 'other' },
    ] }),
    listQuests: async () => ({ items: [
      { questId: 'q1', latestCommentAt: '2026-01-03', latestCommentBy: 'other' },
    ] }),
  };
  const unreadKeys = [];
  const options = {
    normalizeMode: (mode) => mode,
    questKey: (id) => `quest:${id}`,
    isUnread: (key, latest) => { unreadKeys.push([key, latest]); return key === 'p2' || key === 'quest:q1'; },
  };
  assert.deepEqual(await computeFolderUnreadState(api, state, 'photos', options), { photo: true, quest: false });
  assert.deepEqual(await computeFolderUnreadState(api, state, 'quests', options), { photo: false, quest: true });
  assert.deepEqual(unreadKeys, [['p1', ''], ['p2', '2026-01-02'], ['quest:q1', '2026-01-03']]);
});

test('skips unread requests for locked folders without passwords', async () => {
  const state = createInitialAppState({ folders: [{ folderId: 'locked', hasPassword: true }] });
  let requests = 0;
  const result = await computeFolderUnreadState({ listPhotos: async () => { requests += 1; return {}; } }, state, 'locked');
  assert.deepEqual(result, { photo: false, quest: false });
  assert.equal(requests, 0);
});

test('loads comments, records reads, and refreshes selected folder unread state', async () => {
  const state = createInitialAppState({ selectedFolder: { folderId: 'f1' } });
  const calls = [];
  const readTracker = {
    latestIncomingAt: (comments) => comments.at(-1)?.createdAt || '',
    isUnread: (key, latest) => key === 'p1' && Boolean(latest),
    markAsRead: (key, latest) => calls.push(`read:${key}:${latest}`),
  };
  const controller = createCommentReadController({
    listPhotoComments: async (photoId) => ({ items: [{ photoId, createdAt: '2026-01-01' }] }),
  }, state, {
    readTracker,
    refreshFolderUnread: async (ids) => calls.push(`refresh:${ids.join(',')}`),
    renderFolders: () => calls.push('render'),
  });
  const comments = await controller.loadPhotoComments('p1');
  const latest = controller.latestIncoming(comments);
  assert.equal(controller.isUnread('p1', latest), true);
  controller.markAsRead('p1', latest);
  assert.equal(await controller.refreshSelectedFolder(), true);
  assert.deepEqual(calls, ['read:p1:2026-01-01', 'refresh:f1', 'render']);
  state.selectedFolder = null;
  assert.equal(await controller.refreshSelectedFolder(), false);
});

test('creates quests with guarded state and disabled controls', async () => {
  const state = createInitialAppState({ selectedFolder: { folderId: 'f1' } });
  const elements = { createQuestBtn: { disabled: false }, questText: { disabled: false, value: ' keep until created ' } };
  const during = [];
  const result = await runQuestCreation(state, elements, {
    text: '  Inspect door  ',
    createQuest: async (folderId, text) => {
      during.push([state.isCreatingQuest, elements.createQuestBtn.disabled, elements.questText.disabled, folderId, text]);
      return { questId: 'q1' };
    },
    onCreated: (created) => during.push(created.questId),
  });
  assert.deepEqual(during, [[true, true, true, 'f1', 'Inspect door'], 'q1']);
  assert.equal(result.status, 'created');
  assert.equal(elements.questText.value, '');
  assert.equal(state.isCreatingQuest, false);
  assert.equal(elements.createQuestBtn.disabled, false);
});

test('restores quest controls after creation errors and guards invalid starts', async () => {
  const state = createInitialAppState({ selectedFolder: { folderId: 'f1' } });
  const elements = { createQuestBtn: { disabled: false }, questText: { disabled: false, value: 'text' } };
  await assert.rejects(runQuestCreation(state, elements, {
    text: 'text', createQuest: async () => { throw new Error('failed'); },
  }), /failed/);
  assert.equal(state.isCreatingQuest, false);
  assert.equal(elements.questText.disabled, false);
  assert.equal((await runQuestCreation(state, elements, { text: '   ' })).status, 'empty');
  state.selectedFolder = null;
  assert.equal((await runQuestCreation(state, elements, { text: 'text' })).status, 'no-folder');
});

test('wraps mutation actions with shared error boundaries', async () => {
  const calls = [];
  const boundary = createActionBoundary({
    clearError: () => calls.push('clear'),
    showError: (message) => calls.push(`show:${message}`),
    formatError: ({ label, error }) => `${label}:${error.message}`,
    onError: (error, label) => calls.push(`log:${label}:${error.message}`),
  });
  const success = await boundary.wrap(async (value) => value * 2, 'save')(3);
  const failure = await boundary.wrap(async () => { throw new Error('broken'); }, 'delete')();
  assert.equal(success, 6);
  assert.equal(failure, undefined);
  assert.deepEqual(calls, ['clear', 'clear', 'show:delete:broken', 'log:delete:broken']);
});

test('prompts low storage once per room and clears recovered prompts', () => {
  const values = new Map();
  const storage = { getItem: (key) => values.get(key), setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
  const modalClasses = [];
  const elements = { lowStorageModal: { classList: { remove: (name) => modalClasses.push(name) } }, lowStorageMessage: { textContent: '' } };
  const state = createInitialAppState({ roomId: 'r1', isAdmin: true, billing: { freeBytes: 1000, usageBytes: 900, subscription: { currentPlan: 'BASIC' } } });
  const controller = createLowStorageController(state, elements, {
    storage, computeStats: (billing) => ({ freeBytes: billing.freeBytes, freeRemainBytes: billing.freeBytes - billing.usageBytes }),
    formatSize: (value) => `${value}B`, planLabel: (plan) => `Plan ${plan}`,
    lowBytes: 100, lowRatio: 0.15,
  });
  assert.equal(controller.prompt().status, 'shown');
  assert.match(elements.lowStorageMessage.textContent, /100B.*Plan BASIC/);
  assert.equal(controller.prompt().status, 'already-shown');
  state.billing.usageBytes = 100;
  assert.equal(controller.prompt().status, 'available');
  assert.equal(values.has(controller.storageKey()), false);
  assert.deepEqual(modalClasses, ['hidden']);
});

test('opens billing admin and recommends a storage plan', async () => {
  const state = createInitialAppState({ billing: { usageBytes: 6 * 1024 * 1024 * 1024 } });
  const calls = [];
  const controller = createLowStorageController(state, {}, { storage: {}, computeStats: () => ({}) });
  const plan = await controller.charge({
    closeModal: () => calls.push('close'), openAdmin: () => { calls.push('open'); return true; },
    loadAdmin: () => calls.push('load'), changePlan: (value) => calls.push(`plan:${value}`),
  });
  assert.equal(plan, 'PRO');
  assert.deepEqual(calls, ['close', 'open', 'load', 'plan:PRO']);
});

test('orchestrates billing admin rendering and empty cleanup', () => {
  const node = () => ({ textContent: 'old', classList: { values: [], add(name) { this.values.push(name); } } });
  const elements = { billingStatus: node(), billingPlanGuide: node(), billingArchiveNote: node(), billingGraph: node() };
  const state = createInitialAppState({ billing: { usageBytes: 10 } });
  const calls = [];
  assert.equal(renderBillingAdminState(state, elements, {
    buildStatus: (billing) => `usage:${billing.usageBytes}`,
    guideText: () => 'guide', archiveNote: () => 'archive',
    renderGraph: () => calls.push('graph'), promptLowStorage: () => calls.push('prompt'),
    syncPlanButtons: () => calls.push('buttons'),
  }).status, 'rendered');
  assert.deepEqual([elements.billingStatus.textContent, elements.billingPlanGuide.textContent, elements.billingArchiveNote.textContent], ['usage:10', 'guide', 'archive']);
  assert.deepEqual(calls, ['graph', 'prompt', 'buttons']);
  state.billing = null;
  assert.equal(renderBillingAdminState(state, elements, { buildStatus: () => '', syncPlanButtons: () => calls.push('empty-buttons') }).status, 'empty');
  assert.deepEqual([elements.billingStatus.textContent, elements.billingPlanGuide.textContent, elements.billingArchiveNote.textContent], ['', '', '']);
  assert.deepEqual(elements.billingGraph.classList.values, ['hidden']);
});

test('syncs and renders top and admin storage graphs', () => {
  const elements = {
    billingGraphTop: { style: { width: '', removeProperty(name) { this[name] = ''; } } },
    appHeaderSummary: { getBoundingClientRect: () => ({ width: 320.4 }) },
    billingGraphTopUsed: {}, billingGraphTopRemaining: {}, billingGraphTopUsedLabel: {}, billingGraphTopRemainLabel: {},
    billingGraphTopExtraLabel: {}, billingGraphTopSubmeta: {}, billingGraph: {}, billingGraphUsed: {}, billingGraphRemaining: {},
    billingGraphUsedLabel: {}, billingGraphRemainLabel: {},
  };
  const state = createInitialAppState({ roomName: 'Room', billing: { usageBytes: 1 } });
  const calls = [];
  const controller = createStorageGraphController(state, elements, {
    renderTop: (_nodes, billing, options) => calls.push(['top', billing.usageBytes, options.active, options.extraLabel]),
    renderAdmin: (_nodes, billing) => calls.push(['admin', billing.usageBytes]),
    formatSize: String, folderUsage: () => '2 folders',
  });
  assert.equal(controller.syncTopWidth(), 320);
  assert.equal(elements.billingGraphTop.style.width, '320px');
  assert.equal(controller.renderTop(), true);
  controller.renderAdmin();
  assert.deepEqual(calls, [['top', 1, true, '2 folders'], ['admin', 1]]);
});

test('renders billing bars and synchronizes admin visibility', () => {
  const classList = () => ({ calls: [], toggle(name, value) { this.calls.push(['toggle', name, value]); }, add(name) { this.calls.push(['add', name]); } });
  const elements = Object.fromEntries([
    'teamAdminBtn', 'folderDeleteBtn', 'setFolderPasswordBtn', 'openFolderPasswordBtn', 'teamAdminCard',
  ].map((key) => [key, { classList: classList() }]));
  elements.billingBar = {};
  const state = createInitialAppState({ roomName: 'Room', billing: { usageBytes: 1 }, isAdmin: false, userKey: 'u1' });
  const calls = [];
  const controller = createBillingUiController(state, elements, {
    renderTopGraph: () => calls.push('top'),
    renderBillingBarInto: (_target, options) => calls.push(`bar:${options.active}:${options.isAdmin}`),
    closeLowStorage: () => calls.push('low'), closeFolderPassword: () => calls.push('password'),
  });
  assert.equal(controller.renderBar(), true);
  assert.equal(controller.syncAdminVisibility(), false);
  assert.deepEqual(calls, ['top', 'bar:true:false', 'low', 'password']);
  assert.deepEqual(elements.teamAdminBtn.classList.calls, [['toggle', 'hidden', true]]);
  assert.deepEqual(elements.teamAdminCard.classList.calls, [['add', 'hidden']]);
});

test('opens, closes, and toggles team admin mode', async () => {
  const node = (hidden = false) => ({ classList: {
    hidden, calls: [], contains(name) { return name === 'hidden' && this.hidden; },
    add(name) { if (name === 'hidden') this.hidden = true; this.calls.push(['add', name]); },
    remove(name) { if (name === 'hidden') this.hidden = false; this.calls.push(['remove', name]); },
    toggle(name, value) { if (name === 'hidden') this.hidden = value === undefined ? !this.hidden : value; this.calls.push(['toggle', name, value]); },
  } });
  const state = createInitialAppState({ selectedFolder: { folderId: 'f1' } });
  const elements = { teamAdminCard: node(true), appHeaderControls: node(), currentRoomStatic: node(), folderDetail: node() };
  const calls = [];
  const controller = createTeamAdminController(state, elements, {
    closeMenu: () => calls.push('menu'), renderCurrentRoomHeader: () => calls.push('header'), loadPanel: () => calls.push('load'),
  });
  assert.equal(await controller.open(), true);
  controller.close();
  assert.equal(await controller.toggle(), true);
  assert.deepEqual(calls, ['header', 'load', 'header', 'menu', 'header', 'load']);
  assert.equal(elements.teamAdminCard.classList.hidden, false);
  assert.equal(elements.folderDetail.classList.hidden, true);
});

test('loads admin member and folder data with independent errors', async () => {
  const state = createInitialAppState({ isAdmin: true, adminFolderId: 'missing' });
  const result = await loadAdminPanelState({
    listTeamMembers: async () => ({ items: [{ userKey: 'u1', status: 'active' }, { userKey: 'u2', status: 'left' }] }),
    listFolders: async () => ({ items: [{ folderId: 'f1' }] }),
  }, state);
  assert.deepEqual(result.members, [{ userKey: 'u1', status: 'active' }]);
  assert.deepEqual(result.folders, [{ folderId: 'f1' }]);
  assert.equal(state.adminFolderId, '');
  assert.equal(result.membersError, null);

  const failed = await loadAdminPanelState({
    listTeamMembers: async () => { throw new Error('members'); },
    listFolders: async () => { throw new Error('folders'); },
  }, state);
  assert.equal(failed.membersError.message, 'members');
  assert.equal(failed.foldersError.message, 'folders');
  assert.deepEqual([failed.members, failed.folders], [[], []]);
});

test('skips admin data loading without permission or visible panel', async () => {
  let requests = 0;
  const api = { listTeamMembers: async () => { requests += 1; }, listFolders: async () => { requests += 1; } };
  assert.equal(await loadAdminPanelState(api, createInitialAppState()), null);
  assert.equal(await loadAdminPanelState(api, createInitialAppState({ isAdmin: true }), { isVisible: () => false }), null);
  assert.equal(requests, 0);
});

test('loads selected admin folder members and reports errors', async () => {
  const events = [];
  const loaded = await loadAdminFolderMembers({
    listFolderMembers: async (folderId) => ({ items: folderId === 'f1' ? [{ userKey: 'u1' }] : [] }),
  }, 'f1', {
    onLoaded: (members) => events.push(['loaded', members]),
    onError: (error) => events.push(['error', error.message]),
  });
  assert.deepEqual(loaded, { members: [{ userKey: 'u1' }], error: null });
  assert.deepEqual(events, [['loaded', [{ userKey: 'u1' }]]]);

  const failed = await loadAdminFolderMembers({
    listFolderMembers: async () => { throw new Error('folder members'); },
  }, 'f1', {
    onLoaded: (members) => events.push(['loaded', members]),
    onError: (error) => events.push(['error', error.message]),
  });
  assert.equal(failed.error.message, 'folder members');
  assert.deepEqual(failed.members, []);
  assert.deepEqual(events.at(-1), ['error', 'folder members']);
});

test('updates team members and restores controls when cancelled', async () => {
  const member = { userKey: 'u1' };
  const calls = [];
  const api = { updateTeamMember: async (...args) => calls.push(['update', ...args]) };
  const updated = await runTeamMemberUpdate(api, member, { folderScope: 'all' }, {
    confirmUpdate: () => true,
    onUpdated: () => calls.push(['notified']),
    reload: () => calls.push(['reloaded']),
  });
  assert.equal(updated.status, 'updated');
  assert.deepEqual(calls, [
    ['update', 'u1', { folderScope: 'all' }],
    ['notified'],
    ['reloaded'],
  ]);

  const cancelled = await runTeamMemberUpdate(api, member, { status: 'left' }, {
    confirmUpdate: () => false,
    onCancelled: (_member, patch) => calls.push(['restored', patch]),
  });
  assert.equal(cancelled.status, 'cancelled');
  assert.deepEqual(calls.at(-1), ['restored', { status: 'left' }]);
});

test('selects admin folders and manages folder invite tokens', async () => {
  const state = createInitialAppState();
  let reloads = 0;
  assert.equal(await selectAdminFolder(state, 'f1', { reload: () => { reloads += 1; } }), 'f1');
  assert.equal(reloads, 1);

  const calls = [];
  const api = {
    createInvite: async (folderId) => ({ token: `token-${folderId}` }),
    revokeInvite: async (token) => calls.push(['revoke', token]),
  };
  const invite = await createAdminFolderInvite(api, state, 'f1', {
    buildInviteUrl: (token) => `/?invite=${token}`,
    onCreated: (value) => calls.push(['created', value]),
  });
  assert.deepEqual(invite, { token: 'token-f1', url: '/?invite=token-f1' });
  assert.equal(state.lastFolderInviteTokens.f1, 'token-f1');

  assert.equal((await revokeAdminFolderInvite(api, state, 'f1', {
    confirmRevoke: () => false,
  })).status, 'cancelled');
  assert.equal(state.lastFolderInviteTokens.f1, 'token-f1');
  assert.equal((await revokeAdminFolderInvite(api, state, 'f1', {
    onRevoked: (token) => calls.push(['revoked', token]),
  })).status, 'revoked');
  assert.equal(state.lastFolderInviteTokens.f1, undefined);
  assert.deepEqual(calls.slice(-2), [['revoke', 'token-f1'], ['revoked', 'token-f1']]);

  let missing = 0;
  assert.equal((await revokeAdminFolderInvite(api, state, 'f1', { onMissing: () => { missing += 1; } })).status, 'missing');
  assert.equal(missing, 1);
  await assert.rejects(createAdminFolderInvite({ createInvite: async () => ({}) }, state, 'f1'), /Invite token is missing/);
});

test('creates, revokes, and copies generic invite values', async () => {
  const calls = [];
  const api = { createInvite: async (scope) => ({ token: `t-${scope || 'room'}` }), revokeInvite: async (token) => calls.push(['revoke', token]) };
  const created = await createInviteToken(api, {
    scopeId: 'f1', saveToken: (token) => calls.push(['save', token]),
    buildInviteUrl: (token) => `/?invite=${token}`, onCreated: (value) => calls.push(['created', value.url]),
  });
  assert.equal(created.url, '/?invite=t-f1');
  assert.equal((await revokeInviteToken(api, created.token, {
    clearToken: () => calls.push(['clear']), onRevoked: () => calls.push(['revoked']),
  })).status, 'revoked');
  assert.equal((await copyInviteText(' url ', {
    writeText: (text) => calls.push(['copy', text]), onCopied: () => calls.push(['copied']),
  })).status, 'copied');
  assert.equal((await copyInviteText('url', { allowFallback: true, onFallback: () => calls.push(['fallback']) })).status, 'fallback');
  assert.equal((await copyInviteText('', { onMissing: () => calls.push(['missing']) })).status, 'missing');
});

test('sets and clears admin folder passwords with ordered reloads', async () => {
  const state = createInitialAppState();
  const calls = [];
  const api = { setFolderPassword: async (...args) => calls.push(['update', ...args]) };
  const options = {
    confirmUpdate: () => true,
    onUpdated: (password) => calls.push(['notified', password]),
    reloadFolders: () => calls.push(['folders']),
    reloadPanel: () => calls.push(['panel']),
  };
  assert.equal((await runFolderPasswordUpdate(api, state, 'f1', 'secret', options)).status, 'updated');
  assert.equal(state.folderPasswordById.f1, 'secret');
  assert.deepEqual(calls, [
    ['update', 'f1', 'secret'], ['notified', 'secret'], ['folders'], ['panel'],
  ]);
  await runFolderPasswordUpdate(api, state, 'f1', '', options);
  assert.equal(state.folderPasswordById.f1, undefined);

  const count = calls.length;
  assert.equal((await runFolderPasswordUpdate(api, state, 'f1', 'later', {
    confirmUpdate: () => false,
  })).status, 'cancelled');
  assert.equal(calls.length, count);
});

test('deletes admin folders and clears related state', async () => {
  const state = createInitialAppState({
    adminFolderId: 'f1',
    lastFolderInviteTokens: { f1: 'token' },
    folderPasswordById: { f1: 'secret' },
  });
  const calls = [];
  const api = { deleteFolder: async (folderId) => calls.push(['delete', folderId]) };
  const result = await runAdminFolderDelete(api, state, 'f1', {
    confirmDelete: () => true,
    onDeleted: () => calls.push(['notified']),
    reloadFolders: () => calls.push(['folders']),
    reloadTeam: () => calls.push(['team']),
    reloadPanel: () => calls.push(['panel']),
  });
  assert.equal(result.status, 'deleted');
  assert.equal(state.adminFolderId, '');
  assert.equal(state.lastFolderInviteTokens.f1, undefined);
  assert.equal(state.folderPasswordById.f1, undefined);
  assert.deepEqual(calls, [
    ['delete', 'f1'], ['notified'], ['folders'], ['team'], ['panel'],
  ]);

  const count = calls.length;
  assert.equal((await runAdminFolderDelete(api, state, 'f2', {
    confirmDelete: () => false,
  })).status, 'cancelled');
  assert.equal(calls.length, count);
  assert.equal(runAdminFolderDelete, runFolderDelete);
});

test('deletes rooms after two confirmations and runs cleanup in order', async () => {
  const calls = [];
  const api = { deleteTeam: async () => calls.push('delete') };
  const result = await runRoomDelete(api, {
    confirmDelete: () => true,
    confirmFinal: () => true,
    onDeleted: () => calls.push('notified'),
    resetRoom: () => calls.push('reset'),
    showSetup: () => calls.push('setup'),
  });
  assert.equal(result.status, 'deleted');
  assert.deepEqual(calls, ['delete', 'notified', 'reset', 'setup']);
  assert.deepEqual(await runRoomDelete(api, { confirmDelete: () => false }), { status: 'cancelled', step: 'initial' });
  assert.deepEqual(await runRoomDelete(api, { confirmDelete: () => true, confirmFinal: () => false }), { status: 'cancelled', step: 'final' });
  assert.deepEqual(calls, ['delete', 'notified', 'reset', 'setup']);
});

test('guards and deletes accounts with owner conflict handling', async () => {
  const calls = [];
  const callbacks = {
    confirmDelete: () => true, confirmFinal: () => true,
    onDeleted: () => calls.push('notified'), closeMenu: () => calls.push('menu'),
    resetRoom: () => calls.push('reset'), clearAuth: () => calls.push('auth'), showAuth: () => calls.push('show'),
  };
  assert.equal((await runAccountDelete({ deleteAccount: async () => calls.push('delete') }, callbacks)).status, 'deleted');
  assert.deepEqual(calls, ['delete', 'notified', 'menu', 'reset', 'auth', 'show']);
  calls.length = 0;
  const blocked = await runAccountDelete({}, {
    getOwnedRoom: () => ({ roomId: 'r1' }),
    onOwnerBlocked: (room) => calls.push(['blocked', room.roomId]), closeMenu: () => calls.push('menu'),
  });
  assert.equal(blocked.status, 'owner-blocked');
  assert.deepEqual(calls, [['blocked', 'r1'], 'menu']);
  calls.length = 0;
  const conflict = await runAccountDelete({ deleteAccount: async () => { throw new Error('owner'); } }, {
    ...callbacks, isOwnerConflict: () => true, onOwnerConflict: () => calls.push('conflict'),
  });
  assert.equal(conflict.status, 'owner-conflict');
  assert.deepEqual(calls, ['conflict', 'menu']);
});

test('leaves rooms with admin guard and local cleanup fallback', async () => {
  const calls = [];
  const options = {
    onWarning: () => calls.push('warning'), confirmLeave: () => true,
    closeMenu: () => calls.push('menu'), resetRoom: () => calls.push('reset'),
    showSetup: () => calls.push('setup'), reloadRooms: () => calls.push('rooms'),
  };
  const left = await runRoomLeave({ getTeam: async () => ({ isAdmin: false }), leaveTeam: async () => { throw new Error('offline'); } }, options);
  assert.equal(left.status, 'left');
  assert.equal(left.leaveError.message, 'offline');
  assert.deepEqual(calls, ['warning', 'reset', 'menu', 'setup', 'rooms']);
  calls.length = 0;
  assert.equal((await runRoomLeave({ getTeam: async () => ({ isAdmin: true }) }, {
    onAdminBlocked: () => calls.push('blocked'), closeMenu: () => calls.push('menu'),
  })).status, 'admin-blocked');
  assert.deepEqual(calls, ['blocked', 'menu']);
  calls.length = 0;
  assert.equal((await runRoomLeave({ getTeam: async () => { throw new Error('guard'); } }, {
    ...options, confirmLeave: () => false,
  })).status, 'cancelled');
  assert.deepEqual(calls, ['warning', 'menu']);
});

test('creates rooms with validation and conflict classification', async () => {
  const state = createInitialAppState();
  const calls = [];
  const options = {
    onInvalid: () => calls.push('invalid'), closeAdmin: () => calls.push('admin'),
    resetRoom: () => calls.push('reset'), showApp: () => calls.push('app'),
    onCreated: (name) => calls.push(['created', name]),
    describeError: (error) => error.message,
    onExistingRoom: () => calls.push('existing'), onNameConflict: () => calls.push('conflict'),
    onError: () => calls.push('error'),
  };
  assert.equal((await runRoomCreation({}, state, '  ', options)).status, 'invalid');
  assert.equal((await runRoomCreation({ createRoom: async (name) => calls.push(['api', name]) }, state, ' New Room ', options)).status, 'created');
  assert.equal(state.roomName, 'New Room');
  assert.deepEqual(calls.slice(-5), [['api', 'New Room'], 'admin', 'reset', 'app', ['created', 'New Room']]);
  assert.equal((await runRoomCreation({ createRoom: async () => { throw new Error('409 already has a room'); } }, state, 'x', options)).status, 'existing-room');
  assert.equal((await runRoomCreation({ createRoom: async () => { throw new Error('409 duplicate'); } }, state, 'x', options)).status, 'name-conflict');
  assert.equal((await runRoomCreation({ createRoom: async () => { throw new Error('500'); } }, state, 'x', options)).status, 'error');
});

test('creates folders with validation, plan limits, and selection', async () => {
  const calls = [];
  const options = {
    title: ' F-1 ', mode: 'QUEST', password: ' secret ',
    normalizeMode: (mode) => mode.toLowerCase(),
    onInvalid: () => calls.push('invalid'), onValid: () => calls.push('valid'),
    getPlanLimit: (error) => error.limit || null,
    onPlanLimit: (limit) => calls.push(['limit', limit.code]),
    onCreated: (folder) => calls.push(['created', folder.folderId]),
    reloadFolders: () => calls.push('reload'), selectFolder: (id) => calls.push(['select', id]),
  };
  assert.equal((await runFolderCreation({}, { ...options, title: ' ' })).status, 'invalid');
  const api = { createFolder: async (input) => { calls.push(['api', input]); return { folderId: 'f1', title: input.title }; } };
  assert.equal((await runFolderCreation(api, options)).status, 'created');
  assert.deepEqual(calls.slice(-5), [
    'valid', ['api', { title: 'F-1', mode: 'quest', folderPassword: 'secret' }],
    ['created', 'f1'], 'reload', ['select', 'f1'],
  ]);
  const limitError = Object.assign(new Error('limit'), { limit: { code: 'FREE' } });
  assert.equal((await runFolderCreation({ createFolder: async () => { throw limitError; } }, options)).status, 'plan-limit');
});

test('classifies folder list network and general errors', async () => {
  const calls = [];
  assert.equal((await handleFolderListError(new Error('Failed to fetch'), {
    onNetworkError: (message) => calls.push(['network', message]),
    onError: (message) => calls.push(['general', message]),
  })).type, 'network');
  assert.equal((await handleFolderListError(new Error('denied'), {
    onNetworkError: (message) => calls.push(['network', message]),
    onError: (message) => calls.push(['general', message]),
  })).type, 'general');
  assert.deepEqual(calls, [['network', 'Failed to fetch'], ['general', 'denied']]);
});

test('creates reusable room and folder creation handlers', async () => {
  const calls = [];
  const state = createInitialAppState();
  const roomHandler = createRoomCreationHandler({ createRoom: async (name) => calls.push(['room', name]) }, state, () => 'Room', {
    before: () => calls.push('before'), onCreated: () => calls.push('room-created'),
  });
  assert.equal((await roomHandler()).status, 'created');
  const folderHandler = createFolderCreationHandler({ createFolder: async (input) => ({ folderId: 'f1', title: input.title }) }, () => ({ title: 'Folder' }), {
    onCreated: () => calls.push('folder-created'), selectFolder: (id) => calls.push(['select', id]),
  });
  assert.equal((await folderHandler()).status, 'created');
  assert.deepEqual(calls, ['before', ['room', 'Room'], 'room-created', 'folder-created', ['select', 'f1']]);
});

test('creates reusable room leave, room delete, and account delete handlers', async () => {
  assert.equal((await createRoomLeaveHandler({ getTeam: async () => ({ isAdmin: true }) })()).status, 'admin-blocked');
  assert.equal((await createRoomDeleteHandler({}, { confirmDelete: () => false })()).status, 'cancelled');
  assert.equal((await createAccountDeleteHandler({}, { getOwnedRoom: () => ({ roomId: 'r1' }) })()).status, 'owner-blocked');
});

test('creates reusable folder and invite management handlers', async () => {
  const state = createInitialAppState({ selectedFolder: { folderId: 'f1' } });
  assert.equal((await createFolderDeleteHandler({}, state, () => null)()).status, 'missing');
  assert.equal((await createFolderPasswordHandler({}, state, () => null)()).status, 'missing');
  const calls = [];
  const invite = createInviteHandlers({
    createInvite: async () => ({ token: 'token' }), revokeInvite: async (token) => calls.push(['revoke', token]),
  }, {
    getCopyValue: () => 'url', copyOptions: { writeText: (text) => calls.push(['copy', text]) },
    createOptions: { saveToken: (token) => calls.push(['save', token]) },
    getToken: () => 'token', revokeOptions: { clearToken: () => calls.push(['clear']) },
  });
  assert.equal((await invite.copy()).status, 'copied');
  assert.equal((await invite.create()).token, 'token');
  assert.equal((await invite.revoke()).status, 'revoked');
  assert.deepEqual(calls, [['copy', 'url'], ['save', 'token'], ['revoke', 'token'], ['clear']]);
});

test('creates quest complete and delete mutation actions', async () => {
  const calls = [];
  const api = {
    updateQuest: async (...args) => calls.push(['update', ...args]),
    deleteQuest: async (...args) => calls.push(['delete', ...args]),
  };
  const quest = { questId: 'q1', folderId: 'f1' };
  const actions = createQuestMutationActions(api, quest, {
    confirmDelete: () => true,
    reloadQuests: () => calls.push(['quests']), reloadFolder: () => calls.push(['folder']),
  });
  assert.equal((await actions.complete()).status, 'completed');
  assert.equal((await actions.remove()).status, 'deleted');
  assert.deepEqual(calls, [
    ['update', 'q1', { status: 'done' }, 'f1'], ['quests'],
    ['delete', 'q1', 'f1'], ['folder'],
  ]);
  assert.equal((await createQuestMutationActions(api, quest, { confirmDelete: () => false }).remove()).status, 'cancelled');
});

test('creates photo update and delete mutation actions', async () => {
  const calls = [];
  const api = {
    updatePhoto: async (...args) => calls.push(['update', ...args]),
    deletePhoto: async (...args) => calls.push(['delete', ...args]),
  };
  const photo = { photoId: 'p1' };
  const actions = createPhotoMutationActions(api, photo, {
    confirmDelete: () => true,
    beforeUpdate: (...args) => calls.push(['before', ...args]),
    reload: () => calls.push(['reload']),
  });
  assert.equal((await actions.updateLogTag('work')).status, 'updated');
  assert.equal((await actions.remove()).status, 'deleted');
  assert.deepEqual(calls, [
    ['before', photo], ['update', 'p1', { logTag: 'work' }], ['reload'],
    ['delete', 'p1'], ['reload'],
  ]);

  const cancelled = createPhotoMutationActions(api, photo, { confirmDelete: () => false });
  assert.equal((await cancelled.remove()).status, 'cancelled');
  assert.equal(calls.length, 5);
});

test('creates quest comment add and delete mutation actions', async () => {
  const calls = [];
  const api = {
    createQuestComment: async (...args) => calls.push(['create', ...args]),
    deleteQuestComment: async (...args) => calls.push(['delete', ...args]),
  };
  const quest = { questId: 'q1', folderId: 'f1' };
  const actions = createQuestCommentMutationActions(api, quest, {
    confirmDelete: () => true,
    reload: () => calls.push(['reload']),
  });
  assert.equal((await actions.add('memo')).status, 'created');
  assert.equal((await actions.remove({ commentId: 'c1' })).status, 'deleted');
  assert.deepEqual(calls, [
    ['create', 'q1', 'memo', 'f1'], ['reload'],
    ['delete', 'q1', 'c1', 'f1'], ['reload'],
  ]);

  const cancelled = createQuestCommentMutationActions(api, quest, { confirmDelete: () => false });
  assert.equal((await cancelled.remove({ commentId: 'c2' })).status, 'cancelled');
  assert.equal(calls.length, 4);
});

test('creates photo comment edit and delete mutation actions', async () => {
  const calls = [];
  const api = {
    updatePhotoComment: async (...args) => calls.push(['update', ...args]),
    deletePhotoComment: async (...args) => calls.push(['delete', ...args]),
  };
  const photo = { photoId: 'p1' };
  const comment = { commentId: 'c1' };
  const actions = createPhotoCommentMutationActions(api, photo, {
    confirmDelete: () => true,
    beforeEdit: (...args) => calls.push(['before', ...args]),
    reload: () => calls.push(['reload']),
  });
  assert.equal((await actions.edit(comment, 'updated')).status, 'updated');
  assert.equal((await actions.remove(comment)).status, 'deleted');
  assert.deepEqual(calls, [
    ['before', photo, comment], ['update', 'p1', 'c1', 'updated'], ['reload'],
    ['delete', 'p1', 'c1'], ['reload'],
  ]);

  const cancelled = createPhotoCommentMutationActions(api, photo, { confirmDelete: () => false });
  assert.equal((await cancelled.remove(comment)).status, 'cancelled');
  assert.equal(calls.length, 5);
});

test('creates guarded photo comment add handlers', async () => {
  const calls = [];
  let text = '  memo  ';
  let release;
  const createGate = new Promise((resolve) => { release = resolve; });
  const api = { createPhotoComment: async (...args) => {
    calls.push(['create', ...args]);
    await createGate;
  } };
  const handler = createPhotoCommentAddHandler(api, { photoId: 'p1' }, {
    getText: () => text,
    setBusy: (busy) => calls.push(['busy', busy]),
    beforeAdd: () => calls.push(['before']),
    reload: () => calls.push(['reload']),
  });
  const pending = handler();
  assert.equal((await handler()).status, 'busy');
  release();
  assert.equal((await pending).status, 'created');
  assert.deepEqual(calls, [
    ['busy', true], ['before'], ['create', 'p1', 'memo'], ['reload'],
  ]);

  text = '   ';
  assert.equal((await createPhotoCommentAddHandler(api, { photoId: 'p1' }, { getText: () => text })()).status, 'empty');

  let attempts = 0;
  const failing = createPhotoCommentAddHandler({ createPhotoComment: async () => {
    attempts += 1;
    if (attempts === 1) throw new Error('failed');
  } }, { photoId: 'p1' }, { getText: () => 'memo', setBusy: (busy) => calls.push(['retry-busy', busy]) });
  await assert.rejects(failing(), /failed/);
  assert.equal((await failing()).status, 'created');
  assert.deepEqual(calls.slice(-3), [['retry-busy', true], ['retry-busy', false], ['retry-busy', true]]);
});

test('switches to an owned room for the owner delete guard', async () => {
  const state = { roomId: 'current', roomName: 'Current' };
  const ownedRoom = { roomId: 'owned', roomName: 'Owned' };
  const calls = [];
  const result = await runOwnerRoomSwitch({ switchRoom: async (id) => calls.push(['switch', id]) }, state, ownedRoom, {
    confirmSwitch: (room) => { calls.push(['confirm', room.roomId]); return true; },
    closeAdmin: () => calls.push(['close']),
    resetRoom: () => calls.push(['reset']),
    showApp: () => calls.push(['show']),
    onSwitched: (room) => calls.push(['done', room.roomName]),
  });
  assert.equal(result.status, 'switched');
  assert.equal(state.roomName, 'Owned');
  assert.deepEqual(calls, [
    ['confirm', 'owned'], ['switch', 'owned'], ['close'], ['reset'], ['show'], ['done', 'Owned'],
  ]);

  assert.equal((await runOwnerRoomSwitch({}, { roomId: 'owned' }, ownedRoom, {
    onCurrentRoom: () => calls.push(['current']),
  })).status, 'current');
  assert.equal((await runOwnerRoomSwitch({}, state, { roomId: 'other', roomName: 'Other' }, {
    confirmSwitch: () => false,
  })).status, 'cancelled');
});

test('loads, validates, and saves user display names', async () => {
  const calls = [];
  const state = {};
  const api = {
    getCurrentUser: async () => ({ userKey: 'u1', displayName: '' }),
    saveDisplayName: async (name) => calls.push(['save', name]),
  };
  const answers = [null, '   ', '  Alice  '];
  const result = await ensureUserDisplayName(api, state, {
    promptName: () => answers.shift(),
    onLoaded: (user) => calls.push(['loaded', user.userKey]),
    onInvalid: () => calls.push(['invalid']),
    onSaved: (name) => calls.push(['saved', name]),
  });
  assert.equal(result.status, 'saved');
  assert.equal(state.userName, 'Alice');
  assert.deepEqual(calls, [
    ['loaded', 'u1'], ['invalid'], ['save', 'Alice'], ['saved', 'Alice'],
  ]);

  const existingState = {};
  assert.equal((await ensureUserDisplayName({
    getCurrentUser: async () => ({ displayName: 'Bob' }),
  }, existingState)).status, 'existing');
  assert.equal(existingState.userName, 'Bob');

  assert.equal((await saveUserDisplayName(api, state, ' ', {
    onInvalid: () => calls.push(['invalid-save']),
  })).status, 'invalid');
  assert.equal(calls.at(-1)[0], 'invalid-save');
});

test('creates display name change handlers for save, invalid, and cancel paths', async () => {
  const calls = [];
  const state = { userName: 'Before' };
  const api = { saveDisplayName: async (name) => calls.push(['save', name]) };
  const saved = createDisplayNameChangeHandler(api, state, {
    promptName: (current) => { calls.push(['prompt', current]); return '  After  '; },
    onSaved: (name) => calls.push(['saved', name]),
    onFinished: (status) => calls.push(['finished', status]),
  });
  assert.equal((await saved()).status, 'saved');
  assert.equal(state.userName, 'After');
  assert.deepEqual(calls, [
    ['prompt', 'Before'], ['save', 'After'], ['saved', 'After'], ['finished', 'saved'],
  ]);

  const invalid = createDisplayNameChangeHandler(api, state, {
    promptName: () => ' ',
    onInvalid: () => calls.push(['invalid']),
    onFinished: (status) => calls.push(['finished', status]),
  });
  assert.equal((await invalid()).status, 'invalid');
  const cancelled = createDisplayNameChangeHandler(api, state, {
    promptName: () => null,
    onFinished: (status) => calls.push(['finished', status]),
  });
  assert.equal((await cancelled()).status, 'cancelled');
  assert.deepEqual(calls.slice(-3), [
    ['invalid'], ['finished', 'invalid'], ['finished', 'cancelled'],
  ]);
});

test('runs folder exports for presentation and streamed PDF results', async () => {
  const calls = [];
  const api = { exportFolder: async (...args) => {
    calls.push(['export', ...args]);
    return { downloadUrl: 'download' };
  } };
  const options = {
    getFormatLabel: (format) => format.toUpperCase(),
    confirmExport: (label) => { calls.push(['confirm', label]); return true; },
    onStart: (label) => calls.push(['start', label]),
    onComplete: () => calls.push(['complete']),
    onReady: (result) => calls.push(['ready', result]),
  };
  assert.equal((await runFolderExport(api, { selectedFolder: { folderId: 'f1' } }, 'pptx', options)).status, 'ready');
  assert.deepEqual(calls, [
    ['confirm', 'PPTX'], ['start', 'PPTX'], ['export', 'f1', 'pptx'], ['complete'],
    ['ready', { formatLabel: 'PPTX', downloadUrl: 'download' }],
  ]);

  calls.length = 0;
  const chunks = [new Uint8Array([1, 2]), new Uint8Array([3])];
  let index = 0;
  const pdf = await runFolderExport(api, { selectedFolder: { folderId: 'f1' } }, 'pdf', {
    ...options,
    onDownloadReady: () => calls.push(['download-ready']),
    fetchDownload: async () => ({
      ok: true, headers: { get: () => '3' },
      body: { getReader: () => ({ read: async () => index < chunks.length ? { value: chunks[index++], done: false } : { done: true } }) },
    }),
    getFileName: () => 'file.pdf',
    createBlob: (values) => ({ values }),
    createObjectUrl: () => 'blob:url',
    onProgress: (...args) => calls.push(['progress', ...args]),
  });
  assert.equal(pdf.status, 'ready');
  assert.deepEqual(calls.slice(-4), [
    ['download-ready'], ['progress', 2, 3], ['progress', 3, 3],
    ['ready', { formatLabel: 'PDF', downloadUrl: 'download', fileName: 'file.pdf', objectUrl: 'blob:url' }],
  ]);
});

test('guards missing, cancelled, failed, and fallback folder exports', async () => {
  const calls = [];
  const missing = await runFolderExport({}, {}, 'pdf', { onMissingFolder: () => calls.push(['missing']) });
  assert.equal(missing.status, 'missing');
  const cancelled = await runFolderExport({}, { selectedFolder: { folderId: 'f1' } }, 'pdf', {
    confirmExport: () => false,
  });
  assert.equal(cancelled.status, 'cancelled');

  const fallback = await runFolderExport({ exportFolder: async () => ({ downloadUrl: 'download' }) }, {
    selectedFolder: { folderId: 'f1' },
  }, 'pdf', {
    confirmExport: () => true,
    fetchDownload: async () => ({ ok: false, status: 500 }),
    onClose: () => calls.push(['close']),
    onFallback: (url) => calls.push(['fallback', url]),
  });
  assert.equal(fallback.status, 'fallback');
  assert.deepEqual(calls.slice(-2), [['close'], ['fallback', 'download']]);

  await assert.rejects(runFolderExport({ exportFolder: async () => { throw new Error('export failed'); } }, {
    selectedFolder: { folderId: 'f1' },
  }, 'pptx', { confirmExport: () => true, onClose: () => calls.push(['closed-error']) }), /export failed/);
  assert.deepEqual(calls.at(-1), ['closed-error']);
});

test('removes members from admin folders after confirmation', async () => {
  const member = { userKey: 'u1', displayName: 'Member' };
  const calls = [];
  const api = { removeFolderMember: async (...args) => calls.push(['remove', ...args]) };
  const removed = await runAdminFolderMemberRemove(api, 'f1', member, {
    confirmRemove: () => true,
    onRemoved: (value) => calls.push(['notified', value.userKey]),
    reload: () => calls.push(['reloaded']),
  });
  assert.equal(removed.status, 'removed');
  assert.deepEqual(calls, [
    ['remove', 'f1', 'u1'], ['notified', 'u1'], ['reloaded'],
  ]);

  const count = calls.length;
  assert.equal((await runAdminFolderMemberRemove(api, 'f1', member, {
    confirmRemove: () => false,
  })).status, 'cancelled');
  assert.equal(calls.length, count);
});

test('renders admin panel sections behind independent error boundaries', async () => {
  const calls = [];
  assert.equal((await renderAdminPanelSection(['item'], null, {
    render: (items) => calls.push(['render', items]),
    renderError: (error) => calls.push(['error', error.message]),
  })).status, 'rendered');
  const sourceError = new Error('source');
  const failed = await renderAdminPanelSection([], sourceError, {
    render: () => calls.push(['unexpected']),
    renderError: (error) => calls.push(['error', error.message]),
  });
  assert.equal(failed.status, 'error');
  assert.equal(failed.error, sourceError);
  await renderAdminPanelSection([], null, {
    render: () => { throw new Error('render'); },
    renderError: (error) => calls.push(['error', error.message]),
  });
  assert.deepEqual(calls, [
    ['render', ['item']], ['error', 'source'], ['error', 'render'],
  ]);
});

test('loads and renders admin panel sections before billing', async () => {
  const state = createInitialAppState({ isAdmin: true });
  const calls = [];
  const result = await renderAdminPanel({
    listTeamMembers: async () => ({ items: [{ userKey: 'u1' }] }),
    listFolders: async () => { throw new Error('folders'); },
  }, state, {
    renderMembers: (items) => calls.push(['members', items.length]),
    renderMembersError: (error) => calls.push(['members-error', error.message]),
    renderFolders: (items) => calls.push(['folders', items.length]),
    renderFoldersError: (error) => calls.push(['folders-error', error.message]),
    renderBilling: () => calls.push(['billing']),
  });
  assert.equal(result.status, 'rendered');
  assert.deepEqual(calls, [['members', 1], ['folders-error', 'folders'], ['billing']]);
  assert.equal((await renderAdminPanel({}, createInitialAppState())).status, 'skipped');
});

test('builds admin member rendering actions', async () => {
  const state = createInitialAppState({ ownerUserKey: 'owner' });
  const calls = [];
  let options;
  const section = createAdminMemberSection(state, {
    api: { updateTeamMember: async (...args) => calls.push(['update', ...args]) },
    target: 'target',
    renderMembers: (target, items, value) => { calls.push(['render', target, items]); options = value; },
    translate: (value) => `t:${value}`,
    safeAction: (action, label) => async (...args) => { calls.push(['action', label]); return action(...args); },
    confirmScopeChange: () => false,
    confirmRemove: () => true,
    onRemoved: () => calls.push(['removed']),
    reload: () => calls.push(['reload']),
  });
  section.renderMembers([{ userKey: 'u1' }]);
  assert.equal(options.ownerUserKey, 'owner');
  assert.equal(options.translate('x'), 't:x');
  const select = { value: 'next' };
  await options.onScopeChange({ userKey: 'u1' }, 'all', 'own', select);
  assert.equal(select.value, 'own');
  await options.onRemove({ userKey: 'u1' });
  assert.deepEqual(calls.slice(-4), [
    ['action', 'member remove'], ['update', 'u1', { status: 'left' }], ['removed'], ['reload'],
  ]);
});

test('builds admin folder overview rendering and selection', async () => {
  const state = createInitialAppState({ adminFolderId: 'f1' });
  const appended = [];
  const target = { innerHTML: 'old', appendChild: (node) => appended.push(node) };
  let overviewOptions;
  const section = createAdminFolderSection(state, {
    target,
    createOverview: (_folders, options) => {
      overviewOptions = options;
      return { pickerRow: 'picker', folder: { folderId: 'f1' }, wrap: 'wrap', empty: 'empty' };
    },
    safeAction: (action, label) => async (...args) => { appended.push(label); return action(...args); },
    reload: () => appended.push('reload'),
    renderNoFolders: () => appended.push('no-folders'),
    renderSelected: ({ folder }) => appended.push(`selected:${folder.folderId}`),
  });
  await section.renderFolders([{ folderId: 'f1' }]);
  assert.equal(target.innerHTML, '');
  assert.deepEqual(appended, ['picker', 'wrap', 'selected:f1']);
  await overviewOptions.onSelect('f2');
  assert.equal(state.adminFolderId, 'f2');
  assert.deepEqual(appended.slice(-2), ['admin folder select', 'reload']);
  await section.renderFolders([]);
  assert.equal(state.adminFolderId, '');
  assert.equal(appended.at(-1), 'no-folders');
});

test('builds selected admin folder actions and member rendering', async () => {
  const state = createInitialAppState();
  const calls = [];
  let actions;
  let memberOptions;
  const membersBox = { textContent: '', appendChild() {} };
  const renderSelected = createAdminSelectedFolderRenderer(state, {
    api: { listFolderMembers: async () => ({ items: [{ userKey: 'u1' }] }) },
    appendActions: (_wrap, value) => { actions = value; },
    renderMembers: (_box, items, value) => { calls.push(['members', items]); memberOptions = value; },
    createMembersBox: () => membersBox,
    safeAction: (action) => action,
  });
  const wrap = { appendChild: (node) => calls.push(['append', node]) };
  await renderSelected({ folder: { folderId: 'f1' }, wrap });
  assert.equal(typeof actions.onCreateInvite, 'function');
  assert.equal(typeof actions.onSetPassword, 'function');
  assert.equal(typeof actions.onDelete, 'function');
  assert.equal(typeof memberOptions.onRemove, 'function');
  assert.deepEqual(calls, [
    ['append', membersBox], ['members', [{ userKey: 'u1' }]],
  ]);
});

test('composes admin member, folder, selected-folder, and billing options', () => {
  const state = createInitialAppState();
  const options = createAdminPanelOptions(state, {
    isVisible: () => false,
    member: { renderMembers: () => undefined },
    folder: {
      createOverview: () => undefined,
      selected: { appendActions: () => undefined },
    },
    renderBilling: () => 'billing',
  });
  assert.equal(options.isVisible(), false);
  assert.equal(typeof options.renderMembers, 'function');
  assert.equal(typeof options.renderMembersError, 'function');
  assert.equal(typeof options.renderFolders, 'function');
  assert.equal(typeof options.renderFoldersError, 'function');
  assert.equal(options.renderBilling(), 'billing');
});
