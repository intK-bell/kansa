export function createInitialAppState(overrides = {}) {
  return {
    userKey: null, userName: null, idToken: null,
    roomId: null, roomName: null, teamRole: null, isAdmin: false, isDeveloper: false,
    uploadBlocked: false, billing: null, ownerUserKey: null,
    lastInviteToken: null, lastFolderInviteTokens: {}, adminFolderId: '', availableRooms: [],
    folderPasswordById: {}, folders: [], folderUnreadMap: {}, folderModeUnreadMap: {},
    selectedFolder: null, selectedFolderArchive: null, photos: [], quests: [], questSort: 'status',
    openAccordions: new Set(), restoreScrollY: null,
    isUploading: false, isCreatingQuest: false, uploadDrafts: [], uploadTargetQuestId: null,
    folderDetailTab: 'record', photoSearchScope: 'folder', photoSearchTag: 'all',
    photoSearchKeyword: '', searchPhotos: [], roomSearchNextToken: null,
    ...overrides,
  };
}

export function resetRoomState(state) {
  Object.assign(state, {
    roomId: null, roomName: null, teamRole: null, isAdmin: false,
    uploadBlocked: false, billing: null, ownerUserKey: null,
    lastInviteToken: null, lastFolderInviteTokens: {}, adminFolderId: '', availableRooms: [],
    folderPasswordById: {}, folders: [], folderUnreadMap: {}, folderModeUnreadMap: {},
    selectedFolder: null, selectedFolderArchive: null, photos: [], quests: [],
    folderDetailTab: 'record', photoSearchScope: 'folder', photoSearchTag: 'all',
    photoSearchKeyword: '', searchPhotos: [], roomSearchNextToken: null,
    restoreScrollY: null, uploadTargetQuestId: null,
  });
  state.openAccordions.clear();
  return state;
}

export async function runActionWithHandledErrors(action, {
  handleError = () => false,
} = {}) {
  try {
    return { ok: true, value: await action() };
  } catch (error) {
    if (await handleError(error)) return { ok: false, handled: true, error };
    throw error;
  }
}

export async function runRoomChange(state, nextRoomId, {
  confirmSwitch = () => true,
  renderRoomSelect = () => undefined,
  switchRoom,
} = {}) {
  const normalizedRoomId = String(nextRoomId || '');
  const previousRoomId = String(state.roomId || '');
  if (!normalizedRoomId || normalizedRoomId === previousRoomId) {
    renderRoomSelect();
    return { status: 'unchanged' };
  }
  const room = state.availableRooms.find((item) => String(item?.roomId || '') === normalizedRoomId);
  if (!room || String(room.memberStatus || '').toLowerCase() === 'disabled') {
    renderRoomSelect();
    return { status: 'unavailable' };
  }
  if (!confirmSwitch(room)) {
    renderRoomSelect();
    return { status: 'cancelled', room };
  }
  await runActionWithHandledErrors(() => switchRoom(room.roomId, room.roomName), {
    handleError: () => { renderRoomSelect(); return false; },
  });
  return { status: 'switched', room };
}

export async function runFolderChange(state, nextFolderId, {
  clearSelection = () => undefined,
  selectFolder,
  onMissing = () => undefined,
} = {}) {
  const folderId = String(nextFolderId || '');
  if (!folderId) {
    await clearSelection();
    return { status: 'cleared' };
  }
  const folder = state.folders.find((item) => String(item?.folderId || '') === folderId);
  if (!folder) {
    onMissing(folderId);
    return { status: 'missing', folderId };
  }
  await selectFolder(folder);
  return { status: 'selected', folder };
}

export async function runSubscriptionPlanChange(state, targetPlan, {
  planRank,
  confirmChange = () => true,
  startCheckout,
  changeSubscription,
  reload = () => undefined,
  onChanged = () => undefined,
  invalidPlanError = () => new Error('Invalid subscription plan'),
} = {}) {
  const mode = String(state.billing?.billingMode || 'prepaid').toLowerCase();
  const currentPlan = String(state.billing?.subscription?.currentPlan || 'FREE').toUpperCase();
  const normalizedTarget = String(targetPlan || '').toUpperCase();
  const currentRank = planRank(currentPlan);
  const targetRank = planRank(normalizedTarget);
  if (!targetRank) throw invalidPlanError(normalizedTarget);
  if (mode !== 'subscription' || currentRank === 0) {
    if (!confirmChange({ currentPlan, targetPlan: normalizedTarget, action: 'checkout' })) {
      return { status: 'cancelled', action: 'checkout' };
    }
    await startCheckout(normalizedTarget);
    return { status: 'checkout', targetPlan: normalizedTarget };
  }
  if (currentRank === targetRank) return { status: 'unchanged', targetPlan: normalizedTarget };
  const action = targetRank > currentRank ? 'upgrade' : 'downgrade';
  if (!confirmChange({ currentPlan, targetPlan: normalizedTarget, action })) {
    return { status: 'cancelled', action };
  }
  const result = await changeSubscription({ action, targetPlan: normalizedTarget });
  await reload();
  await onChanged({ action, currentPlan, targetPlan: normalizedTarget, result });
  return { status: 'changed', action, targetPlan: normalizedTarget, result };
}

export async function runFreePlanChange({
  confirmChange = () => true,
  changeSubscription,
  getRequirements = () => null,
  showRequirements = () => undefined,
  reload = () => undefined,
  onChanged = () => undefined,
} = {}) {
  if (!confirmChange()) return { status: 'cancelled' };
  let result;
  try {
    result = await changeSubscription({ action: 'free' });
  } catch (error) {
    const requirements = getRequirements(error);
    if (!requirements) throw error;
    await showRequirements(requirements, error);
    return { status: 'requirements-not-met', requirements };
  }
  await reload();
  await onChanged(result);
  return { status: 'changed', result };
}

export async function startAppInitialization(initialize, { onError = () => undefined } = {}) {
  const result = await runActionWithHandledErrors(initialize, {
    handleError: async (error) => { await onError(error); return true; },
  });
  return result.ok;
}

export async function loadTeamState(api, state, { onError = () => undefined } = {}) {
  try {
    const data = await api.getTeam();
    Object.assign(state, {
      roomId: data.roomId || state.roomId,
      roomName: data.roomName || state.roomName,
      teamRole: data.role || 'member',
      isAdmin: Boolean(data.isAdmin),
      uploadBlocked: Boolean(data.uploadBlocked),
      billing: data.billing || null,
      ownerUserKey: data.ownerUserKey || null,
    });
    return data;
  } catch (error) {
    Object.assign(state, {
      teamRole: null, roomId: null, isAdmin: false, uploadBlocked: false, billing: null, ownerUserKey: null,
    });
    onError(error);
    return null;
  }
}

export async function loadRoomListState(api, state) {
  if (!state.idToken) return null;
  const data = await api.listRooms();
  state.availableRooms = (data.items || []).filter((room) =>
    room && room.roomId && room.roomName && room.memberStatus !== 'left'
  );
  return data;
}

export async function loadFolderListState(api, state, {
  refreshUnread = () => undefined,
  onError = () => undefined,
} = {}) {
  try {
    const data = await api.listFolders();
    state.folders = data.items || [];
    await refreshUnread();
    return data;
  } catch (error) {
    state.folders = [];
    onError(error);
    return null;
  }
}

export async function switchRoomState(api, state, roomId, fallbackRoomName = '', {
  beforeReset = () => undefined,
  reset = () => resetRoomState(state),
  onReady = () => undefined,
} = {}) {
  const result = await api.switchRoom(roomId);
  const roomName = result.roomName || fallbackRoomName || null;
  await beforeReset();
  await reset();
  state.roomId = roomId;
  state.roomName = roomName;
  await onReady({ roomId, roomName, result });
  return result;
}

export async function loadFolderContentState(state, {
  mode,
  loadQuests,
  loadPhotos,
  onQuestMode = () => undefined,
  onRendered = () => undefined,
  onSearch = null,
} = {}) {
  if (mode === 'quest') {
    state.photos = [];
    state.selectedFolderArchive = null;
    onQuestMode();
    await loadQuests();
  } else {
    state.quests = [];
    await loadPhotos();
  }
  onRendered();
  if (state.folderDetailTab === 'search' && onSearch) await onSearch();
}

export async function loadPhotoState(api, state, folderId) {
  const data = await api.listPhotos(folderId);
  state.photos = data.items || [];
  state.selectedFolderArchive = {
    archivedCount: Number(data.archivedCount || 0),
    archiveMode: data.archiveMode || 'visible',
    archiveDays: Number(data.archiveDays || 30),
  };
  return data;
}

export async function loadQuestState(api, state, folderId) {
  const data = await api.listQuests(folderId);
  state.quests = data.items || [];
  return data;
}

export async function runPhotoSearchState(api, state, {
  tag = 'all', keyword = '', filterFolder = () => [], onCriteriaChanged = () => undefined,
} = {}) {
  state.photoSearchTag = tag || 'all';
  state.photoSearchKeyword = String(keyword || '').trim();
  state.roomSearchNextToken = null;
  onCriteriaChanged();
  if (state.photoSearchScope === 'room') {
    if (!state.roomId) return null;
    const data = await api.searchPhotos({
      roomId: state.roomId,
      logTag: state.photoSearchTag,
      keyword: state.photoSearchKeyword,
    });
    state.searchPhotos = data.items || [];
    state.roomSearchNextToken = data.nextToken || null;
    return data;
  }
  state.searchPhotos = filterFolder();
  return { items: state.searchPhotos, nextToken: null };
}

export async function runUploadBatch(state, {
  syncDrafts = () => undefined,
  validateDrafts = () => [],
  uploadDraft,
  isDuplicate = () => false,
  setLoading = () => undefined,
  onValidationError = () => undefined,
  onUploaded = () => undefined,
  onComplete = () => undefined,
  onError = (error) => { throw error; },
} = {}) {
  if (state.isUploading) return { status: 'busy' };
  syncDrafts();
  const drafts = state.uploadDrafts.slice();
  if (!drafts.length) return { status: 'empty' };
  const validationErrors = validateDrafts();
  if (validationErrors.length) {
    await onValidationError(validationErrors[0]);
    return { status: 'invalid', errors: validationErrors };
  }

  setLoading(true);
  let activeDraft = null;
  try {
    const result = {
      status: 'complete', totalFiles: drafts.length, uploadedCount: 0,
      duplicateCount: 0, uploadedDraftIds: [], targetQuestId: state.uploadTargetQuestId || null,
    };
    for (const [index, draft] of drafts.entries()) {
      activeDraft = draft;
      try {
        await uploadDraft(draft, index, result.targetQuestId);
        result.uploadedCount += 1;
        result.uploadedDraftIds.push(draft.localId);
      } catch (error) {
        if (isDuplicate(error)) {
          result.duplicateCount += 1;
          continue;
        }
        throw error;
      }
    }
    if (result.uploadedCount > 0) await onUploaded(result);
    await onComplete(result);
    return result;
  } catch (error) {
    await onError(error, activeDraft);
    return { status: 'error', error, activeDraft };
  } finally {
    setLoading(false);
  }
}

export function createUploadLoadingController(state, elements, {
  getExtraFileInputs = () => [],
  idleLabel = () => 'アップロード',
  loadingLabel = () => 'アップロード中...',
} = {}) {
  return {
    set(isLoading) {
      state.isUploading = isLoading;
      if (elements?.uploadBtn) {
        elements.uploadBtn.disabled = isLoading;
        elements.uploadBtn.classList.toggle('is-loading', isLoading);
        elements.uploadBtn.textContent = isLoading ? loadingLabel() : idleLabel();
      }
      if (elements?.photoFiles) elements.photoFiles.disabled = isLoading;
      for (const input of getExtraFileInputs()) input.disabled = isLoading;
      if (elements?.applyCommentBulkBtn) elements.applyCommentBulkBtn.disabled = isLoading;
      if (elements?.cancelUploadDraftsBtn) elements.cancelUploadDraftsBtn.disabled = isLoading;
      elements?.uploadLoading?.classList.toggle('hidden', !isLoading);
    },
  };
}

export function createUploadDraftController(state, {
  urlRef = URL,
  now = () => Date.now(),
  defaultLogTag = 'other',
  clearFileInputs = () => undefined,
  onRender = () => undefined,
} = {}) {
  const revoke = (draft) => {
    if (!draft?.previewUrl) return;
    try { urlRef.revokeObjectURL(draft.previewUrl); } catch (_) { /* Ignore preview cleanup errors. */ }
  };
  const revokeAll = () => state.uploadDrafts.forEach(revoke);
  return {
    revoke,
    clear() {
      revokeAll();
      state.uploadDrafts = [];
      state.uploadTargetQuestId = null;
      clearFileInputs();
      onRender();
    },
    rebuild(files, questId = null) {
      revokeAll();
      state.uploadTargetQuestId = questId || null;
      const timestamp = now();
      state.uploadDrafts = files.map((file, index) => ({
        localId: `${timestamp}_${index}_${file.name}`,
        file,
        originalName: file.name,
        logTag: defaultLogTag,
        initialComment: '',
        previewUrl: urlRef.createObjectURL(file),
      }));
      onRender();
    },
    remove(localIds) {
      const ids = new Set(localIds || []);
      if (!ids.size) return;
      state.uploadDrafts.forEach((draft) => { if (ids.has(draft.localId)) revoke(draft); });
      state.uploadDrafts = state.uploadDrafts.filter((draft) => !ids.has(draft.localId));
      if (!state.uploadDrafts.length) state.uploadTargetQuestId = null;
      onRender();
    },
  };
}

export function createUploadDraftEditor(state, {
  sync = () => undefined,
  validate = () => [],
  onRender = () => undefined,
  onClear = () => undefined,
  alertMissingComment = () => undefined,
  confirmBulkComment = () => true,
  confirmCancel = () => true,
} = {}) {
  return {
    sync,
    validate() {
      sync();
      return validate(state.uploadDrafts);
    },
    applyBulkComment() {
      if (!state.uploadDrafts.length) return false;
      sync();
      const nextComment = String(state.uploadDrafts[0]?.initialComment || '').slice(0, 50);
      if (!nextComment) {
        alertMissingComment();
        return false;
      }
      if (!confirmBulkComment()) return false;
      state.uploadDrafts.forEach((draft) => { draft.initialComment = nextComment; });
      onRender();
      return true;
    },
    cancel() {
      if (!state.uploadDrafts.length || !confirmCancel()) return false;
      onClear();
      return true;
    },
  };
}

export function createFolderDetailController(state, elements, {
  renderMode = () => undefined,
  renderSearchControls = () => undefined,
} = {}) {
  const syncSearchControls = () => renderSearchControls({
    scope: state.photoSearchScope,
    tag: state.photoSearchTag,
    keyword: state.photoSearchKeyword,
  });
  return {
    setTab(tab) {
      const nextTab = tab === 'search' ? 'search' : 'record';
      state.folderDetailTab = nextTab;
      const isSearch = nextTab === 'search';
      if (elements?.recordTabBtn) {
        elements.recordTabBtn.classList.toggle('is-active', !isSearch);
        elements.recordTabBtn.setAttribute('aria-selected', isSearch ? 'false' : 'true');
      }
      if (elements?.searchTabBtn) {
        elements.searchTabBtn.classList.toggle('is-active', isSearch);
        elements.searchTabBtn.setAttribute('aria-selected', isSearch ? 'true' : 'false');
      }
      elements?.recordPanel?.classList.toggle('hidden', isSearch);
      elements?.searchPanel?.classList.toggle('hidden', !isSearch);
      renderMode();
      return nextTab;
    },
    setSearchScope(scope) {
      state.photoSearchScope = scope === 'room' ? 'room' : 'folder';
      if (state.photoSearchScope === 'folder') state.roomSearchNextToken = null;
      syncSearchControls();
      return state.photoSearchScope;
    },
    syncSearchControls,
  };
}

export async function selectFolderState(state, folder, {
  renderFolders = () => undefined,
  showDetail = () => undefined,
  setRecordTab = () => undefined,
  setDetailTitle = () => undefined,
  loadContent = () => undefined,
} = {}) {
  Object.assign(state, {
    selectedFolder: folder,
    folderDetailTab: 'record',
    photoSearchScope: 'folder',
    photoSearchTag: 'all',
    photoSearchKeyword: '',
    searchPhotos: [],
    roomSearchNextToken: null,
  });
  renderFolders();
  showDetail();
  setRecordTab();
  setDetailTitle(folder);
  await loadContent();
  return folder;
}

export function clearFolderSelectionState(state, {
  clearDrafts = () => undefined,
  hideDetail = () => undefined,
  renderArchive = () => undefined,
  renderFolders = () => undefined,
} = {}) {
  Object.assign(state, {
    selectedFolder: null,
    selectedFolderArchive: null,
    photos: [],
    quests: [],
    searchPhotos: [],
    roomSearchNextToken: null,
    folderDetailTab: 'record',
    photoSearchScope: 'folder',
    photoSearchTag: 'all',
    photoSearchKeyword: '',
  });
  clearDrafts();
  hideDetail();
  renderArchive();
  renderFolders();
  return state;
}

export function ensureFolderPasswordState(state, folder, {
  prompt = () => null,
  onCancel = () => undefined,
  onMissing = () => undefined,
} = {}) {
  if (!folder?.hasPassword || state.folderPasswordById[folder.folderId]) return true;
  const entered = prompt(folder);
  if (entered === null) {
    onCancel();
    return false;
  }
  const password = String(entered || '').trim();
  if (!password) {
    onMissing();
    return false;
  }
  state.folderPasswordById[folder.folderId] = password;
  return true;
}

export function handleInvalidFolderPassword(error, state, folderId, {
  isInvalidPassword = () => false,
  cleanup = () => undefined,
  onInvalid = () => undefined,
} = {}) {
  if (!isInvalidPassword(error)) return false;
  delete state.folderPasswordById[folderId];
  cleanup();
  onInvalid(error);
  return true;
}

export function renderFolderListState(state, {
  renderList,
  onEmpty = () => undefined,
  onSelectionMissing = onEmpty,
} = {}) {
  const selectedFolderId = state.selectedFolder?.folderId || null;
  const hasFolders = renderList({
    folders: state.folders,
    unreadById: state.folderUnreadMap,
    selectedFolderId,
  });
  if (!hasFolders) {
    onEmpty();
    return { hasFolders: false, selectionMissing: Boolean(selectedFolderId) };
  }
  const selectionMissing = Boolean(selectedFolderId) &&
    !state.folders.some((folder) => folder?.folderId === selectedFolderId);
  if (selectionMissing) onSelectionMissing();
  return { hasFolders: true, selectionMissing };
}

export async function refreshFolderUnreadState(state, folderIds = null, {
  computeUnread,
} = {}) {
  const targets = folderIds
    ? state.folders.filter((folder) => folderIds.includes(folder.folderId))
    : state.folders;
  if (!targets.length) return [];
  const entries = await Promise.all(targets.map(async (folder) => {
    try {
      const unread = await computeUnread(folder.folderId);
      return [folder.folderId, unread || { photo: false, quest: false }];
    } catch (_) {
      return [folder.folderId, { photo: false, quest: false }];
    }
  }));
  for (const [folderId, unread] of entries) {
    const normalized = { photo: Boolean(unread.photo), quest: Boolean(unread.quest) };
    state.folderModeUnreadMap[folderId] = normalized;
    state.folderUnreadMap[folderId] = normalized.photo || normalized.quest;
  }
  return entries;
}

export async function computeFolderUnreadState(api, state, folderId, {
  normalizeMode = (mode) => mode,
  isUnread = () => false,
  questKey = (questId) => questId,
} = {}) {
  const folder = state.folders.find((item) => item.folderId === folderId);
  const result = { photo: false, quest: false };
  if (folder?.hasPassword && !state.folderPasswordById[folderId]) return result;
  if (normalizeMode(folder?.mode) === 'quest') {
    const data = await api.listQuests(folderId);
    for (const quest of data.items || []) {
      const latestIncoming = quest.latestCommentAt && quest.latestCommentBy && quest.latestCommentBy !== state.userKey
        ? quest.latestCommentAt : '';
      if (isUnread(questKey(quest.questId), latestIncoming)) {
        result.quest = true;
        break;
      }
    }
    return result;
  }
  const data = await api.listPhotos(folderId);
  for (const photo of data.items || []) {
    const latestIncoming = photo.latestCommentAt && photo.latestCommentBy && photo.latestCommentBy !== state.userKey
      ? photo.latestCommentAt : '';
    if (isUnread(photo.photoId, latestIncoming)) {
      result.photo = true;
      break;
    }
  }
  return result;
}

export function createCommentReadController(api, state, {
  readTracker,
  refreshFolderUnread = () => undefined,
  renderFolders = () => undefined,
} = {}) {
  return {
    async loadPhotoComments(photoId) {
      const data = await api.listPhotoComments(photoId);
      return data.items || [];
    },
    latestIncoming(comments) {
      return readTracker.latestIncomingAt(comments);
    },
    isUnread(key, latestIncomingAt) {
      return readTracker.isUnread(key, latestIncomingAt);
    },
    markAsRead(key, latestIncomingAt) {
      readTracker.markAsRead(key, latestIncomingAt);
    },
    async refreshSelectedFolder() {
      if (!state.selectedFolder) return false;
      await refreshFolderUnread([state.selectedFolder.folderId]);
      renderFolders();
      return true;
    },
  };
}

export async function runQuestCreation(state, elements, {
  text,
  createQuest,
  onCreated = () => undefined,
} = {}) {
  if (state.isCreatingQuest) return { status: 'busy' };
  if (!state.selectedFolder) return { status: 'no-folder' };
  const normalizedText = String(text || '').trim();
  if (!normalizedText) return { status: 'empty' };
  const folderId = state.selectedFolder.folderId;
  state.isCreatingQuest = true;
  if (elements?.createQuestBtn) elements.createQuestBtn.disabled = true;
  if (elements?.questText) elements.questText.disabled = true;
  try {
    const result = await createQuest(folderId, normalizedText);
    if (elements?.questText) elements.questText.value = '';
    await onCreated(result);
    return { status: 'created', result };
  } finally {
    state.isCreatingQuest = false;
    if (elements?.createQuestBtn) elements.createQuestBtn.disabled = false;
    if (elements?.questText) elements.questText.disabled = false;
  }
}

export function createActionBoundary({
  clearError = () => undefined,
  showError = () => undefined,
  formatError = ({ label, error }) => `${label || '処理'}失敗: ${error?.message || error}`,
  onError = () => undefined,
} = {}) {
  return {
    wrap(action, label) {
      return async (...args) => {
        try {
          clearError();
          return await action(...args);
        } catch (error) {
          showError(formatError({ label, error }));
          onError(error, label);
          return undefined;
        }
      };
    },
  };
}

export function createLowStorageController(state, elements, {
  storage,
  computeStats,
  formatMessage = ({ remain, plan }) => `容量を追加しますか？（現在の残り: ${remain} / 現在プラン: ${plan}）`,
  formatSize = (value) => String(value),
  planLabel = (plan) => plan,
  lowBytes = 100 * 1024 * 1024,
  lowRatio = 0.15,
} = {}) {
  const storageKey = () => `kansa_low_storage_prompted_${state.roomId || state.roomName || 'unknown'}`;
  return {
    storageKey,
    prompt() {
      if (!state.isAdmin || !state.billing || !elements?.lowStorageModal) return { status: 'ineligible' };
      const stats = computeStats(state.billing);
      const lowByBytes = stats.freeRemainBytes <= lowBytes;
      const lowByRatio = stats.freeBytes > 0 ? stats.freeRemainBytes / stats.freeBytes <= lowRatio : false;
      const key = storageKey();
      if (!state.uploadBlocked && !lowByBytes && !lowByRatio) {
        storage.removeItem(key);
        return { status: 'available', stats };
      }
      if (storage.getItem(key) === '1') return { status: 'already-shown', stats };
      if (elements.lowStorageMessage) {
        const plan = String(state.billing?.subscription?.currentPlan || 'FREE').toUpperCase();
        elements.lowStorageMessage.textContent = formatMessage({
          remain: formatSize(stats.freeRemainBytes), plan: planLabel(plan), stats,
        });
      }
      elements.lowStorageModal.classList.remove('hidden');
      storage.setItem(key, '1');
      return { status: 'shown', stats };
    },
    async charge({
      closeModal = () => undefined,
      openAdmin = () => false,
      loadAdmin = () => undefined,
      changePlan,
    } = {}) {
      closeModal();
      if (await openAdmin()) await loadAdmin();
      const usage = Number(state.billing?.usageBytes || 0);
      const gib = 1024 * 1024 * 1024;
      const recommendedPlan = usage > 5 * gib ? 'PRO' : usage > gib ? 'PLUS' : 'BASIC';
      await changePlan(recommendedPlan);
      return recommendedPlan;
    },
  };
}

export function renderBillingAdminState(state, elements, {
  buildStatus,
  guideText = () => '',
  archiveNote = () => '',
  renderGraph = () => undefined,
  promptLowStorage = () => undefined,
  syncPlanButtons = () => undefined,
} = {}) {
  if (elements?.billingStatus && state.billing) {
    elements.billingStatus.textContent = buildStatus(state.billing);
    if (elements.billingPlanGuide) elements.billingPlanGuide.textContent = guideText(state.billing);
    if (elements.billingArchiveNote) elements.billingArchiveNote.textContent = archiveNote(state.billing);
    renderGraph(state.billing);
    promptLowStorage(state.billing);
    syncPlanButtons(state.billing);
    return { status: 'rendered', billing: state.billing };
  }
  if (elements?.billingStatus) elements.billingStatus.textContent = '';
  if (elements?.billingPlanGuide) elements.billingPlanGuide.textContent = '';
  if (elements?.billingArchiveNote) elements.billingArchiveNote.textContent = '';
  elements?.billingGraph?.classList.add('hidden');
  syncPlanButtons(state.billing);
  return { status: 'empty' };
}

export function createStorageGraphController(state, elements, {
  renderTop,
  renderAdmin,
  formatSize,
  folderUsage = () => '',
  topLabels = {},
  adminLabels = {},
} = {}) {
  const syncTopWidth = () => {
    if (!elements?.billingGraphTop || !elements?.appHeaderSummary) return 0;
    const width = Math.round(elements.appHeaderSummary.getBoundingClientRect().width || 0);
    if (width > 0) elements.billingGraphTop.style.width = `${width}px`;
    else elements.billingGraphTop.style.removeProperty('width');
    return width;
  };
  return {
    syncTopWidth,
    renderTop() {
      if (!elements?.billingGraphTop || !elements?.billingGraphTopUsed || !elements?.billingGraphTopRemaining) return false;
      if (state.roomName && state.billing) syncTopWidth();
      renderTop({
        graph: elements.billingGraphTop,
        used: elements.billingGraphTopUsed,
        remaining: elements.billingGraphTopRemaining,
        usedText: elements.billingGraphTopUsedLabel,
        remainingText: elements.billingGraphTopRemainLabel,
        extraText: elements.billingGraphTopExtraLabel,
        submeta: elements.billingGraphTopSubmeta,
      }, state.billing, {
        active: Boolean(state.roomName), formatSize, extraLabel: folderUsage(), ...topLabels,
      });
      return true;
    },
    renderAdmin() {
      renderAdmin({
        graph: elements?.billingGraph,
        used: elements?.billingGraphUsed,
        remaining: elements?.billingGraphRemaining,
        usedLabel: elements?.billingGraphUsedLabel,
        remainLabel: elements?.billingGraphRemainLabel,
      }, state.billing, formatSize, adminLabels);
    },
  };
}

export function createBillingUiController(state, elements, {
  renderTopGraph = () => undefined,
  renderBillingBarInto,
  planLabel = (plan) => plan,
  translate = (label) => label,
  formatPlan,
  closeLowStorage = () => undefined,
  closeFolderPassword = () => undefined,
} = {}) {
  return {
    renderBar() {
      if (!elements?.billingBar) return false;
      renderTopGraph();
      renderBillingBarInto(elements.billingBar, {
        active: Boolean(state.roomName), billing: state.billing, uploadBlocked: state.uploadBlocked,
        ownerUserKey: state.ownerUserKey, userKey: state.userKey, isAdmin: state.isAdmin,
        planLabel, translate, ...(formatPlan ? { formatPlan } : {}),
      });
      return true;
    },
    syncAdminVisibility() {
      for (const key of ['teamAdminBtn', 'folderDeleteBtn', 'setFolderPasswordBtn', 'openFolderPasswordBtn']) {
        elements?.[key]?.classList.toggle('hidden', !state.isAdmin);
      }
      if (!state.isAdmin) {
        elements?.teamAdminCard?.classList.add('hidden');
        closeLowStorage();
        closeFolderPassword();
      }
      return state.isAdmin;
    },
  };
}

export function createTeamAdminController(state, elements, {
  closeMenu = () => undefined,
  renderCurrentRoomHeader = () => undefined,
  loadPanel = () => undefined,
} = {}) {
  const syncMode = (isOpen) => {
    elements?.appHeaderControls?.classList.toggle('hidden', isOpen);
    elements?.currentRoomStatic?.classList.toggle('hidden', !isOpen);
    renderCurrentRoomHeader();
    elements?.folderDetail?.classList.toggle('hidden', isOpen ? true : !state.selectedFolder);
    return isOpen;
  };
  return {
    syncMode,
    async open({ load = true } = {}) {
      if (!elements?.teamAdminCard) return false;
      const wasHidden = elements.teamAdminCard.classList.contains('hidden');
      elements.teamAdminCard.classList.remove('hidden');
      syncMode(true);
      if (load) await loadPanel();
      return wasHidden;
    },
    close() {
      elements?.teamAdminCard?.classList.add('hidden');
      syncMode(false);
    },
    async toggle() {
      if (!elements?.teamAdminCard) return false;
      elements.teamAdminCard.classList.toggle('hidden');
      closeMenu();
      const isOpen = !elements.teamAdminCard.classList.contains('hidden');
      syncMode(isOpen);
      await loadPanel();
      return isOpen;
    },
  };
}

export async function loadAdminPanelState(api, state, {
  isVisible = () => true,
} = {}) {
  if (!state.isAdmin || !isVisible()) return null;
  let members = [];
  let folders = [];
  let membersError = null;
  let foldersError = null;
  try {
    const data = await api.listTeamMembers();
    members = (data.items || []).filter((member) => member.status !== 'left');
  } catch (error) {
    membersError = error;
  }
  try {
    const data = await api.listFolders();
    folders = data.items || [];
    if (state.adminFolderId && !folders.some((folder) => folder.folderId === state.adminFolderId)) {
      state.adminFolderId = '';
    }
    if (!folders.length) state.adminFolderId = '';
  } catch (error) {
    foldersError = error;
  }
  return { members, folders, membersError, foldersError };
}

export async function loadAdminFolderMembers(api, folderId, {
  onLoaded = () => {},
  onError = () => {},
} = {}) {
  try {
    const data = await api.listFolderMembers(folderId);
    const members = data.items || [];
    await onLoaded(members);
    return { members, error: null };
  } catch (error) {
    await onError(error);
    return { members: [], error };
  }
}

export async function runTeamMemberUpdate(api, member, patch, {
  confirmUpdate = () => true,
  onCancelled = () => undefined,
  onUpdated = () => undefined,
  reload = () => undefined,
} = {}) {
  if (!confirmUpdate(member, patch)) {
    await onCancelled(member, patch);
    return { status: 'cancelled', member, patch };
  }
  await api.updateTeamMember(member.userKey, patch);
  await onUpdated(member, patch);
  await reload();
  return { status: 'updated', member, patch };
}

export async function selectAdminFolder(state, folderId, {
  reload = () => undefined,
} = {}) {
  state.adminFolderId = String(folderId || '');
  await reload();
  return state.adminFolderId;
}

export async function createAdminFolderInvite(api, state, folderId, {
  buildInviteUrl = (token) => token,
  onCreated = () => undefined,
  missingTokenError = () => new Error('Invite token is missing'),
} = {}) {
  return createInviteToken(api, {
    scopeId: folderId, buildInviteUrl, missingTokenError,
    saveToken: (token) => { state.lastFolderInviteTokens[folderId] = token; }, onCreated,
  });
}

export async function revokeAdminFolderInvite(api, state, folderId, {
  confirmRevoke = () => true,
  onMissing = () => undefined,
  onRevoked = () => undefined,
} = {}) {
  const token = state.lastFolderInviteTokens[folderId];
  return revokeInviteToken(api, token, {
    confirmRevoke, onMissing,
    clearToken: () => { delete state.lastFolderInviteTokens[folderId]; }, onRevoked,
  });
}

export async function createInviteToken(api, {
  scopeId,
  saveToken = () => undefined,
  buildInviteUrl = (token) => token,
  onCreated = () => undefined,
  missingTokenError = () => new Error('Invite token is missing'),
} = {}) {
  const result = await api.createInvite(scopeId);
  const token = result.token;
  if (!token) throw missingTokenError();
  await saveToken(token);
  const url = buildInviteUrl(token);
  await onCreated({ token, url });
  return { token, url };
}

export async function revokeInviteToken(api, token, {
  confirmRevoke = () => true,
  onMissing = () => undefined,
  clearToken = () => undefined,
  onRevoked = () => undefined,
} = {}) {
  if (!token) {
    await onMissing();
    return { status: 'missing' };
  }
  if (!confirmRevoke(token)) return { status: 'cancelled', token };
  await api.revokeInvite(token);
  await clearToken(token);
  await onRevoked(token);
  return { status: 'revoked', token };
}

export async function copyInviteText(value, {
  writeText,
  allowFallback = false,
  onMissing = () => undefined,
  onCopied = () => undefined,
  onFallback = () => undefined,
  onDenied = () => undefined,
} = {}) {
  const text = String(value || '').trim();
  if (!text) {
    await onMissing();
    return { status: 'missing' };
  }
  try {
    if (typeof writeText === 'function') {
      await writeText(text);
      await onCopied(text);
      return { status: 'copied', text };
    }
  } catch (_) {
    // Fall through to prompt or denied guidance.
  }
  if (allowFallback) {
    await onFallback(text);
    return { status: 'fallback', text };
  }
  await onDenied(text);
  return { status: 'denied', text };
}

export async function runFolderPasswordUpdate(api, state, folderId, password, {
  confirmUpdate = () => true,
  onUpdated = () => undefined,
  reloadFolders = () => undefined,
  reloadPanel = () => undefined,
} = {}) {
  const nextPassword = String(password || '');
  if (!confirmUpdate(nextPassword)) return { status: 'cancelled', hasPassword: Boolean(nextPassword) };
  await api.setFolderPassword(folderId, nextPassword);
  if (nextPassword) state.folderPasswordById[folderId] = nextPassword;
  else delete state.folderPasswordById[folderId];
  await onUpdated(nextPassword);
  await reloadFolders();
  await reloadPanel();
  return { status: 'updated', hasPassword: Boolean(nextPassword) };
}

export async function runFolderDelete(api, state, folderId, {
  confirmDelete = () => true,
  onDeleted = () => undefined,
  reloadFolders = () => undefined,
  reloadTeam = () => undefined,
  reloadPanel = () => undefined,
} = {}) {
  if (!confirmDelete()) return { status: 'cancelled', folderId };
  await api.deleteFolder(folderId);
  if (state.adminFolderId === folderId) state.adminFolderId = '';
  delete state.lastFolderInviteTokens[folderId];
  delete state.folderPasswordById[folderId];
  await onDeleted(folderId);
  await reloadFolders();
  await reloadTeam();
  await reloadPanel();
  return { status: 'deleted', folderId };
}

export const runAdminFolderDelete = runFolderDelete;

export async function runRoomDelete(api, {
  confirmDelete = () => true,
  confirmFinal = () => true,
  onDeleted = () => undefined,
  resetRoom = () => undefined,
  showSetup = () => undefined,
} = {}) {
  if (!confirmDelete()) return { status: 'cancelled', step: 'initial' };
  if (!confirmFinal()) return { status: 'cancelled', step: 'final' };
  await api.deleteTeam();
  await onDeleted();
  await resetRoom();
  await showSetup();
  return { status: 'deleted' };
}

export async function runAccountDelete(api, {
  getOwnedRoom = () => null, onOwnerBlocked = () => undefined,
  confirmDelete = () => true, confirmFinal = () => true,
  isOwnerConflict = () => false, onOwnerConflict = () => undefined,
  onDeleted = () => undefined, closeMenu = () => undefined,
  resetRoom = () => undefined, clearAuth = () => undefined, showAuth = () => undefined,
} = {}) {
  const ownedRoom = await getOwnedRoom();
  if (ownedRoom) {
    await onOwnerBlocked(ownedRoom);
    await closeMenu();
    return { status: 'owner-blocked', ownedRoom };
  }
  if (!confirmDelete()) return { status: 'cancelled', step: 'initial' };
  if (!confirmFinal()) return { status: 'cancelled', step: 'final' };
  try {
    await api.deleteAccount();
  } catch (error) {
    if (!isOwnerConflict(error)) throw error;
    await onOwnerConflict(error);
    await closeMenu();
    return { status: 'owner-conflict', error };
  }
  await onDeleted();
  await closeMenu();
  await resetRoom();
  await clearAuth();
  await showAuth();
  return { status: 'deleted' };
}

export async function runRoomLeave(api, {
  onAdminBlocked = () => undefined,
  onWarning = () => undefined,
  confirmLeave = () => true,
  closeMenu = () => undefined,
  resetRoom = () => undefined,
  showSetup = () => undefined,
  reloadRooms = () => undefined,
} = {}) {
  try {
    const team = await api.getTeam();
    if (team?.isAdmin) {
      await onAdminBlocked(team);
      await closeMenu();
      return { status: 'admin-blocked' };
    }
  } catch (_) {
    // Preserve local leave behavior when the guard request is unavailable.
  }
  await onWarning();
  if (!confirmLeave()) {
    await closeMenu();
    return { status: 'cancelled' };
  }
  let leaveError = null;
  try {
    await api.leaveTeam();
  } catch (error) {
    leaveError = error;
  }
  await resetRoom();
  await closeMenu();
  await showSetup();
  await reloadRooms();
  return { status: 'left', leaveError };
}

export async function runRoomCreation(api, state, roomName, {
  onInvalid = () => undefined,
  closeAdmin = () => undefined,
  resetRoom = () => undefined,
  showApp = () => undefined,
  onCreated = () => undefined,
  describeError = (error) => String(error?.message || error),
  onExistingRoom = () => undefined,
  onNameConflict = () => undefined,
  onError = () => undefined,
} = {}) {
  const value = String(roomName || '').trim();
  if (!value) {
    await onInvalid();
    return { status: 'invalid' };
  }
  try {
    await api.createRoom(value);
    await closeAdmin();
    await resetRoom();
    state.roomName = value;
    await showApp();
    await onCreated(value);
    return { status: 'created', roomName: value };
  } catch (error) {
    const message = describeError(error);
    if (message.includes('409')) {
      if (message.includes('already has a room')) {
        await onExistingRoom(error);
        return { status: 'existing-room', error };
      }
      await onNameConflict(error);
      return { status: 'name-conflict', error };
    }
    await onError(error);
    return { status: 'error', error };
  }
}

export async function runFolderCreation(api, {
  title,
  mode,
  password,
  normalizeMode = (value) => value,
  onInvalid = () => undefined,
  onValid = () => undefined,
  getPlanLimit = () => null,
  onPlanLimit = () => undefined,
  onCreated = () => undefined,
  reloadFolders = () => undefined,
  selectFolder = () => undefined,
} = {}) {
  const normalizedTitle = String(title || '').trim();
  if (!normalizedTitle) {
    await onInvalid();
    return { status: 'invalid' };
  }
  await onValid();
  const normalizedMode = normalizeMode(mode);
  const folderPassword = String(password || '').trim();
  let created;
  try {
    created = await api.createFolder({ title: normalizedTitle, mode: normalizedMode, folderPassword });
  } catch (error) {
    const limit = getPlanLimit(error);
    if (!limit) throw error;
    await onPlanLimit(limit, error);
    return { status: 'plan-limit', error, limit };
  }
  await onCreated(created);
  await reloadFolders();
  await selectFolder(created.folderId);
  return { status: 'created', folder: created };
}

export async function handleFolderListError(error, {
  describeError = (value) => String(value?.message || value || 'unknown'),
  isNetworkError = (message) => message.includes('Failed to fetch') || message.includes('Type error'),
  onNetworkError = () => undefined,
  onError = () => undefined,
} = {}) {
  const message = describeError(error);
  if (isNetworkError(message)) {
    await onNetworkError(message, error);
    return { type: 'network', message, error };
  }
  await onError(message, error);
  return { type: 'general', message, error };
}

export function createRoomCreationHandler(api, state, getRoomName, options = {}) {
  return async () => {
    await options.before?.();
    return runRoomCreation(api, state, getRoomName(), options);
  };
}

export function createFolderCreationHandler(api, getInput, options = {}) {
  return async () => runFolderCreation(api, { ...getInput(), ...options });
}

export const createRoomLeaveHandler = (api, options = {}) => async () => runRoomLeave(api, options);
export const createRoomDeleteHandler = (api, options = {}) => async () => runRoomDelete(api, options);
export const createAccountDeleteHandler = (api, options = {}) => async () => runAccountDelete(api, options);

export function createFolderDeleteHandler(api, state, getFolder, options = {}) {
  return async () => {
    const folder = getFolder();
    if (!folder?.folderId) return { status: 'missing' };
    return runFolderDelete(api, state, folder.folderId, options);
  };
}

export function createFolderPasswordHandler(api, state, getInput, options = {}) {
  return async () => {
    const input = getInput();
    if (!input?.folderId) return { status: 'missing' };
    return runFolderPasswordUpdate(api, state, input.folderId, input.password, options);
  };
}

export function createInviteHandlers(api, {
  getCopyValue = () => '',
  copyOptions = {},
  createOptions = {},
  getToken = () => null,
  revokeOptions = {},
} = {}) {
  return {
    copy: async () => copyInviteText(getCopyValue(), { ...copyOptions, allowFallback: true }),
    create: async () => createInviteToken(api, createOptions),
    revoke: async () => revokeInviteToken(api, getToken(), revokeOptions),
  };
}

export function createQuestMutationActions(api, quest, {
  confirmDelete = () => true,
  reloadQuests = () => undefined,
  reloadFolder = () => undefined,
} = {}) {
  return {
    async complete() {
      await api.updateQuest(quest.questId, { status: 'done' }, quest.folderId);
      await reloadQuests();
      return { status: 'completed' };
    },
    async remove() {
      if (!confirmDelete(quest)) return { status: 'cancelled' };
      await api.deleteQuest(quest.questId, quest.folderId);
      await reloadFolder();
      return { status: 'deleted' };
    },
  };
}

export function createPhotoMutationActions(api, photo, {
  confirmDelete = () => true,
  beforeUpdate = () => undefined,
  reload = () => undefined,
} = {}) {
  return {
    async updateLogTag(nextLogTag) {
      await beforeUpdate(photo);
      await api.updatePhoto(photo.photoId, { logTag: nextLogTag });
      await reload();
      return { status: 'updated' };
    },
    async remove() {
      if (!confirmDelete(photo)) return { status: 'cancelled' };
      await api.deletePhoto(photo.photoId);
      await reload();
      return { status: 'deleted' };
    },
  };
}

export function createQuestCommentMutationActions(api, quest, {
  confirmDelete = () => true,
  reload = () => undefined,
} = {}) {
  return {
    async add(text) {
      await api.createQuestComment(quest.questId, text, quest.folderId);
      await reload();
      return { status: 'created' };
    },
    async remove(comment) {
      if (!confirmDelete(comment)) return { status: 'cancelled' };
      await api.deleteQuestComment(quest.questId, comment.commentId, quest.folderId);
      await reload();
      return { status: 'deleted' };
    },
  };
}

export function createPhotoCommentMutationActions(api, photo, {
  confirmDelete = () => true,
  beforeEdit = () => undefined,
  reload = () => undefined,
} = {}) {
  return {
    async edit(comment, nextText) {
      await beforeEdit(photo, comment);
      await api.updatePhotoComment(photo.photoId, comment.commentId, nextText);
      await reload();
      return { status: 'updated' };
    },
    async remove(comment) {
      if (!confirmDelete(comment)) return { status: 'cancelled' };
      await api.deletePhotoComment(photo.photoId, comment.commentId);
      await reload();
      return { status: 'deleted' };
    },
  };
}

export function createPhotoCommentAddHandler(api, photo, {
  getText = () => '',
  setBusy = () => undefined,
  beforeAdd = () => undefined,
  reload = () => undefined,
} = {}) {
  let adding = false;
  return async function addPhotoComment() {
    const text = String(getText() || '').trim();
    if (adding || !text) return { status: adding ? 'busy' : 'empty' };
    adding = true;
    await setBusy(true);
    try {
      await beforeAdd(photo);
      await api.createPhotoComment(photo.photoId, text);
      await reload();
      return { status: 'created' };
    } catch (error) {
      adding = false;
      await setBusy(false);
      throw error;
    }
  };
}

export async function runOwnerRoomSwitch(api, state, ownedRoom, {
  onCurrentRoom = () => undefined,
  confirmSwitch = () => true,
  closeAdmin = () => undefined,
  resetRoom = () => undefined,
  showApp = () => undefined,
  onSwitched = () => undefined,
} = {}) {
  const isCurrent =
    (state.roomId && String(state.roomId) === String(ownedRoom?.roomId || '')) ||
    (state.roomName && String(state.roomName) === String(ownedRoom?.roomName || ''));
  if (isCurrent) {
    await onCurrentRoom(ownedRoom);
    return { status: 'current', ownedRoom };
  }
  if (!await confirmSwitch(ownedRoom)) return { status: 'cancelled', ownedRoom };
  await api.switchRoom(ownedRoom.roomId);
  await closeAdmin();
  await resetRoom();
  state.roomName = ownedRoom.roomName;
  await showApp(ownedRoom);
  await onSwitched(ownedRoom);
  return { status: 'switched', ownedRoom };
}

export async function saveUserDisplayName(api, state, value, {
  onInvalid = () => undefined,
  onSaved = () => undefined,
} = {}) {
  const displayName = String(value || '').trim();
  if (!displayName) {
    await onInvalid();
    return { status: 'invalid' };
  }
  await api.saveDisplayName(displayName);
  state.userName = displayName;
  await onSaved(displayName);
  return { status: 'saved', displayName };
}

export async function ensureUserDisplayName(api, state, {
  promptName = () => null,
  onLoaded = () => undefined,
  onInvalid = () => undefined,
  onSaved = () => undefined,
} = {}) {
  const user = await api.getCurrentUser();
  await onLoaded(user);
  if (user.displayName) {
    state.userName = user.displayName;
    return { status: 'existing', user };
  }
  while (true) {
    const next = await promptName();
    if (next === null) continue;
    const result = await saveUserDisplayName(api, state, next, { onInvalid, onSaved });
    if (result.status === 'saved') return { ...result, user };
  }
}

export function createDisplayNameChangeHandler(api, state, {
  promptName = () => null,
  onInvalid = () => undefined,
  onSaved = () => undefined,
  onFinished = () => undefined,
} = {}) {
  return async function changeDisplayName() {
    const next = await promptName(state.userName || '');
    if (next === null) {
      await onFinished('cancelled');
      return { status: 'cancelled' };
    }
    const result = await saveUserDisplayName(api, state, next, { onInvalid, onSaved });
    await onFinished(result.status);
    return result;
  };
}

export async function runFolderExport(api, state, format, {
  getFormatLabel = (value) => value,
  onMissingFolder = () => undefined,
  confirmExport = () => true,
  onStart = () => undefined,
  onDownloadReady = () => undefined,
  fetchDownload = () => { throw new Error('fetchDownload is required'); },
  downloadError = (status) => new Error(`download failed (${status})`),
  getFileName = () => 'export.pdf',
  createBlob = (chunks) => new Blob(chunks, { type: 'application/pdf' }),
  createObjectUrl = (blob) => URL.createObjectURL(blob),
  onProgress = () => undefined,
  onComplete = () => undefined,
  onReady = () => undefined,
  onFallback = () => undefined,
  onClose = () => undefined,
} = {}) {
  const folder = state.selectedFolder;
  if (!folder) {
    await onMissingFolder();
    return { status: 'missing' };
  }
  const formatLabel = getFormatLabel(format);
  if (!await confirmExport(formatLabel, format)) return { status: 'cancelled' };
  await onStart(formatLabel, format);
  try {
    const result = await api.exportFolder(folder.folderId, format);
    if (format !== 'pdf') {
      await onComplete();
      await onReady({ formatLabel, downloadUrl: result.downloadUrl });
      return { status: 'ready', result };
    }
    await onDownloadReady();
    try {
      const response = await fetchDownload(result.downloadUrl);
      if (!response.ok) throw downloadError(response.status);
      const fileName = getFileName(response);
      const total = Number(response.headers.get('content-length') || 0);
      let blob;
      if (!response.body || typeof response.body.getReader !== 'function') {
        blob = await response.blob();
      } else {
        const reader = response.body.getReader();
        const chunks = [];
        let loaded = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            chunks.push(value);
            loaded += value.byteLength;
            await onProgress(loaded, total);
          }
        }
        blob = createBlob(chunks);
      }
      const objectUrl = createObjectUrl(blob);
      await onReady({ formatLabel, downloadUrl: result.downloadUrl, fileName, objectUrl });
      return { status: 'ready', result };
    } catch (downloadFailure) {
      await onClose();
      await onFallback(result.downloadUrl, downloadFailure);
      return { status: 'fallback', result, error: downloadFailure };
    }
  } catch (error) {
    await onClose();
    throw error;
  }
}

export async function runAdminFolderMemberRemove(api, folderId, member, {
  confirmRemove = () => true,
  onRemoved = () => undefined,
  reload = () => undefined,
} = {}) {
  if (!confirmRemove(member)) return { status: 'cancelled', folderId, member };
  await api.removeFolderMember(folderId, member.userKey);
  await onRemoved(member);
  await reload();
  return { status: 'removed', folderId, member };
}

export async function renderAdminPanelSection(data, error, {
  render = () => undefined,
  renderError = () => undefined,
} = {}) {
  try {
    if (error) throw error;
    await render(data);
    return { status: 'rendered' };
  } catch (caughtError) {
    await renderError(caughtError);
    return { status: 'error', error: caughtError };
  }
}

export async function renderAdminPanel(api, state, {
  isVisible = () => true,
  renderMembers = () => undefined,
  renderMembersError = () => undefined,
  renderFolders = () => undefined,
  renderFoldersError = () => undefined,
  renderBilling = () => undefined,
} = {}) {
  const panelData = await loadAdminPanelState(api, state, { isVisible });
  if (!panelData) return { status: 'skipped' };
  const members = await renderAdminPanelSection(panelData.members, panelData.membersError, {
    render: renderMembers,
    renderError: renderMembersError,
  });
  const folders = await renderAdminPanelSection(panelData.folders, panelData.foldersError, {
    render: renderFolders,
    renderError: renderFoldersError,
  });
  await renderBilling();
  return { status: 'rendered', members, folders };
}

export function createAdminMemberSection(state, {
  api,
  target,
  renderMembers,
  translate = (value) => value,
  safeAction = (action) => action,
  confirmScopeChange = () => true,
  confirmRemove = () => true,
  onScopeUpdated = () => undefined,
  onRemoved = () => undefined,
  reload = () => undefined,
  renderError = () => undefined,
  scopeActionLabel = 'member scope update',
  removeActionLabel = 'member remove',
} = {}) {
  return {
    renderMembers(items) {
      renderMembers(target, items, {
        ownerUserKey: state.ownerUserKey,
        translate,
        onScopeChange: safeAction(async (member, next, previous, scopeSelect) => {
          await runTeamMemberUpdate(api, member, { folderScope: next }, {
            confirmUpdate: () => confirmScopeChange(member, next),
            onCancelled: () => { scopeSelect.value = previous; },
            onUpdated: () => onScopeUpdated(member, next),
            reload,
          });
        }, scopeActionLabel),
        onRemove: safeAction(async (member) => {
          await runTeamMemberUpdate(api, member, { status: 'left' }, {
            confirmUpdate: () => confirmRemove(member),
            onUpdated: () => onRemoved(member),
            reload,
          });
        }, removeActionLabel),
      });
    },
    renderMembersError: renderError,
  };
}

export function createAdminFolderSection(state, {
  target,
  createOverview,
  translate = (value) => value,
  formatCount,
  formatHeader,
  safeAction = (action) => action,
  reload = () => undefined,
  renderNoFolders = () => undefined,
  renderSelected = () => undefined,
  renderError = () => undefined,
  selectActionLabel = 'admin folder select',
} = {}) {
  return {
    async renderFolders(folders) {
      if (!target) return;
      target.innerHTML = '';
      if (!folders.length) {
        state.adminFolderId = '';
        await renderNoFolders(target);
        return;
      }
      const overview = createOverview(folders, {
        selectedFolderId: state.adminFolderId,
        translate,
        formatCount,
        formatHeader,
        onSelect: safeAction(async (folderId) => {
          await selectAdminFolder(state, folderId, { reload });
        }, selectActionLabel),
      });
      target.appendChild(overview.pickerRow);
      if (!overview.folder) {
        target.appendChild(overview.empty);
        return;
      }
      target.appendChild(overview.wrap);
      await renderSelected(overview);
    },
    renderFoldersError: renderError,
  };
}

export function createAdminSelectedFolderRenderer(state, {
  api,
  appendActions,
  renderMembers,
  createMembersBox,
  translate = (value) => value,
  safeAction = (action) => action,
  copyInvite,
  buildInviteUrl,
  missingTokenError,
  showInviteUrl,
  confirmRevoke,
  onMissingInvite,
  onInviteRevoked,
  confirmPassword,
  onPasswordUpdated,
  confirmDelete,
  onDeleted,
  confirmMemberRemove,
  onMemberRemoved,
  formatMemberLoadError = (error) => String(error?.message || error),
  reloadFolders = () => undefined,
  reloadTeam = () => undefined,
  reloadPanel = () => undefined,
} = {}) {
  return async ({ folder, wrap }) => {
    appendActions(wrap, {
      translate,
      onCopyInvite: safeAction(copyInvite, 'コンテナ招待URLコピー'),
      onCreateInvite: safeAction(async (inviteInput, revokeButton) => {
        await createAdminFolderInvite(api, state, folder.folderId, {
          buildInviteUrl,
          missingTokenError,
          onCreated: ({ url }) => showInviteUrl({ url, inviteInput, revokeButton }),
        });
      }, 'コンテナ招待URL発行'),
      onRevokeInvite: safeAction(async (inviteInput, revokeButton) => {
        await revokeAdminFolderInvite(api, state, folder.folderId, {
          confirmRevoke: () => confirmRevoke(folder),
          onMissing: onMissingInvite,
          onRevoked: () => onInviteRevoked({ inviteInput, revokeButton }),
        });
      }, 'コンテナ招待URL失効'),
      onSetPassword: safeAction(async (password, passwordInput) => {
        await runFolderPasswordUpdate(api, state, folder.folderId, password, {
          confirmUpdate: (next) => confirmPassword(folder, next),
          onUpdated: (next) => onPasswordUpdated({ password: next, passwordInput }),
          reloadFolders,
          reloadPanel,
        });
      }, 'コンテナパスワード設定'),
      onDelete: safeAction(async () => {
        await runAdminFolderDelete(api, state, folder.folderId, {
          confirmDelete: () => confirmDelete(folder),
          onDeleted,
          reloadFolders,
          reloadTeam,
          reloadPanel,
        });
      }, 'コンテナ削除'),
    });
    const membersBox = createMembersBox();
    wrap.appendChild(membersBox);
    await loadAdminFolderMembers(api, folder.folderId, {
      onLoaded: (items) => renderMembers(membersBox, items, {
        translate,
        onRemove: safeAction(async (member) => {
          await runAdminFolderMemberRemove(api, folder.folderId, member, {
            confirmRemove: () => confirmMemberRemove(member),
            onRemoved: onMemberRemoved,
            reload: reloadPanel,
          });
        }, 'コンテナメンバー解除'),
      }),
      onError: (error) => { membersBox.textContent = formatMemberLoadError(error); },
    });
  };
}

export function createAdminPanelOptions(state, {
  isVisible = () => true,
  member = {},
  folder = {},
  renderBilling = () => undefined,
} = {}) {
  const { selected = {}, ...folderOptions } = folder;
  return {
    isVisible,
    ...createAdminMemberSection(state, member),
    ...createAdminFolderSection(state, {
      ...folderOptions,
      renderSelected: createAdminSelectedFolderRenderer(state, selected),
    }),
    renderBilling,
  };
}

export function createReadTracker({ storage, getUserKey }) {
  const stateKey = () => `kansa_read_comments_${getUserKey() || 'guest'}`;
  const read = () => {
    try {
      return JSON.parse(storage.getItem(stateKey()) || '{}');
    } catch (_) {
      return {};
    }
  };
  const write = (value) => storage.setItem(stateKey(), JSON.stringify(value));
  return {
    latestIncomingAt(comments = [], userKey = getUserKey()) {
      return comments
        .filter((comment) => comment.createdBy !== userKey)
        .reduce((latest, comment) => (comment.createdAt > latest ? comment.createdAt : latest), '');
    },
    isUnread(key, latestIncomingAt) {
      if (!latestIncomingAt) return false;
      const map = read();
      return !map[key] || map[key] < latestIncomingAt;
    },
    markAsRead(key, latestIncomingAt) {
      if (!latestIncomingAt) return;
      const map = read();
      if (!map[key] || map[key] < latestIncomingAt) {
        map[key] = latestIncomingAt;
        write(map);
      }
    },
  };
}

export function createAppViewController(elements, { onTeamAdminMode = () => undefined } = {}) {
  const hide = (key) => elements?.[key]?.classList.add('hidden');
  return {
    closeMenu: () => hide('menuPanel'),
    closeTeamAdminPanel: () => { hide('teamAdminCard'); onTeamAdminMode(false); },
    closeRoomCreateModal: () => hide('roomCreateModal'),
    closeFolderCreateModal: () => hide('folderCreateModal'),
    closeFolderPasswordModal: () => {
      hide('folderPasswordModal');
      if (elements?.folderPasswordTargetName) elements.folderPasswordTargetName.textContent = '-';
    },
    closeHelpModal: () => hide('helpModal'),
    closeDeveloperModal: () => hide('developerModal'),
    closeThemeModal: () => hide('themeModal'),
    closeLowStorageModal: () => hide('lowStorageModal'),
    closeExportOptionsModal: () => hide('exportOptionsModal'),
  };
}

export function createExportProgressController(bar, windowRef = window) {
  let timer = null;
  const stop = () => {
    if (timer) windowRef.clearInterval(timer);
    timer = null;
  };
  const set = (percent) => {
    if (!bar) return;
    bar.classList.remove('is-indeterminate');
    bar.style.width = `${percent}%`;
  };
  return {
    start() {
      if (!bar) return;
      stop();
      let progress = 0;
      set(0);
      timer = windowRef.setInterval(() => {
        progress = progress < 10 ? progress + 0.9 : progress < 22 ? progress + 0.55 : progress < 40 ? progress + 0.3 : progress + 0.12;
        const next = Math.min(56, progress);
        set(next);
        if (next >= 56) stop();
      }, 60);
    },
    update(loaded, total) {
      const ratio = total > 0
        ? Math.min(100, Math.max(60, 60 + (loaded / total) * 40))
        : Math.min(96, Math.max(60, 60 + loaded / 65536));
      set(ratio);
    },
    markDownloadReady() { stop(); set(60); },
    complete() { stop(); set(100); },
    reset() { stop(); set(0); },
    stop,
  };
}

export function createExportResultController({
  elements,
  windowRef = window,
  documentRef = document,
  urlRef = URL,
  clipboard = windowRef.navigator?.clipboard,
  readyTitle = () => '生成完了',
  readyMessage = (label) => `${label} の生成が完了しました。操作を選んでください。`,
  copiedMessage = (label) => `${label} のリンクをコピーしました。`,
  onCopied = () => undefined,
} = {}) {
  let result = null;
  const clear = () => {
    if (result?.objectUrl) urlRef.revokeObjectURL(result.objectUrl);
    result = null;
  };
  return {
    show(nextResult) {
      result = { fileName: '', objectUrl: null, ...nextResult };
      if (elements?.exportLoadingTitle) elements.exportLoadingTitle.textContent = readyTitle();
      if (elements?.exportLoadingText) elements.exportLoadingText.textContent = readyMessage(result.formatLabel);
      if (elements?.exportLoadingBar) elements.exportLoadingBar.style.width = '100%';
      elements?.exportLoadingActions?.classList.remove('hidden');
      elements?.exportLoadingCloseBtn?.classList.remove('hidden');
    },
    clear,
    download() {
      if (!result) return;
      if (!result.objectUrl) {
        windowRef.location.href = result.downloadUrl;
        return;
      }
      const link = documentRef.createElement('a');
      link.href = result.objectUrl;
      if (result.fileName) link.download = result.fileName;
      link.rel = 'noopener';
      link.style.display = 'none';
      documentRef.body.appendChild(link);
      link.click();
      documentRef.body.removeChild(link);
    },
    openInNewTab() {
      if (result) windowRef.open(result.objectUrl || result.downloadUrl, '_blank', 'noopener');
    },
    async copyLink() {
      if (!result?.downloadUrl) return;
      await clipboard.writeText(result.downloadUrl);
      if (elements?.exportLoadingText) elements.exportLoadingText.textContent = copiedMessage(result.formatLabel);
      onCopied(result);
    },
    getResult: () => result,
  };
}

export function createPhotoPreviewController(elements, {
  emptyTitle = () => '写真全体表示',
  titleFor = (photo) => photo?.fileName || photo?.originalName || photo?.photoCode || emptyTitle(),
  altFor = (photo) => photo?.fileName || photo?.originalName || photo?.photoId || '写真プレビュー',
} = {}) {
  return {
    close() {
      elements?.photoPreviewModal?.classList.add('hidden');
      elements?.photoPreviewImage?.removeAttribute('src');
      if (elements?.photoPreviewTitle) elements.photoPreviewTitle.textContent = emptyTitle();
    },
    open(photo) {
      const imageUrl = photo?.viewUrl || photo?.previewUrl || '';
      if (!elements?.photoPreviewModal || !elements?.photoPreviewImage || !imageUrl) return false;
      elements.photoPreviewImage.src = imageUrl;
      elements.photoPreviewImage.alt = altFor(photo);
      if (elements.photoPreviewTitle) elements.photoPreviewTitle.textContent = titleFor(photo);
      elements.photoPreviewModal.classList.remove('hidden');
      return true;
    },
  };
}

export function createScreenController(elements) {
  const hidden = (key, value) => elements?.[key]?.classList.toggle('hidden', value);
  return {
    showAuth() {
      hidden('userSetup', false); hidden('roomSetup', true); hidden('app', true);
      hidden('globalMenuWrap', true); hidden('logoutBtn', true);
    },
    showRoomSetup({ authenticated = false } = {}) {
      hidden('userSetup', true); hidden('roomSetup', false); hidden('app', true);
      hidden('globalMenuWrap', !authenticated); hidden('logoutBtn', !authenticated);
    },
    showApp({ userName = '' } = {}) {
      hidden('userSetup', true); hidden('roomSetup', true); hidden('app', false);
      hidden('globalMenuWrap', false); hidden('logoutBtn', false);
      if (elements?.currentName) elements.currentName.textContent = userName;
    },
  };
}
