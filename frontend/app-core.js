export const LOG_TAGS = Object.freeze([
  { value: 'container_number', label: 'コンテナ番号', color: '#06224A' },
  { value: 'inbound', label: '搬入', color: '#1E90FF' },
  { value: 'outbound', label: '搬出', color: '#2E7D32' },
  { value: 'seal', label: 'シール', color: '#7C4DFF' },
  { value: 'damage', label: '損傷', color: '#E53935' },
  { value: 'other', label: 'その他', color: '#607D8B' },
]);

export const DEFAULT_LOG_TAG = 'container_number';

export function normalizeLogTag(value, fallback = DEFAULT_LOG_TAG) {
  const tag = String(value || '').trim();
  return LOG_TAGS.some((item) => item.value === tag) ? tag : fallback;
}

export function logTagMeta(value) {
  return LOG_TAGS.find((item) => item.value === normalizeLogTag(value, 'other')) || LOG_TAGS.at(-1);
}

export function downloadFileNameFromResponse(response, fallback = 'export.pdf') {
  const disposition = String(response?.headers?.get('content-disposition') || '');
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch (_) {
      return utf8Match[1];
    }
  }
  const plainMatch = disposition.match(/filename="?([^";]+)"?/i);
  return plainMatch?.[1] || fallback;
}

export async function resizeImageToJpeg(file, maxLongSide = 2048, quality = 0.82) {
  let bitmap = null;
  try {
    if (window.createImageBitmap) {
      bitmap = await window.createImageBitmap(file);
    } else {
      const url = URL.createObjectURL(file);
      const image = new Image();
      image.decoding = 'async';
      image.src = url;
      await new Promise((resolve, reject) => {
        image.onload = resolve;
        image.onerror = reject;
      });
      bitmap = image;
      URL.revokeObjectURL(url);
    }
  } catch (_) {
    return null;
  }
  if (!bitmap.width || !bitmap.height) return null;
  const scale = Math.max(bitmap.width, bitmap.height) > maxLongSide
    ? maxLongSide / Math.max(bitmap.width, bitmap.height)
    : 1;
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(bitmap.width * scale));
  canvas.height = Math.max(1, Math.round(bitmap.height * scale));
  const context = canvas.getContext('2d', { alpha: false });
  if (!context) return null;
  context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
  return new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
}

export function el(tag, attrs = {}, text = null) {
  const node = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([key, value]) => {
    if (value === null || value === undefined) return;
    if (key === 'class') node.className = value;
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else if (key.startsWith('on') && typeof value === 'function') node[key] = value;
    else node.setAttribute(key, String(value));
  });
  if (text !== null && text !== undefined) node.textContent = String(text);
  return node;
}

export function createLogTagBadge(value, suffix = '', translate = (label) => label) {
  const meta = logTagMeta(value);
  const badge = el('span', { class: 'tag-badge' }, `${translate(meta.label)}${suffix}`);
  badge.style.setProperty('--tag-color', meta.color);
  return badge;
}

export function createLogTagSelect(value = DEFAULT_LOG_TAG, translate = (label) => label) {
  const select = el('select', { class: 'js-log-tag-select' });
  LOG_TAGS.forEach((tag) => {
    select.appendChild(el('option', { value: tag.value }, translate(tag.label)));
  });
  select.value = normalizeLogTag(value);
  return select;
}

export function createLogTagUi(translate = (label) => label) {
  return {
    createLogTagBadge: (value, suffix = '') => createLogTagBadge(value, suffix, translate),
    createLogTagSelect: (value = DEFAULT_LOG_TAG) => createLogTagSelect(value, translate),
  };
}

export function renderLogTagSummaryInto(target, photos = [], translate = (label) => label) {
  if (!target) return;
  target.innerHTML = '';
  const counts = Object.fromEntries(LOG_TAGS.map((tag) => [tag.value, 0]));
  photos.forEach((photo) => {
    const tag = normalizeLogTag(photo.logTag, 'other');
    counts[tag] = (counts[tag] || 0) + 1;
  });
  LOG_TAGS.forEach((tag) => {
    target.appendChild(createLogTagBadge(tag.value, ` ${counts[tag.value] || 0}`, translate));
  });
}

export function collectAppElements(root = document) {
  const elements = {};
  root.querySelectorAll('[id]').forEach((node) => {
    const key = node.id.replace(/-([a-z0-9])/g, (_, char) => char.toUpperCase());
    elements[key] = node;
  });
  elements.appHeaderControls = root.querySelector('.app-header-controls');
  return elements;
}

export function bindGlobalAppEvents({
  windowRef = window,
  documentRef = document,
  elements,
  onUnhandledRejection,
  onError,
  onResize,
}) {
  if (onUnhandledRejection) windowRef.addEventListener('unhandledrejection', onUnhandledRejection);
  if (onError) windowRef.addEventListener('error', onError);
  if (onResize) windowRef.addEventListener('resize', onResize);

  const { menuBtn, menuPanel } = elements || {};
  if (menuBtn && menuPanel) {
    menuBtn.onclick = (event) => {
      event.stopPropagation();
      menuPanel.classList.toggle('hidden');
    };
    documentRef.addEventListener('click', (event) => {
      if (!menuPanel.contains(event.target) && event.target !== menuBtn) menuPanel.classList.add('hidden');
    });
  }

  documentRef.querySelectorAll('[data-menu-group]').forEach((group) => {
    group.addEventListener('toggle', () => {
      if (!group.open) return;
      documentRef.querySelectorAll('[data-menu-group]').forEach((other) => {
        if (other !== group) other.open = false;
      });
    });
  });
}

export function computeStorageStats(billing) {
  const usageBytes = Math.max(0, Number(billing?.usageBytes || 0));
  const freeBytes = Math.max(0, Number(billing?.freeBytes || 0));
  const mode = String(billing?.billingMode || 'prepaid').toLowerCase();
  const planLimitBytes = Math.max(0, Number(billing?.subscription?.limitBytes || 0));
  const capacityBytes = mode === 'subscription' && planLimitBytes > 0 ? planLimitBytes : freeBytes;
  const usedBytes = Math.min(usageBytes, capacityBytes);
  const freeRemainBytes = Math.max(0, capacityBytes - usageBytes);
  const usedRatio = capacityBytes > 0 ? Math.min(100, (usedBytes / capacityBytes) * 100) : 0;
  const remainRatio = Math.max(0, 100 - usedRatio);
  return { usageBytes, freeBytes, capacityBytes, usedBytes, freeRemainBytes, usedRatio, remainRatio };
}

export function renderCurrentRoomHeaderInto(target, roomName, emptyLabel = '未選択') {
  if (target) target.textContent = roomName || emptyLabel;
}

export function renderFolderModePanels(elements, mode) {
  const isPhoto = normalizeFolderMode(mode) === 'photo';
  if (elements.photoModePanel) elements.photoModePanel.classList.toggle('hidden', !isPhoto);
  if (elements.questModePanel) elements.questModePanel.classList.toggle('hidden', isPhoto);
  if (elements.photoList) elements.photoList.classList.toggle('hidden', !isPhoto);
  if (elements.questList) elements.questList.classList.toggle('hidden', isPhoto);
}

export function renderStorageGraphInto(elements, billing, formatSize = formatBytes, labels = {}) {
  const { graph, used, remaining, usedLabel, remainLabel } = elements;
  if (!graph || !used || !remaining) return;
  if (!billing) {
    graph.classList.add('hidden');
    return;
  }
  const stats = computeStorageStats(billing);
  used.style.width = `${stats.usedRatio}%`;
  remaining.style.width = `${stats.remainRatio}%`;
  if (usedLabel) usedLabel.textContent = (labels.used || ((size) => `使用量 ${size}`))(formatSize(stats.usageBytes));
  if (remainLabel) remainLabel.textContent = (labels.remaining || ((size) => `残り ${size}`))(formatSize(stats.freeRemainBytes));
  graph.classList.remove('hidden');
}

export function renderTopStorageGraphInto(elements, billing, {
  active = true,
  formatSize = formatBytes,
  usedLabel = (size) => `使用量 ${size}`,
  remainingLabel = (size) => `残り ${size}`,
  extraLabel = '',
} = {}) {
  const { graph, used, remaining, usedText, remainingText, extraText, submeta } = elements || {};
  if (!graph || !used || !remaining) return;
  if (!active || !billing) {
    graph.classList.add('hidden');
    return;
  }
  const stats = computeStorageStats(billing);
  used.style.width = `${stats.usedRatio}%`;
  remaining.style.width = `${stats.remainRatio}%`;
  if (usedText) usedText.textContent = usedLabel(formatSize(stats.usageBytes));
  if (remainingText) remainingText.textContent = remainingLabel(formatSize(stats.freeRemainBytes));
  if (extraText) extraText.textContent = extraLabel;
  if (submeta) submeta.classList.remove('hidden');
  graph.classList.remove('hidden');
}

export function renderBillingBarInto(target, {
  active = true,
  billing,
  uploadBlocked = false,
  ownerUserKey = '',
  userKey = '',
  isAdmin = false,
  planLabel = (plan) => plan,
  translate = (label) => label,
  formatPlan = (plan) => `${translate('プラン')}:${planLabel(plan)}`,
} = {}) {
  if (!target) return;
  if (!active || !billing) {
    target.classList.add('hidden');
    target.textContent = '';
    return;
  }
  const freeRemainBytes = Math.max(0, Number(billing.freeBytes || 0) - Number(billing.usageBytes || 0));
  const plan = String(billing?.subscription?.currentPlan || 'FREE').toUpperCase();
  const parts = [formatPlan(plan)];
  if (ownerUserKey && userKey) parts.push(ownerUserKey === userKey ? translate('作成者') : translate('参加者'));
  if (uploadBlocked) parts.push(translate('アップロード停止中（残量不足）'));
  if (!uploadBlocked && plan === 'FREE' && freeRemainBytes > 0) parts.push(translate('無料枠で利用中'));
  if (isAdmin) parts.push(translate('管理者'));
  target.textContent = parts.join(' / ');
  target.classList.remove('hidden');
}

export function syncSubscriptionPlanButtonsInto(elements, billing, {
  translate = (label) => label,
  formatCurrent = (label) => `${label}${translate('（現在のプラン）')}`,
} = {}) {
  const mode = String(billing?.billingMode || 'prepaid').toLowerCase();
  const currentPlan = String(billing?.subscription?.currentPlan || 'FREE').toUpperCase();
  const usageBytes = Number(billing?.usageBytes || 0);
  const currentRank = subscriptionPlanRank(currentPlan);
  const freeButton = elements?.subscribeFreeBtn;
  const isFreeCurrent = mode !== 'subscription' || currentPlan === 'FREE';
  if (freeButton) {
    const label = translate('フリープランに戻る');
    freeButton.textContent = isFreeCurrent ? formatCurrent(label) : label;
    freeButton.disabled = isFreeCurrent;
    freeButton.setAttribute('aria-pressed', isFreeCurrent ? 'true' : 'false');
  }
  [
    { plan: 'BASIC', button: elements?.subscribeBasicBtn, label: translate('1GBプラン (¥980/月)') },
    { plan: 'PLUS', button: elements?.subscribePlusBtn, label: translate('5GBプラン (¥1,980/月)') },
    { plan: 'PRO', button: elements?.subscribeProBtn, label: translate('10GBプラン (¥2,980/月)') },
  ].forEach(({ plan, button, label }) => {
    if (!button) return;
    const isCurrent = mode === 'subscription' && currentPlan === plan;
    const isDowngrade = mode === 'subscription' && subscriptionPlanRank(plan) < currentRank;
    const isOverTargetLimit = isDowngrade && usageBytes > subscriptionPlanLimitBytes(plan);
    button.textContent = isCurrent ? formatCurrent(label) : label;
    button.disabled = isCurrent || isOverTargetLimit;
    button.setAttribute('aria-pressed', isCurrent ? 'true' : 'false');
    button.title = isOverTargetLimit
      ? translate('現在の使用量がこのプランの上限を超えているため変更できません。') : '';
  });
}

export function bindAppControlEvents(elements, handlers = {}) {
  const bindings = [
    ['currentFolderSelect', 'change', handlers.onFolderChange],
    ['currentRoomSelect', 'change', handlers.onRoomChange],
    ['recordTabBtn', 'click', handlers.onRecordTab],
    ['searchTabBtn', 'click', handlers.onSearchTab],
    ['searchScopeFolderBtn', 'click', handlers.onSearchScopeFolder],
    ['searchScopeRoomBtn', 'click', handlers.onSearchScopeRoom],
    ['photoSearchBtn', 'click', handlers.onPhotoSearch],
    ['logTagFilter', 'change', handlers.onLogTagChange],
    ['photoSearchKeyword', 'keydown', handlers.onSearchKeywordKeydown],
  ];
  bindings.forEach(([key, type, handler]) => {
    if (elements?.[key] && handler) elements[key].addEventListener(type, handler);
  });
}

export function renderMyRoomsInto(target, items, activeRoomId, { translate = (label) => label, onSwitch } = {}) {
  if (!target) return;
  const rooms = (items || []).filter((room) =>
    room && room.roomId && room.roomName && room.memberStatus !== 'left'
  );
  if (!rooms.length) {
    target.textContent = translate('入室可能なお部屋がありません');
    return;
  }
  target.innerHTML = '';
  rooms.forEach((room) => {
    const row = el('div', { class: 'room-row' });
    const memberStatus = String(room.memberStatus || 'active').toLowerCase();
    const suffix = room.roomId === activeRoomId
      ? translate('（参加中）')
      : memberStatus === 'disabled' ? translate('（停止中）') : '';
    const ownerLabel = String(room.role || 'member').toLowerCase() === 'admin'
      ? translate('作成者: 自分') : translate('作成者: 別ユーザ');
    const label = el('div', { style: 'flex:1;' }, `${room.roomName}${suffix} / ${ownerLabel}`);
    const buttonLabel = room.roomId === activeRoomId
      ? translate('入室中') : memberStatus === 'disabled' ? translate('停止中') : translate('この部屋へ');
    const button = el('button', { type: 'button' }, buttonLabel);
    button.disabled = room.roomId === activeRoomId || memberStatus === 'disabled';
    if (onSwitch) button.onclick = () => onSwitch(room);
    row.appendChild(label);
    row.appendChild(button);
    target.appendChild(row);
  });
}

export function renderRoomSelectInto(select, rooms, { roomId = '', roomName = '', translate = (label) => label } = {}) {
  if (!select) return;
  select.innerHTML = '';
  if (!rooms?.length) {
    select.appendChild(el('option', { value: '' }, translate('お部屋がありません')));
    select.value = '';
    select.disabled = true;
    return;
  }
  rooms.forEach((room) => {
    const option = el('option', { value: room.roomId }, room.roomName);
    if (String(room.memberStatus || '').toLowerCase() === 'disabled') {
      option.disabled = true;
      option.textContent = `${room.roomName}${translate('（停止中）')}`;
    }
    select.appendChild(option);
  });
  const activeRoom = rooms.find((room) => String(room.roomId || '') === String(roomId || ''))
    || rooms.find((room) => String(room.roomName || '') === String(roomName || ''));
  select.disabled = false;
  select.value = activeRoom?.roomId || '';
}

export function bindModalDismissEvents(elements, modals = []) {
  modals.forEach(({ modalKey, closeKey, close }) => {
    const modal = elements?.[modalKey];
    const closeButton = elements?.[closeKey];
    if (closeButton) closeButton.addEventListener('click', close);
    if (modal) modal.addEventListener('click', (event) => {
      if (event.target === modal) close();
    });
  });
}

export function renderFolderSelectInto(select, folders, {
  unreadById = {}, selectedFolderId = '', translate = (label) => label, photoModeLabel = 'フォト',
} = {}) {
  if (!select) return false;
  select.innerHTML = '';
  if (!folders?.length) {
    select.appendChild(el('option', { value: '' }, translate('まだコンテナがなかです')));
    select.value = '';
    select.disabled = true;
    return false;
  }
  select.appendChild(el('option', { value: '' }, translate('コンテナ番号を選択してください')));
  folders.forEach((folder) => {
    const modeLabel = normalizeFolderMode(folder.mode) === 'quest' ? translate('クエスト') : translate(photoModeLabel);
    const lockedLabel = folder.hasPassword ? ` [${translate('鍵')}]` : '';
    const unreadLabel = unreadById[folder.folderId] ? ` ${translate('●新着')}` : '';
    select.appendChild(el('option', { value: folder.folderId }, `${folder.title} [${modeLabel}]${lockedLabel}${unreadLabel}`));
  });
  select.disabled = false;
  select.value = selectedFolderId || '';
  return true;
}

export function renderSearchResultsInto(target, photos, {
  translate = (label) => label,
  createTagBadge = (tag) => createLogTagBadge(tag, '', translate),
  onPreview,
} = {}) {
  if (!target) return;
  target.innerHTML = '';
  if (!photos?.length) {
    target.appendChild(el('div', { class: 'muted' }, translate('条件に合う写真はなかです。')));
    return;
  }
  photos.forEach((photo) => {
    const card = el('div', { class: 'photo-card search-photo-card' });
    const codeRow = el('div', { class: 'photo-card-meta-row' });
    codeRow.appendChild(el('strong', {}, photo.photoCode || 'P---'));
    codeRow.appendChild(createTagBadge(photo.logTag));
    card.appendChild(codeRow);
    const image = el('img', {
      class: 'photo-card-image', src: photo.viewUrl || '', alt: photo.fileName || photo.photoId, loading: 'lazy',
    });
    image.onclick = () => onPreview?.(photo);
    image.onkeydown = (event) => {
      if (!event || (event.key !== 'Enter' && event.key !== ' ')) return;
      event.preventDefault();
      onPreview?.(photo);
    };
    image.tabIndex = 0;
    image.setAttribute('role', 'button');
    image.setAttribute('aria-label', `${photo.fileName || photo.photoId} ${translate('を全体表示')}`);
    card.appendChild(image);
    if (photo.containerNumber || photo.folderTitle) {
      card.appendChild(el('div', { class: 'muted' }, `${translate('コンテナ')}: ${photo.containerNumber || photo.folderTitle}`));
    }
    card.appendChild(el('div', { class: 'muted' }, `${translate('投稿')}: ${photo.createdByName || '-'}`));
    target.appendChild(card);
  });
}

export function bindExportControlEvents(elements, handlers = {}) {
  const bindings = [
    ['exportLoadingCloseBtn', handlers.onCloseLoading],
    ['exportDownloadBtn', handlers.onDownload],
    ['exportOpenTabBtn', handlers.onOpenTab],
    ['exportCopyLinkBtn', handlers.onCopyLink],
    ['exportHighBtn', handlers.onHighQuality],
    ['exportLightBtn', handlers.onLightweight],
    ['exportPdfBtn', handlers.onPdf],
  ];
  bindings.forEach(([key, handler]) => {
    if (elements?.[key] && handler) elements[key].addEventListener('click', handler);
  });
}

export function bindInviteControlEvents(elements, handlers = {}) {
  const bindings = [
    ['copyInviteUrlBtn', handlers.onCopyInviteUrl],
    ['createInviteBtn', handlers.onCreateInvite],
    ['revokeInviteBtn', handlers.onRevokeInvite],
  ];
  bindings.forEach(([key, handler]) => {
    if (elements?.[key] && handler) elements[key].addEventListener('click', handler);
  });
}

export function renderRentalComparisonInto(container, grid, photos, {
  enabled = false, translate = (label) => label,
  createTagBadge = (tag, suffix) => createLogTagBadge(tag, suffix, translate), onPreview,
} = {}) {
  if (!container || !grid) return;
  container.classList.toggle('hidden', !enabled);
  if (!enabled) return;
  grid.innerHTML = '';
  [{ tag: 'inbound', label: translate('搬入') }, { tag: 'outbound', label: translate('搬出') }]
    .forEach(({ tag, label }) => {
      const column = el('div', { class: `rental-comparison-column rental-comparison-${tag}` });
      const matching = (photos || [])
        .filter((photo) => normalizeLogTag(photo.logTag, 'other') === tag)
        .sort((a, b) => String(a.createdAt || '').localeCompare(String(b.createdAt || '')));
      const heading = el('div', { class: 'rental-comparison-column-head' });
      heading.appendChild(createTagBadge(tag, ` ${matching.length}`));
      heading.appendChild(el('span', { class: 'rental-comparison-side-label' }, tag === 'inbound' ? 'BEFORE' : 'AFTER'));
      column.appendChild(heading);
      if (!matching.length) {
        column.appendChild(el('p', { class: 'muted rental-comparison-empty' }, `${label}の写真を登録すると、ここに表示されます。`));
      } else {
        const strip = el('div', { class: 'rental-comparison-strip' });
        matching.slice(0, 6).forEach((photo) => {
          const image = el('img', {
            src: photo.viewUrl || photo.previewUrl || '', alt: `${label} ${photo.photoCode || ''}`.trim(),
            loading: 'lazy', role: 'button', tabindex: '0',
          });
          image.onclick = () => onPreview?.(photo);
          image.onkeydown = (event) => {
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            onPreview?.(photo);
          };
          strip.appendChild(image);
        });
        column.appendChild(strip);
      }
      grid.appendChild(column);
    });
}

export function bindAuthControlEvents(elements, handlers = {}) {
  const bindings = [
    ['loginBtn', handlers.onLogin],
    ['signupBtn', handlers.onSignup],
    ['resetUserBtn', handlers.onResetUser],
    ['logoutBtn', handlers.onLogout],
    ['accountDeleteBtn', handlers.onDeleteAccount],
  ];
  bindings.forEach(([key, handler]) => {
    if (elements?.[key] && handler) elements[key].onclick = handler;
  });
}

export function renderPhotoArchiveNoteInto(target, archive, formatMessage) {
  if (!target) return;
  if (!archive || Number(archive.archivedCount || 0) <= 0 || archive.archiveMode !== 'hidden') {
    target.textContent = '';
    return;
  }
  const values = { count: archive.archivedCount, days: archive.archiveDays || 30 };
  target.textContent = formatMessage
    ? formatMessage(values)
    : `${values.count}件の写真は${values.days}日保存後にアーカイブされ、現在は非表示です。アーカイブ済みデータも容量に含まれます。有料プランにすると再表示されます。`;
}

export function syncSearchControlsInto(elements, searchState, translate = (label) => label) {
  const { searchScopeFolderBtn, searchScopeRoomBtn, logTagFilter, photoSearchKeyword } = elements;
  if (searchScopeFolderBtn) searchScopeFolderBtn.classList.toggle('is-active', searchState.scope === 'folder');
  if (searchScopeRoomBtn) searchScopeRoomBtn.classList.toggle('is-active', searchState.scope === 'room');
  if (logTagFilter && !logTagFilter.options.length) {
    logTagFilter.appendChild(el('option', { value: 'all' }, translate('すべて')));
    LOG_TAGS.forEach((tag) => logTagFilter.appendChild(el('option', { value: tag.value }, translate(tag.label))));
  }
  if (logTagFilter) logTagFilter.value = searchState.tag || 'all';
  if (photoSearchKeyword) photoSearchKeyword.value = searchState.keyword || '';
}

export function bindManagementControlEvents(elements, handlers = {}) {
  const keys = {
    leaveRoomBtn: 'onLeaveRoom', refreshMyRoomsBtn: 'onRefreshRooms', createRoomMenuBtn: 'onOpenRoomCreate',
    openFolderCreateBtn: 'onOpenFolderCreate', openFolderPasswordBtn: 'onOpenFolderPassword',
    developerDashboardBtn: 'onOpenDeveloperDashboard',
    helpMenuBtn: 'onOpenHelpMenu', helpUserLink: 'onOpenHelpUser', roomCreateSubmitBtn: 'onCreateRoom',
    teamAdminBtn: 'onOpenTeamAdmin', teamAdminBackBtn: 'onCloseTeamAdmin',
    folderDeleteBtn: 'onDeleteFolder', setFolderPasswordBtn: 'onSetFolderPassword',
  };
  Object.entries(keys).forEach(([key, handlerKey]) => {
    const handler = handlers[handlerKey];
    if (elements?.[key] && handler) elements[key].addEventListener('click', handler);
  });
}

export function sortQuests(items = [], sort = 'status') {
  const list = items.slice();
  const rank = { open: 0, shooting: 1, done: 2 };
  if (sort === 'oldest') return list.sort((a, b) => String(a.createdAt || '').localeCompare(String(b.createdAt || '')));
  if (sort === 'newest') return list.sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')));
  return list.sort((a, b) => {
    const statusDiff = (rank[a.status] ?? 9) - (rank[b.status] ?? 9);
    return statusDiff || String(b.createdAt || '').localeCompare(String(a.createdAt || ''));
  });
}

export function questStatusText(status, translate = (label) => label) {
  if (status === 'done') return translate('完了');
  if (status === 'shooting') return translate('撮影中');
  return translate('未対応');
}

export function createQuestCardHeader(quest, {
  translate = (label) => label, formatDateTime = (value) => value || '-',
  isAdmin = false, canDelete = false, onComplete, onDelete,
} = {}) {
  const card = el('div', { class: `quest-card quest-status-${quest.status || 'open'}` });
  const head = el('div', { class: 'quest-head' });
  const title = el('div');
  title.appendChild(el('strong', {}, quest.questCode || 'Q---'));
  title.appendChild(el('span', { class: 'quest-status' }, questStatusText(quest.status, translate)));
  head.appendChild(title);
  const actions = el('div', { class: 'comment-actions' });
  if (isAdmin && quest.status !== 'done' && onComplete) {
    actions.appendChild(el('button', { type: 'button', onclick: () => onComplete(quest) }, translate('完了')));
  }
  if (canDelete && onDelete) {
    actions.appendChild(el('button', {
      class: 'icon-btn danger', type: 'button', title: translate('削除'), onclick: () => onDelete(quest),
    }, '🗑'));
  }
  head.appendChild(actions);
  card.appendChild(head);
  card.appendChild(el('div', { class: 'quest-text' }, quest.text || ''));
  card.appendChild(el('div', { class: 'muted' }, `${translate('投稿')} ${formatDateTime(quest.createdAt)} ${quest.createdByName || ''}`));
  return card;
}

export function bindMutationControlEvents(elements, handlers = {}) {
  const keys = {
    roomCreateSubmitBtn: 'onCreateRoom', createRoomBtn: 'onCreateInitialRoom', createFolderBtn: 'onCreateFolder',
    createQuestBtn: 'onCreateQuest', uploadBtn: 'onUpload', exportBtn: 'onExport',
    folderDeleteBtn: 'onDeleteFolder', setFolderPasswordBtn: 'onSetFolderPassword',
    deleteTeamBtn: 'onDeleteTeam', accountDeleteBtn: 'onDeleteAccount',
  };
  Object.entries(keys).forEach(([key, handlerKey]) => {
    const handler = handlers[handlerKey];
    if (elements?.[key] && handler) elements[key].addEventListener('click', handler);
  });
}

export function createPhotoPreviewImage(photo, {
  className = '', title = '', ariaLabel = '', keyboard = true, onPreview,
} = {}) {
  const image = el('img', {
    class: className || null,
    src: photo.viewUrl || photo.previewUrl || '',
    alt: photo.fileName || photo.photoId,
    loading: 'lazy',
    title: title || null,
  });
  image.onclick = () => onPreview?.(photo);
  if (keyboard) {
    image.tabIndex = 0;
    image.setAttribute('role', 'button');
    image.setAttribute('aria-label', ariaLabel || `${photo.fileName || photo.photoId} を全体表示`);
    image.onkeydown = (event) => {
      if (!event || (event.key !== 'Enter' && event.key !== ' ')) return;
      event.preventDefault();
      onPreview?.(photo);
    };
  }
  return image;
}

export function createPhotoCommentRow(comment, {
  translate = (label) => label, formatDateTime = (value) => value || '-', editable = false, onEdit, onDelete,
} = {}) {
  const stamp = comment.updatedAt ? translate('修正') : translate('投稿');
  const stampAt = comment.updatedAt || comment.createdAt;
  const row = el('div', { class: 'comment' });
  const meta = el('div', { class: 'comment-meta' });
  meta.appendChild(el('span', { class: 'comment-meta-text' }, `${stamp} ${formatDateTime(stampAt)} ${comment.createdByName}`));
  row.appendChild(meta);
  row.appendChild(el('div', { class: 'comment-text' }, comment.text));
  if (!editable) return row;

  const actions = el('div', { class: 'comment-actions' });
  const editButton = el('button', { class: 'icon-btn', type: 'button', title: translate('コメント修正') }, '✎');
  const deleteButton = el('button', { class: 'icon-btn danger', type: 'button', title: translate('コメント削除') }, '🗑');
  editButton.onclick = () => {
    if (row.querySelector('.js-comment-editor')) return;
    const editor = el('div', { class: 'inline-edit js-comment-editor' });
    const textArea = el('textarea', { class: 'js-edit-text', rows: '3', style: 'flex:1' });
    textArea.value = comment.text || '';
    const saveButton = el('button', { class: 'js-save-edit', type: 'button' }, translate('保存'));
    const cancelButton = el('button', { class: 'js-cancel-edit danger', type: 'button' }, translate('取消'));
    editor.appendChild(textArea);
    editor.appendChild(saveButton);
    editor.appendChild(cancelButton);
    row.appendChild(editor);
    saveButton.onclick = () => {
      const nextText = textArea.value.trim();
      if (nextText) onEdit?.(comment, nextText);
    };
    cancelButton.onclick = () => editor.remove();
  };
  deleteButton.onclick = () => onDelete?.(comment);
  actions.appendChild(editButton);
  actions.appendChild(deleteButton);
  row.appendChild(actions);
  return row;
}

export function createQuestCommentsSection(quest, {
  translate = (label) => label,
  formatDateTime = (value) => value || '-',
  canDelete = () => false,
  onDelete,
  onAdd,
} = {}) {
  const wrap = el('div', { class: 'comments quest-comments' });
  (quest.comments || []).forEach((comment) => {
    const row = el('div', { class: 'comment' });
    row.appendChild(el(
      'div',
      { class: 'comment-meta-text' },
      `${formatDateTime(comment.updatedAt || comment.createdAt)} ${comment.createdByName || ''}`
    ));
    row.appendChild(el('div', { class: 'comment-text' }, comment.text));
    if (canDelete(comment)) {
      const actions = el('div', { class: 'comment-actions' });
      const deleteButton = el(
        'button',
        { class: 'icon-btn danger', type: 'button', title: translate('コメント削除') },
        '🗑'
      );
      deleteButton.onclick = () => onDelete?.(comment);
      actions.appendChild(deleteButton);
      row.appendChild(actions);
    }
    wrap.appendChild(row);
  });

  const addRow = el('div', { class: 'row', style: 'margin-top:8px;' });
  const textArea = el('textarea', { rows: '2', placeholder: translate('コメント'), style: 'flex:1' });
  const addButton = el('button', { type: 'button' }, translate('追加'));
  addButton.onclick = () => {
    const text = textArea.value.trim();
    if (text) onAdd?.(text);
  };
  addRow.appendChild(textArea);
  addRow.appendChild(addButton);
  wrap.appendChild(addRow);
  return wrap;
}

export function appendQuestPhotoArea(card, quest, {
  translate = (label) => label,
  createTagBadge = (tag) => createLogTagBadge(tag, '', translate),
  canDelete = () => false,
  onPreview,
  onDelete,
  onFiles,
} = {}) {
  const photoWrap = el('div', { class: 'quest-photo-strip' });
  (quest.photos || []).forEach((photo) => {
    const tile = el('div', { class: 'quest-photo-tile' });
    tile.appendChild(createPhotoPreviewImage(photo, {
      title: photo.fileName || '', keyboard: false, onPreview,
    }));
    tile.appendChild(createTagBadge(photo.logTag));
    if (canDelete(photo)) {
      const deleteButton = el(
        'button',
        { class: 'icon-btn danger', type: 'button', title: translate('写真削除') },
        '🗑'
      );
      deleteButton.onclick = () => onDelete?.(photo);
      tile.appendChild(deleteButton);
    }
    photoWrap.appendChild(tile);
  });
  if (!(quest.photos || []).length) {
    photoWrap.appendChild(el('div', { class: 'muted' }, translate('写真はまだなかです。')));
  }
  card.appendChild(photoWrap);

  const addPhoto = el('div', { class: 'quest-add-photo' });
  const fileInput = el('input', {
    class: 'js-quest-files', type: 'file', accept: 'image/*', multiple: 'multiple',
  });
  fileInput.addEventListener('change', (event) => {
    const files = Array.from(event.target.files || []);
    if (files.length) onFiles?.(files, quest);
  });
  addPhoto.appendChild(fileInput);
  card.appendChild(addPhoto);
  card.appendChild(el('div', { class: 'quest-upload-slot', 'data-quest-id': quest.questId }));
  return { photoWrap, fileInput };
}

export function renderTeamMembersInto(target, items = [], {
  ownerUserKey = '',
  translate = (label) => label,
  onScopeChange,
  onRemove,
} = {}) {
  if (!target) return;
  target.innerHTML = '';
  if (!items.length) {
    target.appendChild(el('div', { class: 'muted' }, translate('メンバーがおらんばい')));
    return;
  }
  items.forEach((member) => {
    const row = el('div', { class: 'member-row' });
    const name = member.displayName || member.userKey;
    const scope = member.folderScope ? ` / ${translate('閲覧')}:${member.folderScope}` : '';
    row.appendChild(el('div', {}, `${name} / ${member.role} / ${member.status}${scope}`));
    const actions = el('div', { class: 'row', style: 'gap:6px; justify-content:flex-end;' });
    if (member.folderScope === 'invited') {
      actions.appendChild(el('span', { class: 'muted' }, translate('コンテナ招待')));
    } else {
      const scopeSelect = el('select', { style: 'min-width:120px;' });
      scopeSelect.appendChild(el('option', { value: 'own' }, translate('自分のコンテナのみ')));
      scopeSelect.appendChild(el('option', { value: 'all' }, translate('全コンテナ表示')));
      scopeSelect.value = member.role === 'admin' ? 'all' : member.folderScope || 'all';
      scopeSelect.disabled = member.role === 'admin' || member.userKey === ownerUserKey;
      scopeSelect.onchange = () => onScopeChange?.(member, scopeSelect.value, member.folderScope || 'all', scopeSelect);
      actions.appendChild(scopeSelect);
    }
    if (member.role !== 'admin' && member.userKey !== ownerUserKey) {
      const removeButton = el('button', { type: 'button', class: 'danger' }, translate('削除'));
      removeButton.onclick = () => onRemove?.(member);
      actions.appendChild(removeButton);
    }
    row.appendChild(actions);
    target.appendChild(row);
  });
}

export function createFolderAdminOverview(folders = [], {
  selectedFolderId = '',
  translate = (label) => label,
  formatSize = formatBytes,
  formatCount = (count) => `${count}件`,
  formatHeader,
  onSelect,
} = {}) {
  const pickerRow = el('div', { class: 'row folder-admin-picker' });
  const folderSelect = el('select');
  folderSelect.appendChild(el('option', { value: '' }, translate('コンテナを選択してください')));
  folders.forEach((folder) => {
    const modeLabel = normalizeFolderMode(folder.mode) === 'quest' ? translate('クエスト') : translate('フォト');
    const lockedLabel = folder.hasPassword ? ` [${translate('鍵')}]` : '';
    const label = `${folder.folderCode ? `${folder.folderCode} ` : ''}${folder.title || folder.folderId} [${modeLabel}]${lockedLabel}`;
    folderSelect.appendChild(el('option', { value: folder.folderId }, label));
  });
  folderSelect.value = selectedFolderId;
  folderSelect.onchange = () => onSelect?.(folderSelect.value, folderSelect);
  pickerRow.appendChild(folderSelect);
  pickerRow.appendChild(el('span', { class: 'muted' }, formatCount(folders.length)));

  const folder = folders.find((item) => item.folderId === selectedFolderId) || null;
  if (!folder) {
    return { pickerRow, folderSelect, folder, empty: el('div', { class: 'muted folder-admin-empty' }, '') };
  }
  const wrap = el('div', { class: 'folder-admin-block' });
  const header = el('div', { class: 'folder-admin-header' });
  const headerText = formatHeader
    ? formatHeader(folder)
    : `${folder.folderCode || ''} ${folder.title || folder.folderId}（作成:${folder.createdByName || folder.createdBy} / 容量:${formatSize(Number(folder.usageBytes || 0))}）`;
  header.appendChild(el('div', {}, headerText));
  wrap.appendChild(header);
  return { pickerRow, folderSelect, folder, wrap };
}

export function appendFolderAdminActions(wrap, {
  translate = (label) => label,
  onCopyInvite, onCreateInvite, onRevokeInvite, onSetPassword, onDelete,
} = {}) {
  const inviteRow = el('div', { class: 'row folder-admin-actions' });
  const inviteInput = el('input', { placeholder: translate('コンテナ招待URL'), readonly: 'readonly' });
  const inviteCell = el('div', { class: 'invite-url-cell' });
  const copyButton = el('button', { type: 'button' }, translate('コピー'));
  const createButton = el('button', { type: 'button' }, translate('招待URL発行（7日）'));
  const revokeButton = el('button', { type: 'button', class: 'danger hidden' }, translate('招待URL失効'));
  copyButton.onclick = () => onCopyInvite?.(inviteInput);
  createButton.onclick = () => onCreateInvite?.(inviteInput, revokeButton);
  revokeButton.onclick = () => onRevokeInvite?.(inviteInput, revokeButton);
  inviteRow.appendChild(createButton);
  inviteRow.appendChild(revokeButton);
  inviteCell.appendChild(inviteInput);
  inviteCell.appendChild(copyButton);
  inviteRow.appendChild(inviteCell);
  wrap.appendChild(inviteRow);

  const passwordRow = el('div', { class: 'row folder-admin-actions folder-admin-password' });
  const passwordInput = el('input', {
    placeholder: translate('コンテナパスワード（空で解除）'), type: 'password',
  });
  const passwordButton = el('button', { type: 'button' }, translate('設定/解除'));
  passwordButton.onclick = () => onSetPassword?.(String(passwordInput.value || '').trim(), passwordInput);
  passwordRow.appendChild(passwordInput);
  passwordRow.appendChild(passwordButton);
  wrap.appendChild(passwordRow);

  const deleteRow = el('div', { class: 'row folder-admin-actions' });
  const deleteButton = el('button', { type: 'button', class: 'danger' }, translate('削除'));
  deleteButton.onclick = () => onDelete?.();
  deleteRow.appendChild(deleteButton);
  wrap.appendChild(deleteRow);
  return { inviteInput, revokeButton, passwordInput };
}

export function renderFolderMembersInto(target, items = [], {
  translate = (label) => label,
  onRemove,
} = {}) {
  if (!target) return;
  target.innerHTML = '';
  if (!items.length) {
    target.appendChild(el('div', { class: 'muted' }, translate('メンバーがおらんばい')));
    return;
  }
  const reasonLabels = {
    admin: translate('管理者'),
    all: translate('全コンテナ'),
    owner: translate('作成者'),
    invited: translate('コンテナ招待'),
  };
  target.appendChild(el('h3', {}, translate('メンバー')));
  items.forEach((member) => {
    const name = member.displayName || member.userKey;
    const reason = reasonLabels[member.accessReason]
      || member.accessReason || member.folderScope || translate('権限');
    const row = el('div', { class: 'member-row folder-admin-member-row' });
    row.appendChild(el('div', {}, `${name}（${reason} / ${member.status || 'active'}）`));
    const actions = el('div', { class: 'row', style: 'gap:6px; justify-content:flex-end;' });
    if (member.accessReason === 'invited' && member.folderScope === 'invited') {
      const removeButton = el(
        'button', { type: 'button', class: 'danger' }, translate('このコンテナから外す')
      );
      removeButton.onclick = () => onRemove?.(member);
      actions.appendChild(removeButton);
    }
    row.appendChild(actions);
    target.appendChild(row);
  });
}

export function createPhotoCardShell(photo, {
  translate = (label) => label,
  createTagBadge = (tag) => createLogTagBadge(tag, '', translate),
  canEdit = false,
  ariaLabel = '',
  onPreview,
} = {}) {
  const card = el('div', { class: 'photo-card' });
  const codeRow = el('div', { class: 'photo-card-meta-row' });
  codeRow.appendChild(el('strong', {}, photo.photoCode || 'P---'));
  codeRow.appendChild(createTagBadge(photo.logTag));
  card.appendChild(codeRow);
  card.appendChild(createPhotoPreviewImage(photo, { className: 'photo-card-image', ariaLabel, onPreview }));
  card.appendChild(el('div', { class: 'muted' }, `${translate('投稿')}: ${photo.createdByName || ''}`));
  const editWrap = el('div', { class: 'inline-edit js-photo-edit-wrap hidden' });
  if (canEdit) {
    const actions = el('div', { class: 'comment-actions' });
    actions.appendChild(el('button', {
      class: 'icon-btn js-edit-photo', type: 'button', title: translate('タグ修正'),
    }, `✎ ${translate('タグ')}`));
    actions.appendChild(el('button', {
      class: 'icon-btn danger js-del-photo', type: 'button', title: translate('写真削除'),
    }, '🗑'));
    card.appendChild(actions);
  }
  card.appendChild(editWrap);
  return { card, editWrap };
}

export function bindPhotoCardEditing({
  card,
  editWrap,
  photo,
  translate = (label) => label,
  createTagSelect = createLogTagSelect,
  onSave,
  onDelete,
}) {
  const editButton = card?.querySelector?.('.js-edit-photo');
  const deleteButton = card?.querySelector?.('.js-del-photo');
  if (editButton) {
    editButton.onclick = () => {
      if (!editWrap.classList.contains('hidden')) return;
      editWrap.classList.remove('hidden');
      editWrap.innerHTML = '';
      const select = createTagSelect(photo.logTag);
      const saveButton = el('button', { class: 'js-photo-name-save', type: 'button' }, translate('保存'));
      const cancelButton = el(
        'button', { class: 'js-photo-name-cancel danger', type: 'button' }, translate('取消')
      );
      editWrap.appendChild(select);
      editWrap.appendChild(saveButton);
      editWrap.appendChild(cancelButton);
      saveButton.onclick = () => {
        const nextLogTag = normalizeLogTag(select.value, '');
        if (nextLogTag) onSave?.(photo, nextLogTag);
      };
      cancelButton.onclick = () => {
        editWrap.classList.add('hidden');
        editWrap.innerHTML = '';
      };
    };
  }
  if (deleteButton) deleteButton.onclick = () => onDelete?.(photo);
}

export function appendPhotoCardComments(card, accordion, unread, translate = (label) => label) {
  card.appendChild(accordion);
  card.appendChild(el(
    'div',
    { class: 'muted', style: 'margin-top: 6px;' },
    unread ? translate('未読コメントがあります') : translate('未読コメントなし')
  ));
}

export function bindBillingControlEvents(elements, handlers = {}) {
  const bindings = [
    ['subscribeBasicBtn', handlers.onBasic], ['subscribePlusBtn', handlers.onPlus],
    ['subscribeProBtn', handlers.onPro], ['subscribeFreeBtn', handlers.onFree],
    ['lowStorageChargeBtn', handlers.onLowStorageCharge],
  ];
  bindings.forEach(([key, handler]) => {
    if (elements?.[key] && handler) elements[key].addEventListener('click', handler);
  });
}

export function createPhotoCommentsAccordion({ unread = false, translate = (label) => label } = {}) {
  const accordion = el('details', { class: 'comments-accordion' });
  const summary = el('summary', { class: 'comments-summary' });
  summary.appendChild(el('span', { class: 'accordion-marker', 'aria-hidden': 'true' }, '▶'));
  const commentLabel = el('span', {}, translate('コメント'));
  summary.appendChild(commentLabel);
  if (unread) summary.appendChild(el('span', { class: 'unread-badge' }, translate('未読')));
  accordion.appendChild(summary);
  const commentWrap = el('div', { class: 'comments' });
  commentWrap.appendChild(el('div', { class: 'muted' }, translate('開いたら読み込みます')));
  accordion.appendChild(commentWrap);
  const addRow = el('div', { class: 'row', style: 'margin-top:8px;' });
  const textArea = el('textarea', {
    class: 'js-comment-text', placeholder: translate('コメント'), rows: '2', style: 'flex:1',
  });
  const addButton = el('button', { class: 'js-add-comment', type: 'button' }, translate('追加'));
  addRow.appendChild(textArea);
  addRow.appendChild(addButton);
  accordion.appendChild(addRow);
  return { accordion, summary, commentLabel, commentWrap, textArea, addButton };
}

export function bindPhotoCommentsAccordionLifecycle({
  accordion,
  summary,
  commentWrap,
  commentLabel,
  photoId,
  initiallyOpen = false,
  translate = (label) => label,
  formatCommentLabel = (count) => `${translate('コメント')} (${count})`,
  loadComments,
  getLatestIncoming,
  renderComments,
  onOpenChange,
  onRead,
  onAfterToggle,
}) {
  let commentsLoaded = false;
  let latestIncoming = '';
  accordion.open = initiallyOpen;
  accordion.addEventListener('toggle', async () => {
    if (accordion.open) {
      onOpenChange?.(true);
      if (!commentsLoaded) {
        commentWrap.innerHTML = '';
        commentWrap.appendChild(el('div', { class: 'muted' }, translate('読み込み中...')));
        const comments = await loadComments();
        commentsLoaded = true;
        commentLabel.textContent = formatCommentLabel(comments.length);
        latestIncoming = getLatestIncoming?.(comments) || '';
        renderComments(comments);
      }
      onRead?.(latestIncoming);
      summary.querySelector('.unread-badge')?.remove();
    } else {
      onOpenChange?.(false);
    }
    await onAfterToggle?.();
  });
}

export function createUploadDraftRow(draft, index, {
  translate = (label) => label,
  createTagSelect = (value) => createLogTagSelect(value, translate),
  onRemove,
  onPreview,
} = {}) {
  const row = el('div', { class: 'upload-draft-row', 'data-draft-id': draft.localId });
  const head = el('div', { class: 'upload-draft-head' });
  head.appendChild(el('strong', {}, `${index + 1}. ${draft.originalName}`));
  const headActions = el('div', { class: 'upload-draft-head-actions' });
  headActions.appendChild(el('span', { class: 'muted' }, formatBytes(draft.file?.size || 0)));
  const removeButton = el('button', {
    class: 'icon-btn danger upload-draft-remove', type: 'button', title: translate('この写真を除外'),
  }, '✕');
  removeButton.addEventListener('click', () => onRemove?.(draft));
  headActions.appendChild(removeButton);
  head.appendChild(headActions);
  row.appendChild(head);

  const name = draft.originalName || `draft-${index + 1}`;
  const thumbnail = el('img', { class: 'upload-draft-thumb', src: draft.previewUrl || '', alt: name, loading: 'lazy' });
  thumbnail.addEventListener('click', () => onPreview?.(draft));
  thumbnail.addEventListener('keydown', (event) => {
    if (!event || (event.key !== 'Enter' && event.key !== ' ')) return;
    event.preventDefault();
    onPreview?.(draft);
  });
  thumbnail.tabIndex = 0;
  thumbnail.setAttribute('role', 'button');
  thumbnail.setAttribute('aria-label', `${name} ${translate('を全体表示')}`);
  thumbnail.addEventListener('error', () => thumbnail.classList.add('hidden'));
  row.appendChild(thumbnail);

  const grid = el('div', { class: 'upload-draft-grid' });
  const tagField = el('label', { class: 'upload-draft-field' });
  tagField.appendChild(el('span', { class: 'upload-draft-label' }, translate('タグ')));
  const tagSelect = createTagSelect(draft.logTag);
  const syncTag = (event) => { draft.logTag = normalizeLogTag(event.target.value); };
  tagSelect.addEventListener('input', syncTag);
  tagSelect.addEventListener('change', syncTag);
  tagField.appendChild(tagSelect);
  grid.appendChild(tagField);

  const commentField = el('label', { class: 'upload-draft-field' });
  commentField.appendChild(el('span', { class: 'upload-draft-label' }, translate('初回コメント')));
  const commentInput = el('textarea', {
    class: 'js-upload-draft-comment', rows: '2', maxlength: '50', placeholder: translate('初回コメント（任意）'),
  });
  commentInput.value = draft.initialComment || '';
  const syncComment = (event) => { draft.initialComment = String(event.target.value || '').slice(0, 50); };
  commentInput.addEventListener('input', syncComment);
  commentInput.addEventListener('change', syncComment);
  commentField.appendChild(commentInput);
  grid.appendChild(commentField);
  row.appendChild(grid);
  return row;
}

export function bindUploadControlEvents(elements, handlers = {}) {
  const bindings = [
    ['photoFiles', 'change', handlers.onFilesChange],
    ['folderTitle', 'input', handlers.onFolderTitleInput],
    ['questSort', 'change', handlers.onQuestSortChange],
    ['applyCommentBulkBtn', 'click', handlers.onApplyBulkComment],
    ['cancelUploadDraftsBtn', 'click', handlers.onCancelDrafts],
  ];
  bindings.forEach(([key, type, handler]) => {
    if (elements?.[key] && handler) elements[key].addEventListener(type, handler);
  });
}

export function syncUploadDraftsFromRows(container, drafts) {
  if (!container) return;
  container.querySelectorAll('.upload-draft-row[data-draft-id]').forEach((row) => {
    const draftId = row.getAttribute('data-draft-id');
    const draft = drafts.find((item) => item.localId === draftId);
    if (!draft) return;
    const tagSelect = row.querySelector('.js-log-tag-select');
    const commentInput = row.querySelector('.js-upload-draft-comment');
    if (tagSelect) draft.logTag = normalizeLogTag(tagSelect.value);
    if (commentInput) draft.initialComment = String(commentInput.value || '').slice(0, 50);
  });
}

export function validateUploadDraftItems(drafts, {
  invalidTagMessage = (row) => `${row}行目: タグを選択してください。`,
  longCommentMessage = (row) => `${row}行目: 初回コメントは50文字以内にしてください。`,
} = {}) {
  const errors = [];
  drafts.forEach((draft, index) => {
    const row = index + 1;
    if (!normalizeLogTag(draft.logTag, '')) errors.push(invalidTagMessage(row));
    if (String(draft.initialComment || '').trim().length > 50) errors.push(longCommentMessage(row));
  });
  return errors;
}

export function renderUploadDraftContainerInto(elements, drafts, {
  uploadTargetQuestId = null,
  formatStatus = (count) => `${count}件の写真をアップロード対象に追加しています。`,
  createRow,
} = {}) {
  const { uploadMetaCard, uploadMetaList, uploadMetaStatus, applyCommentBulkBtn } = elements;
  if (!uploadMetaCard || !uploadMetaList || !uploadMetaStatus) return;
  const hasDrafts = drafts.length > 0;
  uploadMetaCard.classList.toggle('hidden', !hasDrafts);
  if (applyCommentBulkBtn) {
    applyCommentBulkBtn.classList.toggle('hidden', drafts.length < 2 || Boolean(uploadTargetQuestId));
  }
  uploadMetaList.innerHTML = '';
  if (!hasDrafts) {
    uploadMetaStatus.textContent = '';
    return;
  }
  uploadMetaStatus.textContent = formatStatus(drafts.length);
  drafts.forEach((draft, index) => uploadMetaList.appendChild(createRow(draft, index)));
}

export function questReadKey(questId) {
  return `quest:${questId}`;
}

export function normalizeCognitoDomain(raw) {
  const value = String(raw || '').trim();
  if (!value) return '';
  const withoutProto = value.replace(/^https?:\/\//i, '');
  const host = withoutProto.split('/')[0];
  return host.replace(/\.auth\..*$/, '');
}

export function parseJwt(token) {
  if (!token) return null;
  try {
    const payload = token.split('.')[1];
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(normalized));
  } catch (_) {
    return null;
  }
}

export function normalizeFolderMode(value) {
  return String(value || '').trim().toLowerCase() === 'quest' ? 'quest' : 'photo';
}

export function formatBytes(bytes) {
  const n = Number(bytes || 0);
  const mib = 1024 * 1024;
  const gib = 1024 * 1024 * 1024;
  if (n >= gib) return `${(n / gib).toFixed(2)}GB`;
  return `${Math.round(n / mib)}MB`;
}

export function asMessage(error) {
  if (!error) return 'unknown error';
  if (typeof error === 'string') return error;
  return error.message || 'unknown error';
}

export function parseApiErrorBody(error) {
  if (error && typeof error === 'object' && error.body && typeof error.body === 'object') return error.body;
  const raw = asMessage(error);
  const match = raw.match(/APIエラー\(\d+\):\s*(\{[\s\S]*\})$/);
  if (!match) return null;
  try {
    return JSON.parse(match[1]);
  } catch (_) {
    return null;
  }
}

export function planToProductLabel(plan) {
  const value = String(plan || '').trim().toUpperCase();
  if (value === 'BASIC') return '1GB';
  if (value === 'PLUS') return '5GB';
  if (value === 'PRO') return '10GB';
  return null;
}

export function createSubscriptionPlanUi({
  translate = (label) => label,
  formatMessage = (label, values = {}) => String(label).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) =>
    Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : match),
} = {}) {
  const displayLabel = (plan) => {
    const normalized = String(plan || '').trim().toUpperCase();
    const product = planToProductLabel(normalized);
    if (product) return formatMessage('{product}プラン', { product });
    if (normalized === 'FREE') return translate('無料プラン');
    return normalized || translate('不明');
  };
  return {
    displayLabel,
    confirmText(currentPlan, targetPlan, action) {
      const currentLabel = displayLabel(currentPlan);
      const targetLabel = displayLabel(targetPlan);
      if (action === 'checkout') return formatMessage('{plan}を申し込みますか？', { plan: targetLabel });
      const lines = [
        formatMessage('{currentPlan}から{targetPlan}へ変更してよかですか？', { currentPlan: currentLabel, targetPlan: targetLabel }),
        '',
        translate(action === 'upgrade' ? '差額はStripeで即時請求されます。' : '今すぐ反映されます。'),
      ];
      return lines.join('\n');
    },
    successText(targetPlan, action) {
      const plan = displayLabel(targetPlan);
      return action === 'upgrade'
        ? formatMessage('{plan}へ変更しました。差額はStripeで即時請求されます。', { plan })
        : formatMessage('{plan}へ変更しました。', { plan });
    },
  };
}

export function createFreePlanUi({
  translate = (label) => label,
  formatMessage = (label, values = {}) => String(label).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) =>
    Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : match),
  formatSize = formatBytes,
} = {}) {
  return {
    guideText(folderLimit) {
      return folderLimit === null
        ? translate('1GB〜10GBプラン: コンテナ無制限 / 3年保存 / PPT透かしなし')
        : translate('フリープラン: コンテナ2個 / 30日保存 / PPT透かしあり');
    },
    requirementText(constraints = {}) {
      const lines = [
        translate('フリープランへの切り替えは、以下を満たす必要があります。'),
        translate('・容量が512MB未満'),
        translate('・コンテナの数が2つ以下'),
      ];
      const unmet = Array.isArray(constraints.unmet) ? constraints.unmet : [];
      if (unmet.includes('usageBytes')) {
        lines.push(formatMessage('・現在の容量: {size}', { size: formatSize(Number(constraints.usageBytes || 0)) }));
      }
      if (unmet.includes('folderCount')) {
        lines.push(formatMessage('・現在のコンテナ数: {count}', { count: Number(constraints.folderCount || 0) }));
      }
      return lines.join('\n');
    },
    confirmText() {
      return [
        translate('フリープランへ戻してよかですか？'), '',
        translate('実行するとStripeの定期課金は今すぐ停止します。'),
        translate('当月の残り期間分の返金はありません。'),
        translate('フリープランへ戻すには、容量512MB未満・コンテナ2個以下である必要があります。'),
      ].join('\n');
    },
    successText() {
      return [
        translate('フリープランに戻りました。'), '',
        translate('Stripeの定期課金は停止しました。'),
        translate('当月の残り期間分の返金はありません。'),
        translate('現在の上限は、容量512MB未満・コンテナ2個までです。'),
      ].join('\n');
    },
  };
}

export function createBillingStatusUi({
  formatMessage = (label, values = {}) => String(label).replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key) =>
    Object.prototype.hasOwnProperty.call(values, key) ? String(values[key]) : match),
  formatSize = formatBytes,
  planLabel = (plan) => plan,
} = {}) {
  const folderLimit = (billing) => {
    const mode = String(billing?.billingMode || 'prepaid').toLowerCase();
    const currentPlan = String(billing?.subscription?.currentPlan || 'FREE').toUpperCase();
    return mode !== 'subscription' || currentPlan === 'FREE' ? 2 : null;
  };
  const folderUsage = (folders, billing) => {
    const count = Array.isArray(folders) ? folders.length : 0;
    const limit = folderLimit(billing);
    return limit === null
      ? formatMessage('コンテナ {count} / 無制限', { count })
      : formatMessage('コンテナ {count} / {limit}', { count, limit });
  };
  return {
    folderLimit,
    folderUsage,
    statusText(billing, folders) {
      const stats = computeStorageStats(billing);
      const plan = String(billing?.subscription?.currentPlan || 'FREE').toUpperCase();
      const subscription = String(billing?.billingMode || 'prepaid').toLowerCase() === 'subscription';
      const capacity = subscription
        ? formatMessage('プラン容量 {size}', { size: formatSize(stats.capacityBytes) })
        : formatMessage('無料 {size}', { size: formatSize(billing?.freeBytes || 0) });
      return formatMessage('使用量 {used} / {capacity}（残り {remain}） / {folderSummary} / プラン {plan}', {
        used: formatSize(billing?.usageBytes || 0),
        capacity,
        remain: formatSize(stats.freeRemainBytes),
        folderSummary: folderUsage(folders, billing),
        plan: planLabel(plan),
      });
    },
  };
}

export function createAdminPanelUi({
  translate = (value) => value,
  formatMessage = (template, values = {}) => String(template).replace(/\{(\w+)\}/g, (_, key) => values[key] ?? ''),
  formatSize = (value) => String(value),
  describeError = (error) => String(error?.message || error),
} = {}) {
  const memberName = (member) => member.displayName || member.userKey;
  const folderName = (folder) => folder.title || folder.folderId;
  return {
    confirmScopeChange: (member) => formatMessage('メンバー「{name}」の閲覧権限を変更してよかですか？', { name: memberName(member) }),
    confirmMemberRemove: (member) => formatMessage('メンバー「{name}」をお部屋から削除してよかですか？（本人は入れんごとなります）', { name: memberName(member) }),
    scopeUpdated: () => translate('閲覧権限を更新しました。'),
    memberRemoved: () => translate('メンバーを削除しました。'),
    memberLoadError: (error) => formatMessage('メンバー取得失敗: {message}', { message: describeError(error) }),
    folderCount: (count) => formatMessage('{count}件', { count }),
    folderHeader: (folder) => formatMessage('{folder}（作成:{creator} / 容量:{size}）', {
      folder: `${folder.folderCode || ''} ${folder.title || folder.folderId}`,
      creator: folder.createdByName || folder.createdBy,
      size: formatSize(Number(folder.usageBytes || 0)),
    }),
    noFolders: () => translate('コンテナがなかです'),
    missingInviteToken: () => translate('招待トークンが取得できませんでした。'),
    confirmInviteRevoke: (folder) => formatMessage('コンテナ「{folder}」の招待URLを失効してよかですか？', { folder: folderName(folder) }),
    missingInvite: () => translate('失効する招待URLがなかです（先に発行してください）'),
    inviteRevoked: () => translate('コンテナ招待URLを失効しました。'),
    confirmPassword: (folder, password) => formatMessage(password
      ? 'コンテナ「{folder}」のパスワードを設定してよかですか？'
      : 'コンテナ「{folder}」のパスワードを解除してよかですか？', { folder: folderName(folder) }),
    passwordUpdated: (password) => translate(password ? 'コンテナのパスワードを設定しました。' : 'コンテナのパスワードを解除しました。'),
    confirmFolderDelete: (folder) => formatMessage('コンテナ「{folder}」を削除してよかですか？（写真とコメントも消えます）', { folder: folderName(folder) }),
    folderDeleted: () => translate('コンテナを削除しました。'),
    confirmFolderMemberRemove: (member) => formatMessage('メンバー「{name}」をこのコンテナから外してよかですか？', { name: memberName(member) }),
    folderMemberRemoved: () => translate('コンテナメンバーを外しました。'),
    folderLoadError: (error) => formatMessage('コンテナ取得失敗: {message}', { message: describeError(error) }),
    archiveNote: () => translate('※ 30日保存後はアーカイブへ移動し、アーカイブは容量に含まれます。\n※ フリープランへ戻す際の容量判定にはアーカイブ済みデータも含みます。'),
  };
}

export function createRoomCreationUi({
  translate = (value) => value,
  formatMessage = (template, values = {}) => String(template).replace(/\{(\w+)\}/g, (_, key) => values[key] ?? ''),
  describeError = (error) => String(error?.message || error),
} = {}) {
  return {
    invalid: () => translate('お部屋名を入力してください。'),
    created: (roomName) => formatMessage('お部屋：{roomName} が作成されました。', { roomName }),
    existingRoom: () => translate('すでに自分のお部屋を作成済みです（自分の部屋は1人1部屋）。'),
    nameConflict: () => translate('同じ部屋名は作成できません。別の部屋名にしてください。'),
    error: (error) => formatMessage('お部屋作成失敗: {message}', { message: describeError(error) }),
  };
}

export function createFolderCreationUi({
  translate = (value) => value,
  formatMessage = (template, values = {}) => String(template).replace(/\{(\w+)\}/g, (_, key) => values[key] ?? ''),
} = {}) {
  return {
    invalid: () => translate('コンテナ番号を入力してください。'),
    planLimit: (body = {}) => body.message || translate('フリープランではコンテナは2つまでです。有料プランで無制限になります。'),
    created: (folder) => formatMessage('コンテナ：{title} を登録しました。', { title: folder.title }),
  };
}

export function createManagementUi({ translate = (value) => value } = {}) {
  return {
    confirmRoomDelete: () => translate('このお部屋を削除すると、コンテナ/写真/コメント/課金情報が全て削除され、Stripeの定期課金も即時停止されます。よかですか？'),
    confirmRoomDeleteFinal: () => translate('本当によかですか？（取り消せません）'),
    roomDeleted: () => translate('お部屋を削除しました。'),
    leaveAdminBlocked: () => translate('管理者は脱退できません。お部屋管理から「お部屋を削除（全データ）」を実行してください。'),
    leaveWarning: () => translate('メンバーをやめると、このお部屋には招待URLなしでは再参加できません。'),
    confirmLeave: () => translate('本当にメンバーをやめますか？'),
    confirmAccountDelete: () => translate('アカウントを削除すると、このユーザーでは今後ログインできません。よかですか？'),
    confirmAccountDeleteFinal: () => translate('本当によかですか？（アカウント削除後は取り消せません）'),
    accountOwnerConflict: () => translate('作成者は先に「お部屋を削除（全データ）」を実行してください。'),
    accountDeleted: () => translate('アカウントを削除しました。'),
  };
}

export function createFolderManagementUi({ translate = (value) => value } = {}) {
  return {
    confirmDelete: () => translate('このコンテナを削除すると、写真とコメントも消えます。よかですか？'),
    deleted: () => translate('コンテナを削除しました。'),
    passwordUpdated: () => translate('コンテナの鍵を更新しました。'),
    copyMissing: () => translate('コピーする招待URLがなかです（先に発行してください）'),
    copied: () => translate('招待URLをコピーしました。'),
    copyPrompt: () => translate('招待URL（コピーしてください）'),
    copyDenied: () => translate('ブラウザがコピー操作を許可しませんでした。URL欄からコピーしてください。'),
    missingInviteToken: () => translate('招待トークンが取得できませんでした。'),
    revokeMissing: () => translate('失効する招待URLがなかです（先に発行してください）'),
    confirmRevoke: () => translate('この招待URLを失効してよかですか？'),
    revoked: () => translate('招待URLを失効しました。'),
  };
}

export function createAppErrorUi({
  translate = (value) => value,
  formatMessage = (template, values = {}) => String(template).replace(/\{(\w+)\}/g, (_, key) => values[key] ?? ''),
  describeError = (error) => String(error?.message || error),
} = {}) {
  const formatError = (template, error) => formatMessage(template, { message: describeError(error) });
  return {
    folderNetwork: () => translate('コンテナ取得失敗: ネットワーク/CORSエラーの可能性があります'),
    folder: (error) => formatError('コンテナ取得失敗: {message}', error),
    initialization: (error) => formatError('初期化失敗: {message}', error),
    unhandled: (error) => formatError('予期しないエラー: {message}', error),
    runtime: (error) => formatError('実行エラー: {message}', error),
  };
}

export function subscriptionPlanRank(plan) {
  const value = String(plan || '').trim().toUpperCase();
  if (value === 'BASIC') return 1;
  if (value === 'PLUS') return 2;
  if (value === 'PRO') return 3;
  return 0;
}

export function subscriptionPlanLimitBytes(plan) {
  const gib = 1024 * 1024 * 1024;
  const value = String(plan || '').trim().toUpperCase();
  if (value === 'BASIC') return gib;
  if (value === 'PLUS') return 5 * gib;
  if (value === 'PRO') return 10 * gib;
  return 512 * 1024 * 1024;
}
