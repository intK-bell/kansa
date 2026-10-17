import assert from 'node:assert/strict';
import test from 'node:test';
import {
  appendFolderAdminActions,
  appendPhotoCardComments,
  appendQuestPhotoArea,
  DEFAULT_LOG_TAG,
  LOG_TAGS,
  asMessage,
  bindGlobalAppEvents,
  bindManagementControlEvents,
  bindAppControlEvents,
  bindAuthControlEvents,
  bindBillingControlEvents,
  bindExportControlEvents,
  bindInviteControlEvents,
  bindModalDismissEvents,
  bindMutationControlEvents,
  bindPhotoCardEditing,
  bindPhotoCommentsAccordionLifecycle,
  bindUploadControlEvents,
  collectAppElements,
  computeStorageStats,
  createAdminPanelUi,
  createAppErrorUi,
  createBillingStatusUi,
  createFolderAdminOverview,
  createFolderCreationUi,
  createFolderManagementUi,
  createFreePlanUi,
  createLogTagUi,
  createManagementUi,
  createPhotoCardShell,
  createPhotoCommentRow,
  createPhotoCommentsAccordion,
  createPhotoPreviewImage,
  createQuestCardHeader,
  createQuestCommentsSection,
  createRoomCreationUi,
  createSubscriptionPlanUi,
  createUploadDraftRow,
  downloadFileNameFromResponse,
  formatBytes,
  normalizeCognitoDomain,
  normalizeFolderMode,
  normalizeLogTag,
  parseApiErrorBody,
  parseJwt,
  planToProductLabel,
  questReadKey,
  questStatusText,
  renderBillingBarInto,
  renderLogTagSummaryInto,
  renderMyRoomsInto,
  renderPhotoArchiveNoteInto,
  renderRentalComparisonInto,
  renderRoomSelectInto,
  renderCurrentRoomHeaderInto,
  renderFolderModePanels,
  renderFolderMembersInto,
  renderFolderSelectInto,
  renderSearchResultsInto,
  renderStorageGraphInto,
  renderTeamMembersInto,
  renderTopStorageGraphInto,
  renderUploadDraftContainerInto,
  syncSearchControlsInto,
  syncSubscriptionPlanButtonsInto,
  syncUploadDraftsFromRows,
  logTagMeta,
  subscriptionPlanLimitBytes,
  subscriptionPlanRank,
  validateUploadDraftItems,
  sortQuests,
} from './app-core.js';

test('normalizes Cognito domains', () => {
  assert.equal(normalizeCognitoDomain('https://example.auth.ap-northeast-1.amazoncognito.com/path'), 'example');
  assert.equal(normalizeCognitoDomain(' example '), 'example');
  assert.equal(normalizeCognitoDomain(''), '');
});

test('parses JWT payloads without accepting malformed values', () => {
  const payload = Buffer.from(JSON.stringify({ sub: 'user-1' })).toString('base64url');
  assert.deepEqual(parseJwt(`header.${payload}.signature`), { sub: 'user-1' });
  assert.equal(parseJwt('invalid'), null);
});

test('normalizes folder mode', () => {
  assert.equal(normalizeFolderMode(' QUEST '), 'quest');
  assert.equal(normalizeFolderMode('unknown'), 'photo');
});

test('creates stable quest read keys', () => {
  assert.equal(questReadKey('q-12'), 'quest:q-12');
});

test('sorts quests and creates shared quest card headers', () => {
  const quests = [
    { questId: 'done', status: 'done', createdAt: '2026-01-03' },
    { questId: 'open', status: 'open', createdAt: '2026-01-01' },
    { questId: 'shooting', status: 'shooting', createdAt: '2026-01-02' },
  ];
  assert.deepEqual(sortQuests(quests).map((quest) => quest.questId), ['open', 'shooting', 'done']);
  assert.deepEqual(sortQuests(quests, 'newest').map((quest) => quest.questId), ['done', 'shooting', 'open']);
  assert.equal(questStatusText('shooting'), '撮影中');

  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    let completed = false;
    const card = createQuestCardHeader({ questId: 'q1', questCode: 'Q-001', status: 'open', text: 'Take photo' }, {
      isAdmin: true, onComplete: () => { completed = true; },
    });
    assert.equal(card.children[0].children[0].children[0].textContent, 'Q-001');
    card.children[0].children[1].children[0].onclick();
    assert.equal(completed, true);
  } finally {
    globalThis.document = previousDocument;
  }
});

test('creates shared quest comment lists and add controls', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    let deleted = null;
    let added = null;
    const comment = { commentId: 'c1', text: 'Check seal', createdAt: '2026-08-11', createdByName: 'Aoki' };
    const section = createQuestCommentsSection({ comments: [comment] }, {
      formatDateTime: () => '11:00',
      canDelete: () => true,
      onDelete: (item) => { deleted = item.commentId; },
      onAdd: (text) => { added = text; },
    });
    assert.equal(section.children[0].children[0].textContent, '11:00 Aoki');
    section.children[0].children[2].children[0].onclick();
    assert.equal(deleted, 'c1');
    const addRow = section.children[1];
    addRow.children[0].value = ' New comment ';
    addRow.children[1].onclick();
    assert.equal(added, 'New comment');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('appends shared quest photo strips and upload controls', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, listeners: {},
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      addEventListener(type, handler) { this.listeners[type] = handler; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const card = { children: [], appendChild(child) { this.children.push(child); } };
    const photo = { photoId: 'p1', fileName: 'seal.jpg', viewUrl: 'view', logTag: 'seal' };
    let deleted = null;
    let uploaded = null;
    const result = appendQuestPhotoArea(card, { questId: 'q1', photos: [photo] }, {
      createTagBadge: () => ({ tag: 'badge' }),
      canDelete: () => true,
      onDelete: (item) => { deleted = item.photoId; },
      onFiles: (files, quest) => { uploaded = [files[0].name, quest.questId]; },
    });
    assert.equal(card.children.length, 3);
    assert.equal(result.photoWrap.children[0].children[0].attributes.src, 'view');
    result.photoWrap.children[0].children[2].onclick();
    assert.equal(deleted, 'p1');
    result.fileInput.listeners.change({ target: { files: [{ name: 'new.jpg' }] } });
    assert.deepEqual(uploaded, ['new.jpg', 'q1']);
  } finally {
    globalThis.document = previousDocument;
  }
});

test('renders shared team member rows and permissions', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const target = { children: [], innerHTML: 'old', appendChild(child) { this.children.push(child); } };
    let scopeChange = null;
    let removed = null;
    renderTeamMembersInto(target, [
      { userKey: 'owner', displayName: 'Owner', role: 'admin', status: 'active', folderScope: 'all' },
      { userKey: 'member', displayName: 'Member', role: 'member', status: 'active', folderScope: 'own' },
    ], {
      ownerUserKey: 'owner',
      onScopeChange: (member, next) => { scopeChange = [member.userKey, next]; },
      onRemove: (member) => { removed = member.userKey; },
    });
    assert.equal(target.innerHTML, '');
    assert.equal(target.children.length, 2);
    const memberActions = target.children[1].children[1];
    memberActions.children[0].value = 'all';
    memberActions.children[0].onchange();
    memberActions.children[1].onclick();
    assert.deepEqual(scopeChange, ['member', 'all']);
    assert.equal(removed, 'member');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('creates shared folder admin picker and overview', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    let selected = null;
    const result = createFolderAdminOverview([{
      folderId: 'f1', folderCode: 'F001', title: 'Container', mode: 'quest', hasPassword: true,
      createdByName: 'Owner', usageBytes: 1024,
    }], {
      selectedFolderId: 'f1',
      onSelect: (folderId) => { selected = folderId; },
    });
    assert.equal(result.folder.folderId, 'f1');
    assert.match(result.folderSelect.children[1].textContent, /F001 Container \[クエスト\] \[鍵\]/);
    assert.match(result.wrap.children[0].children[0].textContent, /Owner.*容量:0MB/);
    result.folderSelect.value = '';
    result.folderSelect.onchange();
    assert.equal(selected, '');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('appends shared folder admin action rows', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const wrap = { children: [], appendChild(child) { this.children.push(child); } };
    const calls = [];
    const controls = appendFolderAdminActions(wrap, {
      onCreateInvite: (input, revoke) => calls.push(['create', input, revoke]),
      onSetPassword: (value) => calls.push(['password', value]),
      onDelete: () => calls.push(['delete']),
    });
    assert.equal(wrap.children.length, 3);
    wrap.children[0].children[0].onclick();
    assert.equal(calls[0][0], 'create');
    assert.equal(calls[0][1], controls.inviteInput);
    assert.equal(calls[0][2], controls.revokeButton);
    controls.passwordInput.value = ' secret ';
    wrap.children[1].children[1].onclick();
    wrap.children[2].children[0].onclick();
    assert.deepEqual(calls.slice(1), [['password', 'secret'], ['delete']]);
  } finally {
    globalThis.document = previousDocument;
  }
});

test('renders shared folder member rows and removal controls', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const target = { children: [], innerHTML: 'loading', appendChild(child) { this.children.push(child); } };
    let removed = null;
    renderFolderMembersInto(target, [{
      userKey: 'member', displayName: 'Member', accessReason: 'invited', folderScope: 'invited', status: 'active',
    }], { onRemove: (member) => { removed = member.userKey; } });
    assert.equal(target.innerHTML, '');
    assert.equal(target.children[0].textContent, 'メンバー');
    assert.match(target.children[1].children[0].textContent, /Member（コンテナ招待 \/ active）/);
    target.children[1].children[1].children[0].onclick();
    assert.equal(removed, 'member');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('binds shared photo editing and appends comment status', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const classes = new Set(['hidden']);
    const editWrap = {
      children: [], innerHTML: '', classList: {
        contains: (name) => classes.has(name), add: (name) => classes.add(name), remove: (name) => classes.delete(name),
      },
      appendChild(child) { this.children.push(child); },
    };
    const editButton = {};
    const deleteButton = {};
    const card = {
      children: [], appendChild(child) { this.children.push(child); },
      querySelector: (selector) => selector === '.js-edit-photo' ? editButton : deleteButton,
    };
    let saved = null;
    let deleted = null;
    bindPhotoCardEditing({
      card, editWrap, photo: { photoId: 'p1', logTag: 'seal' },
      createTagSelect: () => ({ value: 'damage' }),
      onSave: (_photo, tag) => { saved = tag; },
      onDelete: (photo) => { deleted = photo.photoId; },
    });
    editButton.onclick();
    editWrap.children[1].onclick();
    deleteButton.onclick();
    assert.equal(saved, 'damage');
    assert.equal(deleted, 'p1');
    appendPhotoCardComments(card, { tag: 'details' }, true);
    assert.equal(card.children.at(-1).textContent, '未読コメントがあります');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('creates keyboard-accessible shared photo preview images', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, attributes: {}, dataset: {}, style: { setProperty() {} },
      setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    let previewCount = 0;
    const image = createPhotoPreviewImage({ photoId: 'p1', fileName: 'door.jpg', viewUrl: 'view' }, {
      className: 'photo-card-image', onPreview: () => { previewCount += 1; },
    });
    assert.equal(image.attributes.src, 'view');
    assert.equal(image.attributes.role, 'button');
    image.onclick();
    image.onkeydown({ key: 'Enter', preventDefault() {} });
    assert.equal(previewCount, 2);
  } finally {
    globalThis.document = previousDocument;
  }
});

test('creates editable shared photo comment rows', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '',
      appendChild(child) { this.children.push(child); child.parent = this; },
      setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
      querySelector(selector) { return this.children.find((child) => `.${child.attributes?.class || ''}`.includes(selector)) || null; },
      remove() { if (this.parent) this.parent.children = this.parent.children.filter((child) => child !== this); },
    }),
  };
  try {
    let edited = '';
    let deleted = false;
    const row = createPhotoCommentRow({ commentId: 'c1', text: 'before', createdAt: 'now', createdByName: 'User' }, {
      editable: true, onEdit: (_comment, text) => { edited = text; }, onDelete: () => { deleted = true; },
    });
    const actions = row.children[2];
    actions.children[0].onclick();
    const editor = row.children[3];
    editor.children[0].value = 'after';
    editor.children[1].onclick();
    actions.children[1].onclick();
    assert.equal(edited, 'after');
    assert.equal(deleted, true);
  } finally {
    globalThis.document = previousDocument;
  }
});

test('creates shared photo comment accordions', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const result = createPhotoCommentsAccordion({ unread: true });
    assert.equal(result.accordion.tag, 'details');
    assert.equal(result.summary.children[2].textContent, '未読');
    assert.equal(result.commentWrap.children[0].textContent, '開いたら読み込みます');
    assert.equal(result.textArea.attributes.placeholder, 'コメント');
    assert.equal(result.addButton.textContent, '追加');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('creates upload draft rows and synchronizes inputs', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], listeners: {}, attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '',
      classList: { add() {} }, appendChild(child) { this.children.push(child); },
      addEventListener(type, handler) { this.listeners[type] = handler; },
      setAttribute(key, value) { this.attributes[key] = value; }, set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const draft = { localId: 'd1', originalName: 'door.jpg', previewUrl: 'preview', logTag: 'damage', initialComment: '', file: { size: 1024 } };
    const tagSelect = globalThis.document.createElement('select');
    let removed = false;
    const row = createUploadDraftRow(draft, 0, {
      createTagSelect: () => tagSelect, onRemove: () => { removed = true; },
    });
    row.children[0].children[1].children[1].listeners.click();
    assert.equal(removed, true);
    tagSelect.listeners.change({ target: { value: 'inbound' } });
    assert.equal(draft.logTag, 'inbound');
    const commentInput = row.children[2].children[1].children[1];
    commentInput.listeners.input({ target: { value: 'memo' } });
    assert.equal(draft.initialComment, 'memo');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('synchronizes, validates, and renders upload draft containers', () => {
  const draft = { localId: 'd1', logTag: 'damage', initialComment: '' };
  const row = {
    getAttribute: () => 'd1',
    querySelector: (selector) => selector.includes('log-tag') ? { value: 'inbound' } : { value: 'memo' },
  };
  syncUploadDraftsFromRows({ querySelectorAll: () => [row] }, [draft]);
  assert.equal(draft.logTag, 'inbound');
  assert.equal(draft.initialComment, 'memo');
  assert.deepEqual(validateUploadDraftItems([{ logTag: 'invalid', initialComment: 'x'.repeat(51) }]), [
    '1行目: タグを選択してください。', '1行目: 初回コメントは50文字以内にしてください。',
  ]);

  const classList = { toggles: [], toggle(name, force) { this.toggles.push([name, force]); } };
  const list = { innerHTML: 'old', children: [], appendChild(child) { this.children.push(child); } };
  const status = { textContent: '' };
  renderUploadDraftContainerInto({
    uploadMetaCard: { classList }, uploadMetaList: list, uploadMetaStatus: status,
    applyCommentBulkBtn: { classList: { toggle() {} } },
  }, [draft], { createRow: () => ({ id: 'row' }) });
  assert.equal(status.textContent, '1件の写真をアップロード対象に追加しています。');
  assert.equal(list.children.length, 1);
});

test('loads and marks photo comments through shared accordion lifecycle', async () => {
  let toggleHandler;
  const accordion = { open: false, addEventListener: (_type, handler) => { toggleHandler = handler; } };
  const badge = { removed: false, remove() { this.removed = true; } };
  const summary = { querySelector: () => badge };
  const commentWrap = { innerHTML: '', children: [], appendChild(child) { this.children.push(child); } };
  const commentLabel = { textContent: '' };
  const events = [];
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: () => ({ attributes: {}, dataset: {}, style: { setProperty() {} }, setAttribute() {}, set className(value) { this.attributes.class = value; } }),
  };
  try {
    bindPhotoCommentsAccordionLifecycle({
      accordion, summary, commentWrap, commentLabel, photoId: 'p1',
      loadComments: async () => [{ createdAt: 'latest' }],
      getLatestIncoming: () => 'latest',
      renderComments: (comments) => events.push(['render', comments.length]),
      onOpenChange: (open) => events.push(['open', open]),
      onRead: (latest) => events.push(['read', latest]),
      onAfterToggle: () => events.push(['after']),
    });
    accordion.open = true;
    await toggleHandler();
    assert.equal(commentLabel.textContent, 'コメント (1)');
    assert.equal(badge.removed, true);
    assert.deepEqual(events, [['open', true], ['render', 1], ['read', 'latest'], ['after']]);
  } finally {
    globalThis.document = previousDocument;
  }
});

test('creates shared photo card shells with edit actions', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '',
      appendChild(child) { this.children.push(child); }, setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const { card, editWrap } = createPhotoCardShell({ photoId: 'p1', photoCode: 'P-001', fileName: 'door.jpg', createdByName: 'User' }, {
      canEdit: true, createTagBadge: () => globalThis.document.createElement('span'),
    });
    assert.equal(card.children[0].children[0].textContent, 'P-001');
    assert.equal(card.children[2].textContent, '投稿: User');
    assert.equal(card.children[3].children.length, 2);
    assert.equal(editWrap.attributes.class, 'inline-edit js-photo-edit-wrap hidden');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('normalizes log tags against the shared catalog', () => {
  assert.equal(DEFAULT_LOG_TAG, 'container_number');
  assert.equal(LOG_TAGS.length, 6);
  assert.equal(normalizeLogTag('damage'), 'damage');
  assert.equal(normalizeLogTag('invalid'), DEFAULT_LOG_TAG);
  assert.equal(logTagMeta('invalid').value, 'other');
});

test('renders translated log tag controls and summaries', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { values: {}, setProperty(key, value) { this.values[key] = value; } },
      appendChild(child) { this.children.push(child); },
      setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
      get className() { return this.attributes.class || ''; },
      textContent: '', value: '', innerHTML: '',
    }),
  };
  try {
    const translate = (label) => `訳:${label}`;
    const { createLogTagBadge, createLogTagSelect } = createLogTagUi(translate);
    const badge = createLogTagBadge('damage', ' 2');
    assert.equal(badge.textContent, '訳:損傷 2');
    assert.equal(badge.style.values['--tag-color'], '#E53935');

    const select = createLogTagSelect('outbound');
    assert.equal(select.children.length, LOG_TAGS.length);
    assert.equal(select.children[0].textContent, '訳:コンテナ番号');
    assert.equal(select.value, 'outbound');

    const target = globalThis.document.createElement('div');
    renderLogTagSummaryInto(target, [{ logTag: 'damage' }, { logTag: 'invalid' }], translate);
    assert.equal(target.children.length, LOG_TAGS.length);
    assert.equal(target.children.find((node) => node.textContent.startsWith('訳:損傷')).textContent, '訳:損傷 1');
    assert.equal(target.children.find((node) => node.textContent.startsWith('訳:その他')).textContent, '訳:その他 1');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('collects shared DOM references from element IDs', () => {
  const nodes = [
    { id: 'current-room-select' },
    { id: 'photo-list' },
    { id: 'developer-modal' },
  ];
  const controls = { className: 'app-header-controls' };
  const root = {
    querySelectorAll: (selector) => selector === '[id]' ? nodes : [],
    querySelector: (selector) => selector === '.app-header-controls' ? controls : null,
  };

  assert.deepEqual(collectAppElements(root), {
    currentRoomSelect: nodes[0], photoList: nodes[1], developerModal: nodes[2], appHeaderControls: controls,
  });
});

test('binds shared global, menu, and accordion events', () => {
  const windowListeners = {};
  const documentListeners = {};
  const groupListeners = [];
  const groups = [{ open: true }, { open: true }];
  groups.forEach((group) => {
    group.addEventListener = (type, handler) => groupListeners.push({ group, type, handler });
  });
  const menuPanel = {
    classList: { toggled: [], added: [], toggle(value) { this.toggled.push(value); }, add(value) { this.added.push(value); } },
    contains: () => false,
  };
  const menuBtn = {};
  const onResize = () => undefined;
  bindGlobalAppEvents({
    windowRef: { addEventListener: (type, handler) => { windowListeners[type] = handler; } },
    documentRef: {
      addEventListener: (type, handler) => { documentListeners[type] = handler; },
      querySelectorAll: () => groups,
    },
    elements: { menuBtn, menuPanel },
    onUnhandledRejection: () => undefined,
    onError: () => undefined,
    onResize,
  });

  assert.deepEqual(Object.keys(windowListeners), ['unhandledrejection', 'error', 'resize']);
  assert.equal(windowListeners.resize, onResize);
  let stopped = false;
  menuBtn.onclick({ stopPropagation: () => { stopped = true; } });
  assert.equal(stopped, true);
  assert.deepEqual(menuPanel.classList.toggled, ['hidden']);
  documentListeners.click({ target: {} });
  assert.deepEqual(menuPanel.classList.added, ['hidden']);
  groupListeners[0].handler();
  assert.equal(groups[1].open, false);
});

test('binds shared app control events by element key', () => {
  const events = [];
  const makeElement = (key) => ({ addEventListener: (type, handler) => events.push({ key, type, handler }) });
  const elements = {
    currentFolderSelect: makeElement('currentFolderSelect'),
    recordTabBtn: makeElement('recordTabBtn'),
    photoSearchKeyword: makeElement('photoSearchKeyword'),
  };
  const handlers = {
    onFolderChange: () => undefined,
    onRecordTab: () => undefined,
    onSearchKeywordKeydown: () => undefined,
  };
  bindAppControlEvents(elements, handlers);
  assert.deepEqual(events.map(({ key, type }) => [key, type]), [
    ['currentFolderSelect', 'change'], ['recordTabBtn', 'click'], ['photoSearchKeyword', 'keydown'],
  ]);
  assert.equal(events[0].handler, handlers.onFolderChange);
});

test('renders room lists and selects with shared behavior', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '', disabled: false,
      appendChild(child) { this.children.push(child); },
      setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const rooms = [
      { roomId: 'r1', roomName: 'Alpha', role: 'admin', memberStatus: 'active' },
      { roomId: 'r2', roomName: 'Beta', role: 'member', memberStatus: 'disabled' },
      { roomId: 'r3', roomName: 'Gone', role: 'member', memberStatus: 'left' },
    ];
    const list = globalThis.document.createElement('div');
    let switched = null;
    renderMyRoomsInto(list, rooms, 'r1', { onSwitch: (room) => { switched = room.roomId; } });
    assert.equal(list.children.length, 2);
    assert.equal(list.children[0].children[1].disabled, true);
    list.children[1].children[1].onclick();
    assert.equal(switched, 'r2');

    const select = globalThis.document.createElement('select');
    renderRoomSelectInto(select, rooms.slice(0, 2), { roomId: 'r1' });
    assert.equal(select.children.length, 2);
    assert.equal(select.children[1].disabled, true);
    assert.equal(select.value, 'r1');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('renders folder selects and search result cards', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '', value: '', disabled: false,
      appendChild(child) { this.children.push(child); },
      setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const select = globalThis.document.createElement('select');
    const folders = [{ folderId: 'f1', title: 'Box', mode: 'quest', hasPassword: true }];
    assert.equal(renderFolderSelectInto(select, folders, { unreadById: { f1: true }, selectedFolderId: 'f1' }), true);
    assert.equal(select.value, 'f1');
    assert.equal(select.children[1].textContent, 'Box [クエスト] [鍵] ●新着');

    const target = globalThis.document.createElement('div');
    let previewed = null;
    renderSearchResultsInto(target, [{ photoId: 'p1', photoCode: 'P-001', fileName: 'door.jpg', logTag: 'damage', createdByName: 'User' }], {
      createTagBadge: () => globalThis.document.createElement('span'),
      onPreview: (photo) => { previewed = photo.photoId; },
    });
    assert.equal(target.children.length, 1);
    target.children[0].children[1].onclick();
    assert.equal(previewed, 'p1');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('binds modal close buttons and backdrop dismissal', () => {
  const listeners = {};
  const closeButton = { addEventListener: (type, handler) => { listeners.button = { type, handler }; } };
  const modal = { addEventListener: (type, handler) => { listeners.modal = { type, handler }; } };
  let closeCount = 0;
  bindModalDismissEvents({ modal, closeButton }, [
    { modalKey: 'modal', closeKey: 'closeButton', close: () => { closeCount += 1; } },
  ]);
  listeners.button.handler();
  listeners.modal.handler({ target: {} });
  listeners.modal.handler({ target: modal });
  assert.equal(closeCount, 2);
});

test('binds export controls through the shared registrar', () => {
  const events = [];
  const elements = Object.fromEntries(['exportDownloadBtn', 'exportPdfBtn'].map((key) => [key, {
    addEventListener: (type, handler) => events.push({ key, type, handler }),
  }]));
  const handlers = { onDownload: () => undefined, onPdf: () => undefined };
  bindExportControlEvents(elements, handlers);
  assert.deepEqual(events.map(({ key, type }) => [key, type]), [
    ['exportDownloadBtn', 'click'], ['exportPdfBtn', 'click'],
  ]);
});

test('binds auth controls through the shared registrar', () => {
  const elements = { loginBtn: {}, logoutBtn: {} };
  const onLogin = () => undefined;
  const onLogout = () => undefined;
  bindAuthControlEvents(elements, { onLogin, onLogout });
  assert.equal(elements.loginBtn.onclick, onLogin);
  assert.equal(elements.logoutBtn.onclick, onLogout);

  const demoLogout = () => undefined;
  bindAuthControlEvents(elements, { onLogout: demoLogout });
  assert.equal(elements.logoutBtn.onclick, demoLogout);
});

test('binds invite controls through the shared registrar', () => {
  const events = [];
  const elements = Object.fromEntries(['copyInviteUrlBtn', 'revokeInviteBtn'].map((key) => [key, {
    addEventListener: (type, handler) => events.push({ key, type, handler }),
  }]));
  bindInviteControlEvents(elements, { onCopyInviteUrl: () => undefined, onRevokeInvite: () => undefined });
  assert.deepEqual(events.map(({ key, type }) => [key, type]), [
    ['copyInviteUrlBtn', 'click'], ['revokeInviteBtn', 'click'],
  ]);
});

test('binds billing controls through the shared registrar', () => {
  const events = [];
  const elements = Object.fromEntries(['subscribeBasicBtn', 'lowStorageChargeBtn'].map((key) => [key, {
    addEventListener: (type, handler) => events.push({ key, type, handler }),
  }]));
  bindBillingControlEvents(elements, { onBasic: () => undefined, onLowStorageCharge: () => undefined });
  assert.deepEqual(events.map(({ key, type }) => [key, type]), [
    ['subscribeBasicBtn', 'click'], ['lowStorageChargeBtn', 'click'],
  ]);
});

test('renders archive notes and synchronizes search controls', () => {
  const note = { textContent: '' };
  renderPhotoArchiveNoteInto(note, { archivedCount: 2, archiveDays: 45, archiveMode: 'hidden' });
  assert.match(note.textContent, /2件.*45日/);
  renderPhotoArchiveNoteInto(note, null);
  assert.equal(note.textContent, '');

  const makeToggle = () => ({ values: [], toggle(name, force) { this.values.push([name, force]); } });
  const elements = {
    searchScopeFolderBtn: { classList: makeToggle() },
    searchScopeRoomBtn: { classList: makeToggle() },
    logTagFilter: { options: [{}], value: '' },
    photoSearchKeyword: { value: '' },
  };
  syncSearchControlsInto(elements, { scope: 'room', tag: 'damage', keyword: 'door' });
  assert.deepEqual(elements.searchScopeRoomBtn.classList.values.at(-1), ['is-active', true]);
  assert.equal(elements.logTagFilter.value, 'damage');
  assert.equal(elements.photoSearchKeyword.value, 'door');
});

test('binds management controls through the shared registrar', () => {
  const events = [];
  const elements = Object.fromEntries(['refreshMyRoomsBtn', 'helpMenuBtn'].map((key) => [key, {
    addEventListener: (type, handler) => events.push({ key, type, handler }),
  }]));
  bindManagementControlEvents(elements, { onRefreshRooms: () => undefined, onOpenHelpMenu: () => undefined });
  assert.deepEqual(events.map(({ key, type }) => [key, type]), [
    ['refreshMyRoomsBtn', 'click'], ['helpMenuBtn', 'click'],
  ]);
});

test('binds mutation controls through the shared registrar', () => {
  const events = [];
  const elements = { createQuestBtn: { addEventListener: (type, handler) => events.push({ type, handler }) } };
  const handler = () => undefined;
  bindMutationControlEvents(elements, { onCreateQuest: handler });
  assert.equal(events[0].type, 'click');
  assert.equal(events[0].handler, handler);
});

test('binds upload controls through the shared registrar', () => {
  const events = [];
  const elements = Object.fromEntries(['photoFiles', 'applyCommentBulkBtn'].map((key) => [key, {
    addEventListener: (type, handler) => events.push({ key, type, handler }),
  }]));
  bindUploadControlEvents(elements, { onFilesChange: () => undefined, onApplyBulkComment: () => undefined });
  assert.deepEqual(events.map(({ key, type }) => [key, type]), [['photoFiles', 'change'], ['applyCommentBulkBtn', 'click']]);
});

test('renders rental before and after comparison', () => {
  const previousDocument = globalThis.document;
  globalThis.document = {
    createElement: (tag) => ({
      tag, children: [], attributes: {}, dataset: {}, style: { setProperty() {} }, textContent: '',
      appendChild(child) { this.children.push(child); },
      setAttribute(key, value) { this.attributes[key] = value; },
      set className(value) { this.attributes.class = value; },
    }),
  };
  try {
    const container = { classList: { toggle() {} } };
    const grid = globalThis.document.createElement('div');
    let previewed = null;
    renderRentalComparisonInto(container, grid, [{ photoId: 'p1', photoCode: 'P1', logTag: 'inbound', viewUrl: 'x' }], {
      enabled: true,
      createTagBadge: () => globalThis.document.createElement('span'),
      onPreview: (photo) => { previewed = photo.photoId; },
    });
    assert.equal(grid.children.length, 2);
    grid.children[0].children[1].children[0].onclick();
    assert.equal(previewed, 'p1');
    assert.equal(grid.children[1].children[1].textContent, '搬出の写真を登録すると、ここに表示されます。');
  } finally {
    globalThis.document = previousDocument;
  }
});

test('extracts download names from content-disposition', () => {
  const response = { headers: { get: () => "attachment; filename*=UTF-8''report%20ja.pdf" } };
  assert.equal(downloadFileNameFromResponse(response), 'report ja.pdf');
  assert.equal(downloadFileNameFromResponse(null, 'fallback.pdf'), 'fallback.pdf');
});

test('formats binary storage units', () => {
  assert.equal(formatBytes(512 * 1024), '1MB');
  assert.equal(formatBytes(1024 * 1024 * 1024), '1.00GB');
});

test('renders shared room, folder mode, and storage views', () => {
  const classList = () => ({ values: [], toggle(name, force) { this.values.push([name, force]); }, add(name) { this.values.push([name, true]); }, remove(name) { this.values.push([name, false]); } });
  const roomName = { textContent: '' };
  renderCurrentRoomHeaderInto(roomName, '', 'None');
  assert.equal(roomName.textContent, 'None');

  const panels = Object.fromEntries(['photoModePanel', 'questModePanel', 'photoList', 'questList'].map((key) => [key, { classList: classList() }]));
  renderFolderModePanels(panels, 'quest');
  assert.deepEqual(panels.photoModePanel.classList.values.at(-1), ['hidden', true]);
  assert.deepEqual(panels.questModePanel.classList.values.at(-1), ['hidden', false]);

  const graph = { classList: classList() };
  const used = { style: {} };
  const remaining = { style: {} };
  const usedLabel = { textContent: '' };
  const remainLabel = { textContent: '' };
  const billing = { usageBytes: 25, freeBytes: 100, billingMode: 'prepaid' };
  assert.equal(computeStorageStats(billing).remainRatio, 75);
  renderStorageGraphInto({ graph, used, remaining, usedLabel, remainLabel }, billing, (size) => `${size}B`);
  assert.equal(used.style.width, '25%');
  assert.equal(remaining.style.width, '75%');
  assert.equal(usedLabel.textContent, '使用量 25B');
  assert.equal(remainLabel.textContent, '残り 75B');
});

test('renders shared top storage graph and billing bar', () => {
  const makeClassList = () => ({ values: [], add(name) { this.values.push(['add', name]); }, remove(name) { this.values.push(['remove', name]); } });
  const graphElements = {
    graph: { classList: makeClassList() }, used: { style: {} }, remaining: { style: {} },
    usedText: {}, remainingText: {}, extraText: {}, submeta: { classList: makeClassList() },
  };
  const billing = { usageBytes: 25, freeBytes: 100, subscription: { currentPlan: 'FREE' } };
  renderTopStorageGraphInto(graphElements, billing, { formatSize: (value) => `${value}B`, extraLabel: '2 containers' });
  assert.equal(graphElements.used.style.width, '25%');
  assert.equal(graphElements.usedText.textContent, '使用量 25B');
  assert.equal(graphElements.extraText.textContent, '2 containers');

  const bar = { textContent: '', classList: makeClassList() };
  renderBillingBarInto(bar, {
    billing, ownerUserKey: 'owner', userKey: 'owner', isAdmin: true, planLabel: () => 'Free',
  });
  assert.equal(bar.textContent, 'プラン:Free / 作成者 / 無料枠で利用中 / 管理者');
});

test('synchronizes shared subscription plan buttons', () => {
  const button = () => ({ textContent: '', disabled: false, title: '', attributes: {}, setAttribute(key, value) { this.attributes[key] = value; } });
  const elements = {
    subscribeFreeBtn: button(), subscribeBasicBtn: button(), subscribePlusBtn: button(), subscribeProBtn: button(),
  };
  syncSubscriptionPlanButtonsInto(elements, {
    billingMode: 'subscription', usageBytes: 2 * 1024 * 1024 * 1024,
    subscription: { currentPlan: 'PLUS' },
  });
  assert.equal(elements.subscribePlusBtn.textContent, '5GBプラン (¥1,980/月)（現在のプラン）');
  assert.equal(elements.subscribePlusBtn.disabled, true);
  assert.equal(elements.subscribeBasicBtn.disabled, true);
  assert.match(elements.subscribeBasicBtn.title, /上限を超えている/);
  assert.equal(elements.subscribeProBtn.disabled, false);
  assert.equal(elements.subscribePlusBtn.attributes['aria-pressed'], 'true');
});

test('reads API errors and messages', () => {
  assert.equal(asMessage(new Error('failed')), 'failed');
  assert.deepEqual(parseApiErrorBody({ body: { code: 'X' } }), { code: 'X' });
  assert.deepEqual(parseApiErrorBody('APIエラー(400): {"code":"Y"}'), { code: 'Y' });
});

test('maps subscription plans', () => {
  assert.equal(planToProductLabel('basic'), '1GB');
  assert.equal(subscriptionPlanRank('PRO'), 3);
  assert.equal(subscriptionPlanLimitBytes('PLUS'), 5 * 1024 * 1024 * 1024);
  assert.equal(subscriptionPlanLimitBytes('FREE'), 512 * 1024 * 1024);
});

test('formats subscription plan UI labels and change messages', () => {
  const ui = createSubscriptionPlanUi();
  assert.equal(ui.displayLabel('basic'), '1GBプラン');
  assert.equal(ui.displayLabel('FREE'), '無料プラン');
  assert.equal(ui.confirmText('BASIC', 'PLUS', 'checkout'), '5GBプランを申し込みますか？');
  assert.equal(ui.confirmText('BASIC', 'PLUS', 'upgrade'), '1GBプランから5GBプランへ変更してよかですか？\n\n差額はStripeで即時請求されます。');
  assert.equal(ui.confirmText('PLUS', 'BASIC', 'downgrade'), '5GBプランから1GBプランへ変更してよかですか？\n\n今すぐ反映されます。');
  assert.equal(ui.successText('PLUS', 'upgrade'), '5GBプランへ変更しました。差額はStripeで即時請求されます。');
});

test('formats free plan guidance, requirements, confirmation, and success', () => {
  const ui = createFreePlanUi({ formatSize: (value) => `${value}B` });
  assert.match(ui.guideText(null), /コンテナ無制限/);
  assert.match(ui.guideText(2), /フリープラン/);
  const requirements = ui.requirementText({ unmet: ['usageBytes', 'folderCount'], usageBytes: 600, folderCount: 3 });
  assert.match(requirements, /現在の容量: 600B/);
  assert.match(requirements, /現在のコンテナ数: 3/);
  assert.match(ui.confirmText(), /定期課金は今すぐ停止/);
  assert.match(ui.successText(), /フリープランに戻りました/);
});

test('formats billing folder limits, usage, capacity, and plan status', () => {
  const ui = createBillingStatusUi({ formatSize: (value) => `${value}B`, planLabel: (plan) => `Plan ${plan}` });
  const free = { billingMode: 'prepaid', usageBytes: 100, freeBytes: 1000 };
  assert.equal(ui.folderLimit(free), 2);
  assert.equal(ui.folderUsage([{ folderId: 'f1' }], free), 'コンテナ 1 / 2');
  assert.equal(ui.statusText(free, [{ folderId: 'f1' }]), '使用量 100B / 無料 1000B（残り 900B） / コンテナ 1 / 2 / プラン Plan FREE');
  const paid = { billingMode: 'subscription', usageBytes: 500, freeBytes: 0, subscription: { currentPlan: 'PLUS', limitBytes: 5000 } };
  assert.equal(ui.folderLimit(paid), null);
  assert.equal(ui.folderUsage([], paid), 'コンテナ 0 / 無制限');
  assert.match(ui.statusText(paid, []), /プラン容量 5000B/);
});

test('formats admin panel confirmations, status, and errors', () => {
  const ui = createAdminPanelUi({
    formatSize: (value) => `${value}B`,
    describeError: (error) => `E:${error.message}`,
  });
  const member = { userKey: 'u1', displayName: '田中' };
  const folder = { folderId: 'f1', title: '資料', createdByName: '佐藤', usageBytes: 120 };
  assert.match(ui.confirmScopeChange(member), /田中/);
  assert.match(ui.confirmMemberRemove(member), /お部屋から削除/);
  assert.equal(ui.folderCount(3), '3件');
  assert.equal(ui.folderHeader(folder), ' 資料（作成:佐藤 / 容量:120B）');
  assert.match(ui.confirmInviteRevoke(folder), /資料/);
  assert.match(ui.confirmPassword(folder, 'secret'), /設定/);
  assert.match(ui.confirmPassword(folder, ''), /解除/);
  assert.match(ui.confirmFolderDelete(folder), /写真とコメントも消えます/);
  assert.match(ui.confirmFolderMemberRemove(member), /このコンテナから外して/);
  assert.equal(ui.memberLoadError(new Error('failed')), 'メンバー取得失敗: E:failed');
  assert.equal(ui.folderLoadError(new Error('failed')), 'コンテナ取得失敗: E:failed');
});

test('formats room creation validation, success, conflicts, and errors', () => {
  const ui = createRoomCreationUi({ describeError: (error) => `E:${error.message}` });
  assert.equal(ui.invalid(), 'お部屋名を入力してください。');
  assert.equal(ui.created('資料室'), 'お部屋：資料室 が作成されました。');
  assert.match(ui.existingRoom(), /1人1部屋/);
  assert.match(ui.nameConflict(), /同じ部屋名/);
  assert.equal(ui.error(new Error('failed')), 'お部屋作成失敗: E:failed');
});

test('formats folder creation validation, plan limits, and success', () => {
  const ui = createFolderCreationUi();
  assert.equal(ui.invalid(), 'コンテナ番号を入力してください。');
  assert.match(ui.planLimit(), /フリープラン/);
  assert.equal(ui.planLimit({ message: 'custom limit' }), 'custom limit');
  assert.equal(ui.created({ title: 'F-1' }), 'コンテナ：F-1 を登録しました。');
});

test('formats room, leave, and account management messages', () => {
  const ui = createManagementUi();
  assert.match(ui.confirmRoomDelete(), /Stripe/);
  assert.match(ui.confirmRoomDeleteFinal(), /取り消せません/);
  assert.equal(ui.roomDeleted(), 'お部屋を削除しました。');
  assert.match(ui.leaveAdminBlocked(), /管理者は脱退できません/);
  assert.match(ui.leaveWarning(), /招待URLなしでは再参加/);
  assert.equal(ui.confirmLeave(), '本当にメンバーをやめますか？');
  assert.match(ui.confirmAccountDelete(), /今後ログインできません/);
  assert.match(ui.confirmAccountDeleteFinal(), /アカウント削除後/);
  assert.match(ui.accountOwnerConflict(), /先に「お部屋を削除/);
  assert.equal(ui.accountDeleted(), 'アカウントを削除しました。');
});

test('formats folder management and invite messages', () => {
  const ui = createFolderManagementUi();
  assert.match(ui.confirmDelete(), /写真とコメントも消えます/);
  assert.equal(ui.deleted(), 'コンテナを削除しました。');
  assert.equal(ui.passwordUpdated(), 'コンテナの鍵を更新しました。');
  assert.match(ui.copyMissing(), /コピーする招待URL/);
  assert.equal(ui.copied(), '招待URLをコピーしました。');
  assert.match(ui.copyPrompt(), /コピーしてください/);
  assert.match(ui.copyDenied(), /許可しませんでした/);
  assert.equal(ui.missingInviteToken(), '招待トークンが取得できませんでした。');
  assert.match(ui.revokeMissing(), /失効する招待URL/);
  assert.equal(ui.confirmRevoke(), 'この招待URLを失効してよかですか？');
  assert.equal(ui.revoked(), '招待URLを失効しました。');
});

test('formats folder, initialization, and global errors', () => {
  const ui = createAppErrorUi({ describeError: (error) => `E:${error.message || error}` });
  assert.match(ui.folderNetwork(), /ネットワーク\/CORS/);
  assert.equal(ui.folder(new Error('folder')), 'コンテナ取得失敗: E:folder');
  assert.equal(ui.initialization(new Error('init')), '初期化失敗: E:init');
  assert.equal(ui.unhandled(new Error('promise')), '予期しないエラー: E:promise');
  assert.equal(ui.runtime('runtime'), '実行エラー: E:runtime');
});
