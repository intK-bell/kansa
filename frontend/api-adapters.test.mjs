import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createDemoApi, createDemoBackend, createDemoRequest } from './api-demo.js';
import { createCognitoClient, createLiveApi, createLiveRequest, resolveLiveEnvironment } from './api-live.js';

for (const [label, createAdapter] of [
  ['live', createLiveApi],
  ['demo', createDemoApi],
]) {
  test(`${label} account/room adapter maps semantic operations`, async () => {
    const calls = [];
    const api = createAdapter(async (path, options) => {
      calls.push({ path, options });
      return { ok: true };
    });

    await api.getCurrentUser();
    await api.saveDisplayName('Aoki');
    await api.listRooms();
    await api.switchRoom('room-1');
    await api.createRoom('Room One');

    assert.deepEqual(calls, [
      { path: '/me', options: { method: 'GET' } },
      { path: '/me/display-name', options: { method: 'PUT', body: '{"displayName":"Aoki"}' } },
      { path: '/rooms/mine', options: { method: 'GET' } },
      { path: '/rooms/switch', options: { method: 'POST', body: '{"roomId":"room-1"}' } },
      { path: '/rooms/create', options: { method: 'POST', body: '{"roomName":"Room One"}' } },
    ]);
  });

  test(`${label} folder adapter maps identifiers, passwords, and members`, async () => {
    const calls = [];
    const api = createAdapter(
      async (path, options) => {
        calls.push({ path, options });
        return { ok: true };
      },
      (folderId) => ({ 'X-Folder-Password': `pw-${folderId}` })
    );

    await api.listFolders();
    await api.createFolder({ title: 'TCLU1234567', mode: 'photo', folderPassword: '' });
    await api.deleteFolder('folder/1');
    await api.setFolderPassword('folder/1', 'new-password');
    await api.listFolderMembers('folder/1');
    await api.removeFolderMember('folder/1', 'user@example.com');

    assert.deepEqual(calls, [
      { path: '/folders', options: { method: 'GET' } },
      {
        path: '/folders',
        options: { method: 'POST', body: '{"title":"TCLU1234567","mode":"photo","folderPassword":null}' },
      },
      {
        path: '/folders/folder/1',
        options: { method: 'DELETE', headers: { 'X-Folder-Password': 'pw-folder/1' } },
      },
      {
        path: '/folders/folder/1/password',
        options: {
          method: 'PUT',
          headers: { 'X-Folder-Password': 'pw-folder/1' },
          body: '{"folderPassword":"new-password"}',
        },
      },
      { path: '/folders/folder%2F1/members', options: { method: 'GET' } },
      { path: '/folders/folder%2F1/members/user%40example.com', options: { method: 'DELETE' } },
    ]);
  });

  test(`${label} photo adapter maps records and comments`, async () => {
    const calls = [];
    const api = createAdapter(
      async (path, options) => {
        calls.push({ path, options });
        return { ok: true };
      },
      () => ({ 'X-Folder-Password': 'secret' })
    );

    await api.listPhotos('folder-1');
    await api.updatePhoto('photo-1', { logTag: 'damage' });
    await api.deletePhoto('photo-1');
    await api.listPhotoComments('photo-1');
    await api.createPhotoComment('photo-1', 'new');
    await api.updatePhotoComment('photo-1', 'comment-1', 'updated');
    await api.deletePhotoComment('photo-1', 'comment-1');

    assert.deepEqual(calls, [
      {
        path: '/folders/folder-1/photos',
        options: { method: 'GET', headers: { 'X-Folder-Password': 'secret' } },
      },
      { path: '/photos/photo-1', options: { method: 'PUT', body: '{"logTag":"damage"}' } },
      { path: '/photos/photo-1', options: { method: 'DELETE' } },
      { path: '/photos/photo-1/comments', options: { method: 'GET' } },
      { path: '/photos/photo-1/comments', options: { method: 'POST', body: '{"text":"new"}' } },
      {
        path: '/photos/photo-1/comments/comment-1',
        options: { method: 'PUT', body: '{"text":"updated"}' },
      },
      { path: '/photos/photo-1/comments/comment-1', options: { method: 'DELETE' } },
    ]);
  });

  test(`${label} quest adapter maps records and comments`, async () => {
    const calls = [];
    const api = createAdapter(
      async (path, options) => {
        calls.push({ path, options });
        return { ok: true };
      },
      () => ({ 'X-Folder-Password': 'secret' })
    );
    await api.listQuests('folder-1');
    await api.createQuest('folder-1', '撮影してください');
    await api.updateQuest('quest-1', { status: 'done' }, 'folder-1');
    await api.deleteQuest('quest-1', 'folder-1');
    await api.createQuestComment('quest-1', '確認しました', 'folder-1');
    await api.deleteQuestComment('quest-1', 'comment-1', 'folder-1');

    const headers = { 'X-Folder-Password': 'secret' };
    assert.deepEqual(calls, [
      { path: '/folders/folder-1/quests', options: { method: 'GET', headers } },
      {
        path: '/folders/folder-1/quests',
        options: { method: 'POST', headers, body: '{"text":"撮影してください"}' },
      },
      {
        path: '/quests/quest-1',
        options: { method: 'PUT', headers, body: '{"status":"done"}' },
      },
      { path: '/quests/quest-1', options: { method: 'DELETE', headers } },
      {
        path: '/quests/quest-1/comments',
        options: { method: 'POST', headers, body: '{"text":"確認しました"}' },
      },
      { path: '/quests/quest-1/comments/comment-1', options: { method: 'DELETE', headers } },
    ]);
  });

  test(`${label} search/export adapter maps query and folder credentials`, async () => {
    const calls = [];
    const api = createAdapter(
      async (path, options) => {
        calls.push({ path, options });
        return { items: [], downloadUrl: 'https://download.test/file' };
      },
      () => ({ 'X-Folder-Password': 'secret' })
    );
    await api.searchPhotos({ roomId: 'room/1', logTag: 'damage', keyword: 'door seal' });
    await api.exportFolder('folder-1', 'pdf');

    assert.deepEqual(calls, [
      {
        path: '/rooms/room%2F1/photos/search?logTag=damage&sort=newest&limit=50&keyword=door+seal',
        options: { method: 'GET' },
      },
      {
        path: '/folders/folder-1/export',
        options: { method: 'POST', headers: { 'X-Folder-Password': 'secret' }, body: '{"format":"pdf"}' },
      },
    ]);
  });

  test(`${label} team, invite, and billing adapter maps operations`, async () => {
    const calls = [];
    const api = createAdapter(async (path, options) => {
      calls.push({ path, options });
      return { ok: true };
    });
    await api.getTeam();
    await api.listTeamMembers();
    await api.updateTeamMember('user@example.com', { status: 'left' });
    await api.leaveTeam();
    await api.deleteTeam();
    await api.deleteAccount();
    await api.createInvite('folder-1');
    await api.acceptInvite('token-1');
    await api.revokeInvite('token-1');
    await api.getSubscription();
    await api.startSubscriptionCheckout({ plan: 'BASIC', successUrl: 'https://ok', cancelUrl: 'https://cancel' });
    await api.changeSubscription({ action: 'free' });

    assert.deepEqual(calls, [
      { path: '/team/me', options: { method: 'GET' } },
      { path: '/team/members', options: { method: 'GET' } },
      {
        path: '/team/members/user%40example.com',
        options: { method: 'PUT', body: '{"status":"left"}' },
      },
      { path: '/team/leave', options: { method: 'POST' } },
      { path: '/team/delete', options: { method: 'POST' } },
      { path: '/account/delete', options: { method: 'POST', body: '{}' } },
      { path: '/invites/create', options: { method: 'POST', body: '{"folderId":"folder-1"}' } },
      { path: '/invites/accept', options: { method: 'POST', body: '{"token":"token-1"}' } },
      { path: '/invites/revoke', options: { method: 'POST', body: '{"token":"token-1"}' } },
      { path: '/team/subscription', options: { method: 'GET' } },
      {
        path: '/team/subscription/checkout',
        options: { method: 'POST', body: '{"plan":"BASIC","successUrl":"https://ok","cancelUrl":"https://cancel"}' },
      },
      { path: '/team/subscription/change', options: { method: 'POST', body: '{"action":"free"}' } },
    ]);
  });
}

test('rejects adapters without a request function', () => {
  assert.throws(() => createLiveApi(null), /must be a function/);
  assert.throws(() => createDemoApi(null), /must be a function/);
});

test('live request owns HTTP headers, JSON parsing, and auth errors', async () => {
  const calls = [];
  let unauthorized = 0;
  const request = createLiveRequest({
    baseUrl: 'https://api.example',
    getHeaders: (method) => ({ authorization: 'Bearer token', method }),
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, status: 200, json: async () => ({ value: 1 }) };
    },
    onUnauthorized: () => { unauthorized += 1; },
  });
  assert.deepEqual(await request('/me', { method: 'GET', headers: { custom: 'yes' } }), { value: 1 });
  assert.equal(calls[0].url, 'https://api.example/me');
  assert.deepEqual(calls[0].options.headers, { custom: 'yes', authorization: 'Bearer token', method: 'GET' });

  const rejected = createLiveRequest({
    fetchImpl: async () => ({ ok: false, status: 401, text: async () => '{"code":"unauthorized"}' }),
    onUnauthorized: () => { unauthorized += 1; },
  });
  await assert.rejects(rejected('/me'), (error) => error.status === 401 && error.body.code === 'unauthorized');
  assert.equal(unauthorized, 1);
});

test('live environment and Cognito client own production auth configuration', async () => {
  const values = new Map([['kansa_api_base', 'https://api.example'], ['kansa_cognito_region', 'ap-northeast-1']]);
  const storage = {
    values,
    getItem: (key) => values.get(key) || null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
  const windowRef = {
    KANSA_CONFIG: { cognitoDomain: 'https://tenant.auth.ap-northeast-1.amazoncognito.com', cognitoClientId: 'client' },
    localStorage: storage,
    location: { origin: 'https://app.example', href: 'https://app.example/' },
    history: { replaceState() {} }, document: { title: 'Kansa' }, btoa,
    crypto: { getRandomValues: (bytes) => bytes.fill(1) },
  };
  const environment = resolveLiveEnvironment(windowRef);
  assert.equal(environment.apiBase, 'https://api.example');
  assert.equal(environment.cognito.domain, 'tenant');
  const client = createCognitoClient({ ...environment.cognito, windowRef, fetchImpl: async () => ({ ok: true }) });
  assert.equal(client.isConfigured(), true);
  await client.startLogin();
  assert.match(windowRef.location.href, /tenant\.auth\.ap-northeast-1\.amazoncognito\.com\/oauth2\/authorize/);
  assert.match(client.logoutUrl(), /\/logout\?/);
});

test('live upload sends original and preview before saving metadata', async () => {
  const requests = [];
  const uploads = [];
  const request = async (path, options) => {
    requests.push({ path, options });
    if (path.endsWith('/upload-url')) {
      return {
        photoId: 'photo-1', originalS3Key: 'original/key', previewS3Key: 'preview/key',
        originalUploadUrl: 'https://upload.test/original', previewUploadUrl: 'https://upload.test/preview',
      };
    }
    return { ok: true };
  };
  const fetchImpl = async (url, options) => {
    uploads.push({ url, options });
    return { ok: true, status: 200 };
  };
  const api = createLiveApi(request, () => ({ 'X-Folder-Password': 'secret' }), fetchImpl);
  const file = { name: 'photo.jpg', type: 'image/jpeg', size: 123 };
  const previewBlob = { preview: true };

  await api.uploadPhoto({
    folderId: 'folder-1', file, previewBlob, logTag: 'damage', initialComment: 'memo', questId: null,
  });

  assert.equal(uploads.length, 2);
  assert.equal(uploads[0].url, 'https://upload.test/original');
  assert.equal(uploads[0].options.body, file);
  assert.equal(uploads[1].url, 'https://upload.test/preview');
  assert.equal(uploads[1].options.body, previewBlob);
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    photoId: 'photo-1', originalS3Key: 'original/key', previewS3Key: 'preview/key',
    logTag: 'damage', initialComment: 'memo', questId: null,
  });
});

test('demo upload saves directly without external upload URLs', async () => {
  const calls = [];
  const api = createDemoApi(async (path, options) => {
    calls.push({ path, options });
    return { ok: true };
  });
  await api.uploadPhoto({
    folderId: 'folder-1', fileName: 'demo-001.jpg', logTag: 'inbound', initialComment: 'memo', questId: null,
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, '/folders/folder-1/photos');
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    fileName: 'demo-001.jpg', logTag: 'inbound', initialComment: 'memo', questId: null,
  });
});

test('demo backend request is isolated behind a context boundary', async () => {
  let clearCount = 0;
  const request = createDemoRequest({
    DEMO_USER_KEY: 'demo-user',
    clearError: () => { clearCount += 1; },
    demoBackend: {
      store: { me: { displayName: 'Demo User' }, rooms: [] },
      userKey: 'demo-user',
      getActiveRoom: () => null,
      recalculate: () => undefined,
    },
  });

  assert.deepEqual(await request('/me', { method: 'GET' }), {
    userKey: 'demo-user', displayName: 'Demo User',
  });
  assert.deepEqual(await request('/account/delete', { method: 'POST' }), { ok: true });
  await assert.rejects(() => request('/unknown', { method: 'GET' }), (error) => error.status === 501);
  assert.equal(clearCount, 3);
});

test('demo backend owns store lookup, recalculation, and summaries', async () => {
  const photo = {
    photoId: 'photo-1', fileName: 'door.jpg', logTag: 'damage', sizeBytes: 40,
    createdBy: 'demo-user', createdAt: '2026-08-11T00:00:00Z', comments: [],
  };
  const folder = { folderId: 'folder-1', title: 'Room 101', mode: 'photo', photos: [photo], quests: [] };
  const room = {
    roomId: 'room-1', roomName: 'Demo', subscriptionPlan: 'FREE', folders: [folder],
    members: [{ userKey: 'demo-user', role: 'admin', status: 'active' }],
  };
  const store = { activeRoomId: 'room-1', me: { displayName: 'Demo User' }, rooms: [room] };
  const backend = createDemoBackend({
    store,
    planBytes: { FREE: 100 },
    userKey: 'demo-user',
    defaultLogTag: 'container_number',
    normalizeFolderMode: (mode) => mode,
    normalizeLogTag: (tag, fallback = 'container_number') => tag === 'damage' ? tag : fallback,
    questStatusText: (status) => status,
  });

  backend.recalculate();

  assert.equal(backend.getActiveRoom(), room);
  assert.equal(backend.findFolder('folder-1').folder, folder);
  assert.equal(backend.findPhoto('photo-1').photo, photo);
  assert.equal(folder.usageBytes, 40);
  assert.equal(room.billing.freeBytes, 100);
  assert.equal(backend.photoSummary(photo).photoId, 'photo-1');

  const request = createDemoRequest({ demoBackend: backend, clearError: () => undefined });
  assert.deepEqual(await request('/rooms/mine', { method: 'GET' }), {
    activeRoomId: 'room-1',
    items: [{ roomId: 'room-1', roomName: 'Demo', role: 'admin', memberStatus: 'active', folderScope: 'all' }],
  });
  assert.equal((await request('/team/me', { method: 'GET' })).roomId, 'room-1');
  await request('/photos/photo-1', { method: 'PUT', body: '{"logTag":"invalid"}' });
  assert.equal(photo.logTag, 'damage');
});

test('demo UI keeps backend and upload behavior behind adapters', async () => {
  const source = await readFile(new URL('./demo.js', import.meta.url), 'utf8');

  assert.match(source, /demoRequest\s*=\s*createDemoRequest\s*\(/);
  assert.match(source, /const demoBackend\s*=\s*createDemoBackend\s*\(/);
  assert.doesNotMatch(source, /^api\s*=\s*async function/m);
  assert.doesNotMatch(source, /^uploadFiles\s*=\s*async function/m);
  assert.doesNotMatch(source, /^function demo(?:GetActiveRoom|FindFolder|FindPhoto|FindQuest|Recalculate|\w+Summary)/m);
});

test('demo entry contains no production auth, HTTP transport, or runtime function overrides', async () => {
  const source = await readFile(new URL('./demo.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /(?:COGNITO_|amazoncognito\.com|kansa_cognito_|kansa_api_base)/);
  assert.doesNotMatch(source, /async function api\s*\(/);
  assert.doesNotMatch(source, /function (?:headers|supportsPkce|randomString|sha256|base64UrlEncode|completeLoginFromCallback)\s*\(/);
  assert.doesNotMatch(source, /^(?:startLogin|startSignup|startSubscriptionCheckout|initUser|api)\s*=/m);
  assert.match(source, /let demoRequest;/);
  assert.match(source, /const appApi\s*=\s*createDemoApi\s*\(/);
});

test('demo request dispatches extracted domain handlers', async () => {
  const source = await readFile(new URL('./api-demo.js', import.meta.url), 'utf8');

  assert.match(source, /const handleSearchRequest\s*=/);
  assert.match(source, /const handleAccountRequest\s*=/);
  assert.match(source, /const handleInviteBillingRequest\s*=/);
  assert.match(source, /const handleRoomTeamRequest\s*=/);
  assert.match(source, /const handlers\s*=\s*\[handleSearchRequest, handleAccountRequest, handleInviteBillingRequest, handleRoomTeamRequest\]/);
  assert.match(source, /for \(const handler of handlers\)/);
});

test('both app entries connect upload validation and rendering to shared draft controllers', async () => {
  for (const file of ['./main.js', './demo.js']) {
    const source = await readFile(new URL(file, import.meta.url), 'utf8');
    assert.match(source, /createUploadDraftEditor\(state,[\s\S]*?validate:\s*\(drafts\)\s*=>\s*validateUploadDraftItems\(/);
    assert.match(source, /function validateUploadDrafts\(\)[\s\S]*?uploadDraftEditor\.validate\(\)/);
    assert.match(source, /function renderUploadDrafts\(\)[\s\S]*?renderUploadDraftContainerInto\(/);
  }
});

test('both app entries keep static element events behind shared registrars', async () => {
  for (const file of ['./main.js', './demo.js']) {
    const source = await readFile(new URL(file, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /els\.[A-Za-z0-9_]+\.(?:onclick|onchange|oninput|onkeydown)\s*=/);
    assert.doesNotMatch(source, /els\.[A-Za-z0-9_]+\.addEventListener\s*\(/);
    assert.match(source, /const updateFolderPasswordHandler\s*=\s*createFolderPasswordHandler\(appApi, state,/);
    assert.match(source, /const deleteFolderHandler\s*=\s*createFolderDeleteHandler\(appApi, state,/);
    assert.match(source, /const deleteRoomHandler\s*=\s*createRoomDeleteHandler\(appApi,/);
    assert.match(source, /const leaveRoomHandler\s*=\s*createRoomLeaveHandler\(appApi,/);
    assert.match(source, /onDeleteTeam:\s*safeAction\(deleteRoomHandler,/);
    assert.match(source, /onLeaveRoom:\s*safeAction\(leaveRoomHandler,/);
    assert.match(source, /const createRoomHandler\s*=\s*createRoomCreationHandler\(appApi, state,/);
    assert.match(source, /const createInitialRoomHandler\s*=\s*createRoomCreationHandler\(appApi, state,/);
    assert.match(source, /const createFolderHandler\s*=\s*createFolderCreationHandler\(appApi,/);
    assert.match(source, /onCreateRoom:\s*safeAction\(createRoomHandler,/);
    assert.match(source, /onCreateInitialRoom:\s*createInitialRoomHandler/);
    assert.match(source, /onCreateFolder:\s*safeAction\(createFolderHandler,/);
    assert.match(source, /const inviteHandlers\s*=\s*createInviteHandlers\(appApi,/);
    assert.match(source, /onCreateInvite:\s*safeAction\(inviteHandlers\.create,/);
    assert.match(source, /onRevokeInvite:\s*safeAction\(inviteHandlers\.revoke,/);
    assert.match(source, /function copyInviteUrl[\s\S]*?copyInviteText\(url,/);
    assert.match(source, /function setInviteUrlText[\s\S]*?copyInviteUrl\(url, true\)/);
    assert.match(source, /function copyInviteUrlFromInput[\s\S]*?copyInviteUrl\(targetInput\?\.value \|\| '', true\)/);
    assert.match(source, /function loadFolders[\s\S]*?handleFolderListError\(error,/);
    assert.match(source, /createQuestMutationActions\(appApi, quest,/);
    assert.match(source, /createQuestCommentMutationActions\(appApi, quest,/);
    assert.match(source, /createPhotoMutationActions\(appApi, photo,/);
    assert.match(source, /createPhotoCommentMutationActions\(appApi, photo,/);
    assert.match(source, /createPhotoCommentAddHandler\(appApi, photo,/);
    assert.doesNotMatch(source, /appApi\.deletePhoto\(photo\.photoId\)/);
    assert.doesNotMatch(source, /appApi\.updatePhoto\(photo\.photoId,/);
    assert.doesNotMatch(source, /appApi\.(?:create|delete)QuestComment\(/);
    assert.doesNotMatch(source, /appApi\.(?:update|delete)PhotoComment\(/);
    assert.doesNotMatch(source, /appApi\.createPhotoComment\(/);
    assert.match(source, /runOwnerRoomSwitch\(appApi, state, ownedRoom,/);
    assert.doesNotMatch(source, /appApi\.switchRoom\(ownedRoom\.roomId\)/);
    assert.match(source, /ensureUserDisplayName\(appApi, state,/);
    assert.doesNotMatch(source, /appApi\.(?:getCurrentUser|saveDisplayName)\(/);
    assert.match(source, /onResetUser:\s*safeAction\(createDisplayNameChangeHandler\(appApi, state,/);
    assert.match(source, /runFolderExport\(appApi, state, format,/);
    assert.doesNotMatch(source, /appApi\.exportFolder\(/);
    assert.doesNotMatch(source, /function createRoomAndEnter\s*\(/);
  }
});

test('both app entries compose major feature rendering from shared UI helpers', async () => {
  const requiredHelpers = [
    'renderUploadDraftContainerInto', 'renderFolderSelectInto', 'createQuestCardHeader',
    'appendQuestPhotoArea', 'createQuestCommentsSection', 'createPhotoCardShell',
    'createPhotoCommentsAccordion', 'syncSubscriptionPlanButtonsInto',
  ];
  for (const file of ['./main.js', './demo.js']) {
    const source = await readFile(new URL(file, import.meta.url), 'utf8');
    requiredHelpers.forEach((helper) => assert.match(source, new RegExp(`\\b${helper}\\s*\\(`), `${file} must use ${helper}`));
    assert.match(source, /createAdminPanelOptions\(state,[\s\S]*?member:\s*\{[\s\S]*?renderMembers:\s*renderTeamMembersInto/);
    assert.match(source, /createAdminPanelOptions\(state,[\s\S]*?folder:\s*\{[\s\S]*?createOverview:\s*createFolderAdminOverview/);
    assert.match(source, /createAdminPanelOptions\(state,[\s\S]*?selected:\s*\{[\s\S]*?appendActions:\s*appendFolderAdminActions[\s\S]*?renderMembers:\s*renderFolderMembersInto/);
    assert.match(source, /createStorageGraphController\(state, els,[\s\S]*?renderTop:\s*renderTopStorageGraphInto/);
    assert.match(source, /createStorageGraphController\(state, els,[\s\S]*?renderAdmin:\s*renderStorageGraphInto/);
    assert.match(source, /createBillingUiController\(state, els,[\s\S]*?renderBillingBarInto/);
    assert.match(source, /const adminPanelOptions\s*=\s*createAdminPanelOptions\(state,[\s\S]*?async function loadAdminPanel\(\)\s*\{\s*await renderAdminPanel\(appApi, state, adminPanelOptions\);\s*\}/);
  }
});

test('production entry delegates HTTP and Cognito implementation to api-live', async () => {
  const source = await readFile(new URL('./main.js', import.meta.url), 'utf8');
  assert.match(source, /createLiveRequest\s*\(/);
  assert.match(source, /createCognitoClient\s*\(/);
  assert.match(source, /const deleteAccountHandler\s*=\s*createAccountDeleteHandler\(appApi,/);
  assert.match(source, /onDeleteAccount:\s*safeAction\(deleteAccountHandler,/);
  assert.doesNotMatch(source, /amazoncognito\.com/);
  assert.doesNotMatch(source, /async function api\s*\(/);
  assert.doesNotMatch(source, /function (?:supportsPkce|randomString|base64UrlEncode)\s*\(/);
});
