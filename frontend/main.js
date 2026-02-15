const APP_CONFIG = window.KANSA_CONFIG || {};
const API_BASE =
  window.localStorage.getItem('kansa_api_base') || APP_CONFIG.apiBase || 'http://127.0.0.1:3000';
const PHOTO_BUCKET =
  window.localStorage.getItem('kansa_photo_bucket') || APP_CONFIG.photoBucket || '';
function normalizeCognitoDomain(raw) {
  const value = String(raw || '').trim();
  if (!value) return '';
  const withoutProto = value.replace(/^https?:\/\//i, '');
  const host = withoutProto.split('/')[0];
  return host.replace(/\.auth\..*$/, '');
}

const COGNITO_REGION =
  window.localStorage.getItem('kansa_cognito_region') || APP_CONFIG.cognitoRegion || '';
const COGNITO_DOMAIN = normalizeCognitoDomain(
  window.localStorage.getItem('kansa_cognito_domain') || APP_CONFIG.cognitoDomain || ''
);
const COGNITO_CLIENT_ID =
  window.localStorage.getItem('kansa_cognito_client_id') || APP_CONFIG.cognitoClientId || '';
const COGNITO_REDIRECT_URI =
  APP_CONFIG.cognitoRedirectUri || window.localStorage.getItem('kansa_cognito_redirect_uri') || window.location.origin;

const state = {
  userKey: null,
  userName: null,
  idToken: null,
  roomName: null,
  teamRole: null,
  isAdmin: false,
  uploadBlocked: false,
  billing: null,
  ownerUserKey: null,
  lastInviteToken: null,
  folderPasswordById: {},
  folders: [],
  folderUnreadMap: {},
  selectedFolder: null,
  photos: [],
  openAccordions: new Set(),
  restoreScrollY: null,
  season: 'spring',
  isUploading: false,
};

const SEASONS = new Set(['spring', 'summer', 'autumn', 'winter']);

function el(tag, attrs = {}, text = null) {
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

function detectCurrentSeason() {
  const month = new Date().getMonth() + 1;
  if (month >= 3 && month <= 5) return 'spring';
  if (month >= 6 && month <= 8) return 'summer';
  if (month >= 9 && month <= 11) return 'autumn';
  return 'winter';
}

function normalizeSeason(value) {
  return SEASONS.has(value) ? value : detectCurrentSeason();
}

function readStateKey() {
  return `kansa_read_comments_${state.userKey || 'guest'}`;
}

function getReadState() {
  try {
    return JSON.parse(localStorage.getItem(readStateKey()) || '{}');
  } catch (_) {
    return {};
  }
}

function setReadState(nextState) {
  localStorage.setItem(readStateKey(), JSON.stringify(nextState));
}

function getLatestIncomingCommentAt(comments) {
  return comments
    .filter((comment) => comment.createdBy !== state.userKey)
    .reduce((latest, comment) => (comment.createdAt > latest ? comment.createdAt : latest), '');
}

function isUnread(photoId, latestIncomingAt) {
  if (!latestIncomingAt) return false;
  const map = getReadState();
  return !map[photoId] || map[photoId] < latestIncomingAt;
}

function markAsRead(photoId, latestIncomingAt) {
  if (!latestIncomingAt) return;
  const map = getReadState();
  if (!map[photoId] || map[photoId] < latestIncomingAt) {
    map[photoId] = latestIncomingAt;
    setReadState(map);
  }
}

function hasCognitoConfig() {
  return Boolean(COGNITO_REGION && COGNITO_DOMAIN && COGNITO_CLIENT_ID && COGNITO_REDIRECT_URI);
}

function parseJwt(token) {
  if (!token) return null;
  try {
    const payload = token.split('.')[1];
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(normalized);
    return JSON.parse(json);
  } catch (_) {
    return null;
  }
}

function clearAuth() {
  localStorage.removeItem('kansa_id_token');
  localStorage.removeItem('kansa_oauth_state');
  localStorage.removeItem('kansa_oauth_code_verifier');
  localStorage.removeItem('kansa_room_name');
  state.idToken = null;
  state.userKey = null;
  state.userName = null;
}

function resetRoomContext() {
  localStorage.removeItem('kansa_room_name');
  state.roomName = null;
  state.teamRole = null;
  state.isAdmin = false;
  state.uploadBlocked = false;
  state.billing = null;
  state.ownerUserKey = null;
  state.lastInviteToken = null;
  state.folderPasswordById = {};
  state.folders = [];
  state.folderUnreadMap = {};
  state.selectedFolder = null;
  state.photos = [];
  state.openAccordions.clear();
  state.restoreScrollY = null;
  if (els.folderDetail) els.folderDetail.classList.add('hidden');
  renderBillingBar();
  setAdminUiVisibility();
}

function supportsPkce() {
  return Boolean(window.crypto && window.crypto.subtle && typeof window.crypto.subtle.digest === 'function');
}

function randomString(length = 64) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  if (window.crypto && typeof window.crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => chars[b % chars.length]).join('');
  }
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

function base64UrlEncode(bytes) {
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function startLogin() {
  if (!hasCognitoConfig()) {
    throw new Error('Cognito設定が不足しています。config.jsを確認してください。');
  }
  const stateVal = randomString(32);
  localStorage.setItem('kansa_oauth_state', stateVal);
  const authUrl = new URL(`https://${COGNITO_DOMAIN}.auth.${COGNITO_REGION}.amazoncognito.com/oauth2/authorize`);
  const usePkceHash = supportsPkce();
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', COGNITO_CLIENT_ID);
  authUrl.searchParams.set('redirect_uri', COGNITO_REDIRECT_URI);
  authUrl.searchParams.set('scope', 'openid email profile');
  authUrl.searchParams.set('state', stateVal);
  const verifier = randomString(64);
  localStorage.setItem('kansa_oauth_code_verifier', verifier);
  if (usePkceHash) {
    const challenge = base64UrlEncode(await sha256(verifier));
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('code_challenge', challenge);
  } else {
    authUrl.searchParams.set('code_challenge_method', 'plain');
    authUrl.searchParams.set('code_challenge', verifier);
  }
  window.location.href = authUrl.toString();
}

async function startSignup() {
  if (!hasCognitoConfig()) {
    throw new Error('Cognito設定が不足しています。config.jsを確認してください。');
  }
  const stateVal = randomString(32);
  localStorage.setItem('kansa_oauth_state', stateVal);
  const signupUrl = new URL(`https://${COGNITO_DOMAIN}.auth.${COGNITO_REGION}.amazoncognito.com/signup`);
  const usePkceHash = supportsPkce();
  signupUrl.searchParams.set('state', stateVal);
  signupUrl.searchParams.set('client_id', COGNITO_CLIENT_ID);
  signupUrl.searchParams.set('response_type', 'code');
  signupUrl.searchParams.set('scope', 'openid email profile');
  signupUrl.searchParams.set('redirect_uri', COGNITO_REDIRECT_URI);
  const verifier = randomString(64);
  localStorage.setItem('kansa_oauth_code_verifier', verifier);
  if (usePkceHash) {
    signupUrl.searchParams.set('code_challenge_method', 'S256');
    signupUrl.searchParams.set('code_challenge', base64UrlEncode(await sha256(verifier)));
  } else {
    signupUrl.searchParams.set('code_challenge_method', 'plain');
    signupUrl.searchParams.set('code_challenge', verifier);
  }
  window.location.href = signupUrl.toString();
}

async function completeLoginFromCallback() {
  const url = new URL(window.location.href);
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');
  if (!code) return false;

  const expectedState = localStorage.getItem('kansa_oauth_state');
  const verifier = localStorage.getItem('kansa_oauth_code_verifier');
  if (!expectedState || !verifier || returnedState !== expectedState) {
    localStorage.removeItem('kansa_oauth_state');
    localStorage.removeItem('kansa_oauth_code_verifier');
    url.searchParams.delete('code');
    url.searchParams.delete('state');
    window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
    return false;
  }

  const body = new URLSearchParams();
  body.set('grant_type', 'authorization_code');
  body.set('client_id', COGNITO_CLIENT_ID);
  body.set('redirect_uri', COGNITO_REDIRECT_URI);
  body.set('code', code);
  body.set('code_verifier', verifier);

  const tokenRes = await fetch(
    `https://${COGNITO_DOMAIN}.auth.${COGNITO_REGION}.amazoncognito.com/oauth2/token`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    }
  );
  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`Cognitoトークン取得失敗: ${text || tokenRes.status}`);
  }
  const tokenJson = await tokenRes.json();
  if (!tokenJson.id_token) {
    throw new Error('Cognitoトークンが取得できませんでした。');
  }
  localStorage.setItem('kansa_id_token', tokenJson.id_token);
  localStorage.removeItem('kansa_oauth_state');
  localStorage.removeItem('kansa_oauth_code_verifier');
  url.searchParams.delete('code');
  url.searchParams.delete('state');
  window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
  return true;
}

const els = {
  userSetup: document.querySelector('#user-setup'),
  roomSetup: document.querySelector('#room-setup'),
  app: document.querySelector('#app'),
  globalMenuWrap: document.querySelector('#global-menu-wrap'),
  loginBtn: document.querySelector('#login-btn'),
  signupBtn: document.querySelector('#signup-btn'),
  logoutBtn: document.querySelector('#logout-btn'),
  createRoomName: document.querySelector('#create-room-name'),
  createRoomBtn: document.querySelector('#create-room-btn'),
  refreshMyRoomsBtn: document.querySelector('#refresh-my-rooms-btn'),
  myRoomsList: document.querySelector('#my-rooms-list'),
  leaveRoomBtn: document.querySelector('#leave-room-btn'),
  menuBtn: document.querySelector('#menu-btn'),
  menuPanel: document.querySelector('#menu-panel'),
  toggleThemeBtn: document.querySelector('#toggle-theme-btn'),
  seasonSelect: document.querySelector('#season-select'),
  resetUserBtn: document.querySelector('#reset-user-btn'),
  teamAdminBtn: document.querySelector('#team-admin-btn'),
  teamAdminCard: document.querySelector('#team-admin'),
  teamAdminBackBtn: document.querySelector('#team-admin-back-btn'),
  billingBar: document.querySelector('#billing-bar'),
  billingStatus: document.querySelector('#billing-status'),
  purchase1Btn: document.querySelector('#purchase-1gbm'),
  purchase10Btn: document.querySelector('#purchase-10gbm'),
  purchase50Btn: document.querySelector('#purchase-50gbm'),
  deleteTeamBtn: document.querySelector('#delete-team-btn'),
  createInviteBtn: document.querySelector('#create-invite-btn'),
  revokeInviteBtn: document.querySelector('#revoke-invite-btn'),
  inviteUrl: document.querySelector('#invite-url'),
  memberList: document.querySelector('#member-list'),
  folderAdminList: document.querySelector('#folder-admin-list'),
  folderCreateCard: document.querySelector('#folder-create-card'),
  folderListCard: document.querySelector('#folder-list-card'),
  folderDeleteBtn: document.querySelector('#delete-folder-btn'),
  currentName: document.querySelector('#current-name'),
  currentRoom: document.querySelector('#current-room'),
  folderTitle: document.querySelector('#folder-title'),
  folderPassword: document.querySelector('#folder-password'),
  createFolderBtn: document.querySelector('#create-folder-btn'),
  folderSelect: document.querySelector('#folder-select'),
  folderDetail: document.querySelector('#folder-detail'),
  folderDetailTitle: document.querySelector('#folder-detail-title'),
  folderPasswordSet: document.querySelector('#folder-password-set'),
  setFolderPasswordBtn: document.querySelector('#set-folder-password-btn'),
  photoFiles: document.querySelector('#photo-files'),
  uploadBtn: document.querySelector('#upload-btn'),
  uploadLoading: document.querySelector('#upload-loading'),
  exportBtn: document.querySelector('#export-btn'),
  photoList: document.querySelector('#photo-list'),
  errorBox: document.querySelector('#error-box'),
  toast: document.querySelector('#toast'),
};

function closeMenu() {
  if (els.menuPanel) {
    els.menuPanel.classList.add('hidden');
  }
}

function setTeamAdminMode(isOpen) {
  // While team admin is open, hide main folder workflow to reduce clutter.
  if (els.folderCreateCard) els.folderCreateCard.classList.toggle('hidden', isOpen);
  if (els.folderListCard) els.folderListCard.classList.toggle('hidden', isOpen);
  if (els.folderDetail) els.folderDetail.classList.toggle('hidden', isOpen ? true : !state.selectedFolder);
}

function setMenuActionVisibility(showActions) {
  if (els.resetUserBtn) {
    els.resetUserBtn.classList.toggle('hidden', !showActions);
  }
  if (els.leaveRoomBtn) {
    els.leaveRoomBtn.classList.toggle('hidden', !showActions);
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

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  const mib = 1024 * 1024;
  const gib = 1024 * 1024 * 1024;
  if (n >= gib) return `${(n / gib).toFixed(2)}GB`;
  return `${Math.round(n / mib)}MB`;
}

function renderBillingBar() {
  if (!els.billingBar) return;
  if (!state.roomName || !state.billing) {
    els.billingBar.classList.add('hidden');
    els.billingBar.textContent = '';
    return;
  }

  const b = state.billing;
  const usage = formatBytes(b.usageBytes);
  const free = formatBytes(b.freeBytes);
  const freeRemainBytes = Math.max(0, Number(b.freeBytes || 0) - Number(b.usageBytes || 0));
  const freeRemain = formatBytes(freeRemainBytes);
  const gbm = Number(b.gbMonthEquivalent || 0).toFixed(2);
  const days = b.estimatedDaysLeft === null ? '-' : Math.max(0, b.estimatedDaysLeft).toFixed(1);
  const blocked = state.uploadBlocked;

  const parts = [];
  parts.push(`使用量: ${usage} / 無料: ${free}（残り ${freeRemain}）`);
  parts.push(`追加残り: ${gbm} GB・月 相当`);
  if (state.ownerUserKey && state.userKey) {
    parts.push(state.ownerUserKey === state.userKey ? '作成者' : '参加者');
  }
  if (blocked) parts.push('アップロード停止中（残量不足）');
  if (!blocked && Number(b.gbMonthEquivalent || 0) <= 0 && freeRemainBytes > 0) parts.push('無料枠で利用中');
  if (state.isAdmin) parts.push('管理者');

  els.billingBar.textContent = parts.join(' / ');
  els.billingBar.classList.remove('hidden');
}

function setAdminUiVisibility() {
  if (els.teamAdminBtn) els.teamAdminBtn.classList.toggle('hidden', !state.isAdmin);
  if (els.folderDeleteBtn) els.folderDeleteBtn.classList.toggle('hidden', !state.isAdmin);
  if (els.setFolderPasswordBtn) els.setFolderPasswordBtn.classList.toggle('hidden', !state.isAdmin);
  if (!state.isAdmin) {
    if (els.teamAdminCard) els.teamAdminCard.classList.add('hidden');
  }
}

function applyTheme(theme) {
  if (theme === 'dark') {
    document.body.classList.add('dark');
  } else {
    document.body.classList.remove('dark');
  }
}

function applySeason(season) {
  const normalized = normalizeSeason(season);
  state.season = normalized;
  document.body.setAttribute('data-season', normalized);
  if (els.seasonSelect && els.seasonSelect.value !== normalized) {
    els.seasonSelect.value = normalized;
  }
}

function initTheme() {
  const theme = localStorage.getItem('kansa_theme') || 'light';
  applyTheme(theme);
  const season = normalizeSeason(localStorage.getItem('kansa_season'));
  applySeason(season);
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

async function fetchMe() {
  return api('/me', { method: 'GET' });
}

async function saveDisplayName(displayName) {
  return api('/me/display-name', {
    method: 'PUT',
    body: JSON.stringify({ displayName }),
  });
}

async function ensureDisplayName() {
  const me = await fetchMe();
  if (me.displayName) {
    state.userName = me.displayName;
    return;
  }

  while (true) {
    const next = window.prompt('表示名を入力してください。メニューからいつでも変更可能です。');
    if (next === null) continue;
    const displayName = next.trim();
    if (!displayName) {
      window.alert('表示名は必須です。');
      continue;
    }
    await saveDisplayName(displayName);
    state.userName = displayName;
    showToast('表示名を設定しました。');
    return;
  }
}

function setUploadLoading(isLoading) {
  state.isUploading = isLoading;
  if (els.uploadBtn) {
    els.uploadBtn.disabled = isLoading;
  }
  if (els.photoFiles) {
    els.photoFiles.disabled = isLoading;
  }
  if (els.uploadLoading) {
    els.uploadLoading.classList.toggle('hidden', !isLoading);
  }
}

function asMessage(error) {
  if (!error) return 'unknown error';
  if (typeof error === 'string') return error;
  return error.message || 'unknown error';
}

function safeAction(fn, label) {
  return async (...args) => {
    try {
      clearError();
      await fn(...args);
    } catch (error) {
      showError(`${label}失敗: ${asMessage(error)}`);
      console.error(error);
    }
  };
}

function preserveCurrentView(photoId) {
  if (photoId) {
    state.openAccordions.add(photoId);
  }
  state.restoreScrollY = window.scrollY;
}

async function initUser() {
  initTheme();
  setMenuActionVisibility(false);
  if (els.logoutBtn) els.logoutBtn.classList.add('hidden');
  if (els.globalMenuWrap) els.globalMenuWrap.classList.add('hidden');
  if (!hasCognitoConfig()) {
    if (els.userSetup) els.userSetup.classList.remove('hidden');
    showError('Cognito設定が不足しています。config.jsにdomain/clientId/regionを設定してください。');
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
        const res = await api('/invites/accept', { method: 'POST', body: JSON.stringify({ token: inviteToken }) });
        state.roomName = res.roomName || null;
        localStorage.removeItem('kansa_pending_invite');
        const url = new URL(window.location.href);
        url.searchParams.delete('invite');
        window.history.replaceState({}, document.title, url.pathname + url.search + url.hash);
        showApp();
        showToast('お部屋に参加しました。');
        return;
      } catch (error) {
        showError(`招待URLの処理に失敗しました: ${asMessage(error)}`);
        // The token may be expired/invalid; avoid retry loops.
        localStorage.removeItem('kansa_pending_invite');
        // Fall through to normal room discovery/setup.
      }
    }
    // Resolve room solely from membership; don't trust local cache across users.
    try {
      const data = await api('/team/me', { method: 'GET' });
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
  if (els.userSetup) els.userSetup.classList.remove('hidden');
}

function showRoomSetup() {
  els.userSetup.classList.add('hidden');
  if (els.roomSetup) els.roomSetup.classList.remove('hidden');
  els.app.classList.add('hidden');
  if (state.userKey) {
    if (els.globalMenuWrap) els.globalMenuWrap.classList.remove('hidden');
    if (els.logoutBtn) els.logoutBtn.classList.remove('hidden');
    loadMyRooms().catch(() => {});
  } else {
    if (els.globalMenuWrap) els.globalMenuWrap.classList.add('hidden');
    if (els.logoutBtn) els.logoutBtn.classList.add('hidden');
  }
  setMenuActionVisibility(false);
  closeMenu();
}

function renderMyRooms(items, activeRoomId) {
  if (!els.myRoomsList) return;
  const rooms = (items || []).filter((r) => r && r.roomId && r.roomName && r.status !== 'left');
  if (!rooms.length) {
    els.myRoomsList.textContent = '招待されたお部屋がなかです';
    return;
  }
  els.myRoomsList.innerHTML = '';
  rooms.forEach((r) => {
    const row = el('div', { class: 'row', style: 'gap:8px; justify-content:space-between; align-items:center;' });
    const suffix = r.roomId === activeRoomId ? '（参加中）' : r.status === 'inactive' ? '（退出中）' : '';
    const label = el('div', {}, `${r.roomName}${suffix}`);
    const btn = el('button', { type: 'button' }, r.roomId === activeRoomId ? '入室中' : 'この部屋へ');
    btn.disabled = r.roomId === activeRoomId;
    btn.onclick = safeAction(async () => {
      const res = await api('/rooms/switch', { method: 'POST', body: JSON.stringify({ roomId: r.roomId }) });
      state.roomName = res.roomName || r.roomName;
      showApp();
    }, 'お部屋切替');
    row.appendChild(label);
    row.appendChild(btn);
    els.myRoomsList.appendChild(row);
  });
}

async function loadMyRooms() {
  if (!state.idToken) return;
  if (!els.myRoomsList) return;
  els.myRoomsList.textContent = '読み込み中...';
  const res = await api('/rooms/mine', { method: 'GET' });
  renderMyRooms(res.items || [], res.activeRoomId || null);
}

function showApp() {
  els.userSetup.classList.add('hidden');
  if (els.roomSetup) els.roomSetup.classList.add('hidden');
  els.app.classList.remove('hidden');
  if (els.globalMenuWrap) els.globalMenuWrap.classList.remove('hidden');
  setMenuActionVisibility(true);
  if (els.logoutBtn) els.logoutBtn.classList.remove('hidden');
  closeMenu();
  els.currentName.textContent = state.userName;
  if (els.currentRoom) els.currentRoom.textContent = state.roomName || '-';
  loadTeamMe().then(() => {
    if (els.uploadBtn) els.uploadBtn.disabled = Boolean(state.uploadBlocked);
  });
  loadFolders();
}

function headers(method = 'GET') {
  const upper = String(method || 'GET').toUpperCase();
  const authHeader = state.idToken ? { Authorization: `Bearer ${state.idToken}` } : {};
  // Room headers are deprecated. Room is inferred from membership (/team/me, invite accept).
  const roomHeaders = {};
  if (upper === 'GET') return { ...authHeader, ...roomHeaders };
  const safeUserName = encodeURIComponent(state.userName || 'unknown');
  return {
    ...authHeader,
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

async function api(path, options = {}) {
  clearError();
  const method = String(options.method || 'GET').toUpperCase();
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        ...(options.headers || {}),
        ...headers(method),
      },
    });
  } catch (error) {
    throw new Error(`ネットワークエラー: ${asMessage(error)}`);
  }

  if (!res.ok) {
    const text = await res.text();
    if (res.status === 401) {
      clearAuth();
      if (els.app) els.app.classList.add('hidden');
      if (els.roomSetup) els.roomSetup.classList.add('hidden');
      if (els.userSetup) els.userSetup.classList.remove('hidden');
    }
    if (res.status === 403 && text.includes('"no active room"')) {
      resetRoomContext();
      showRoomSetup();
    }
    throw new Error(`APIエラー(${res.status}): ${text || 'unknown error'}`);
  }

  return res.json();
}

async function loadTeamMe() {
  try {
    const data = await api('/team/me', { method: 'GET' });
    state.teamRole = data.role || 'member';
    state.isAdmin = Boolean(data.isAdmin);
    state.uploadBlocked = Boolean(data.uploadBlocked);
    state.billing = data.billing || null;
    state.ownerUserKey = data.ownerUserKey || null;
  } catch (error) {
    // Keep the UI usable, but don't hide the failure.
    showError(`チーム情報取得失敗: ${asMessage(error)}（バックエンド/フロントのデプロイ差分やキャッシュの可能性）`);
    state.teamRole = null;
    state.isAdmin = false;
    state.uploadBlocked = false;
    state.billing = null;
    state.ownerUserKey = null;
  }
  setAdminUiVisibility();
  renderBillingBar();
}

async function loadAdminPanel() {
  if (!state.isAdmin) return;
  if (!els.teamAdminCard || els.teamAdminCard.classList.contains('hidden')) return;

  // Members
  try {
    const members = await api('/team/members', { method: 'GET' });
    const items = members.items || [];
    if (els.memberList) {
      els.memberList.innerHTML = '';
      if (!items.length) {
        els.memberList.appendChild(el('div', { class: 'muted' }, 'メンバーがおらんばい'));
      } else {
        items.forEach((m) => {
          const row = el('div', { class: 'member-row' });
          const name = m.displayName || m.userKey;
          const left = el(
            'div',
            {},
            `${name} / ${m.role} / ${m.status}${m.folderScope ? ` / 閲覧:${m.folderScope}` : ''}`
          );
          row.appendChild(left);

          const actions = el('div', { class: 'row', style: 'gap:6px; justify-content:flex-end;' });
          const scopeSelect = el('select', { style: 'min-width:120px;' });
          scopeSelect.appendChild(el('option', { value: 'own' }, '自分のフォルダのみ'));
          scopeSelect.appendChild(el('option', { value: 'all' }, '全フォルダ表示'));
          scopeSelect.value = m.role === 'admin' ? 'all' : m.folderScope || 'own';
          scopeSelect.disabled = m.role === 'admin' || m.userKey === state.ownerUserKey;
          scopeSelect.onchange = safeAction(async () => {
            const next = scopeSelect.value;
            await api(`/team/members/${encodeURIComponent(m.userKey)}`, {
              method: 'PUT',
              body: JSON.stringify({ folderScope: next }),
            });
            await loadAdminPanel();
          }, '権限更新');
          actions.appendChild(scopeSelect);

          // Remove member (kick) with confirm.
          if (m.role !== 'admin' && m.userKey !== state.ownerUserKey && m.status !== 'left') {
            const removeBtn = el('button', { type: 'button', class: 'danger' }, '削除');
            removeBtn.onclick = safeAction(async () => {
              const ok = window.confirm(`メンバー「${name}」をお部屋から削除してよかですか？（本人は入れんごとなります）`);
              if (!ok) return;
              await api(`/team/members/${encodeURIComponent(m.userKey)}`, {
                method: 'PUT',
                body: JSON.stringify({ status: 'left' }),
              });
              showToast('メンバーを削除しました。');
              await loadAdminPanel();
            }, 'メンバー削除');
            actions.appendChild(removeBtn);
          }
          row.appendChild(actions);
          els.memberList.appendChild(row);
        });
      }
    }
  } catch (error) {
    if (els.memberList) {
      els.memberList.innerHTML = '';
      els.memberList.appendChild(el('div', { class: 'muted' }, `メンバー取得失敗: ${asMessage(error)}`));
    }
  }

  // Folder admin list
  try {
    const data = await api('/folders', { method: 'GET' });
    const folders = data.items || [];
    if (els.folderAdminList) {
      els.folderAdminList.innerHTML = '';
      if (!folders.length) {
        els.folderAdminList.appendChild(el('div', { class: 'muted' }, 'フォルダがなかです'));
      } else {
        folders.forEach((f) => {
          const row = el('div', { class: 'member-row' });
          const left = el('div', {}, `${f.folderCode || ''} ${f.title || f.folderId}（作成:${f.createdByName || f.createdBy}）`);
          row.appendChild(left);
          const actions = el('div', { class: 'row', style: 'gap:6px; justify-content:flex-end;' });
          const delBtn = el('button', { type: 'button', class: 'danger' }, '削除');
          delBtn.onclick = safeAction(async () => {
            const ok = window.confirm(`フォルダ「${f.title || f.folderId}」を削除してよかですか？（写真とコメントも消えます）`);
            if (!ok) return;
            await api(`/folders/${f.folderId}`, { method: 'DELETE' });
            await loadFolders();
            await loadAdminPanel();
          }, 'フォルダ削除');
          actions.appendChild(delBtn);
          row.appendChild(actions);
          els.folderAdminList.appendChild(row);
        });
      }
    }
  } catch (error) {
    if (els.folderAdminList) {
      els.folderAdminList.innerHTML = '';
      els.folderAdminList.appendChild(el('div', { class: 'muted' }, `フォルダ取得失敗: ${asMessage(error)}`));
    }
  }

  if (els.billingStatus && state.billing) {
    const b = state.billing;
    const freeRemainBytes = Math.max(0, Number(b.freeBytes || 0) - Number(b.usageBytes || 0));
    els.billingStatus.textContent = `使用量 ${formatBytes(b.usageBytes)} / 無料 ${formatBytes(
      b.freeBytes
    )}（残り ${formatBytes(freeRemainBytes)}） / 追加残り ${Number(
      b.gbMonthEquivalent || 0
    ).toFixed(2)} GB・月 相当`;
  }
}

async function setInviteUrlText(url) {
  if (els.inviteUrl) els.inviteUrl.value = url || '';
  if (!url) return;
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(url);
      showToast('招待URLをコピーしました。');
      return;
    }
  } catch (_) {
    // Ignore and fall back.
  }
  window.prompt('招待URL（コピーしてください）', url);
}

if (els.createInviteBtn) {
  els.createInviteBtn.onclick = safeAction(async () => {
    const res = await api('/invites/create', { method: 'POST', body: JSON.stringify({}) });
    const token = res.token;
    if (!token) throw new Error('招待トークンが取得できませんでした。');
    state.lastInviteToken = token;
    if (els.revokeInviteBtn) els.revokeInviteBtn.classList.remove('hidden');
    const base = window.location.origin + window.location.pathname;
    const url = `${base}?invite=${encodeURIComponent(token)}`;
    await setInviteUrlText(url);
  }, '招待URL発行');
}

if (els.revokeInviteBtn) {
  els.revokeInviteBtn.onclick = safeAction(async () => {
    if (!state.lastInviteToken) {
      showError('失効する招待URLがなかです（先に発行してください）');
      return;
    }
    const ok = window.confirm('この招待URLを失効してよかですか？');
    if (!ok) return;
    await api('/invites/revoke', { method: 'POST', body: JSON.stringify({ token: state.lastInviteToken }) });
    state.lastInviteToken = null;
    if (els.inviteUrl) els.inviteUrl.value = '';
    els.revokeInviteBtn.classList.add('hidden');
    showToast('招待URLを失効しました。');
  }, '招待URL失効');
}

async function loadFolders() {
  try {
    const data = await api('/folders', { method: 'GET' });
    state.folders = data.items || [];
    await refreshFolderUnread();
    renderFolders();
  } catch (error) {
    state.folders = [];
    renderFolders();
    const message = error?.message || 'unknown';
    if (message.includes('Failed to fetch') || message.includes('Type error')) {
      showError('フォルダ取得失敗: ネットワーク/CORSエラーの可能性があります');
    } else {
      showError(`フォルダ取得失敗: ${message}`);
    }
  }
}

async function computeFolderUnread(folderId) {
  const photosData = await api(`/folders/${folderId}/photos`, { method: 'GET' });
  const photos = photosData.items || [];
  for (const photo of photos) {
    const latestAt = photo.latestCommentAt || '';
    const latestBy = photo.latestCommentBy || '';
    const latestIncoming = latestAt && latestBy && latestBy !== state.userKey ? latestAt : '';
    if (isUnread(photo.photoId, latestIncoming)) return true;
  }
  return false;
}

async function refreshFolderUnread(folderIds = null) {
  const targets = folderIds
    ? state.folders.filter((folder) => folderIds.includes(folder.folderId))
    : state.folders;
  if (!targets.length) return;

  const entries = await Promise.all(
    targets.map(async (folder) => {
      try {
        const unread = await computeFolderUnread(folder.folderId);
        return [folder.folderId, unread];
      } catch (_) {
        return [folder.folderId, false];
      }
    })
  );
  entries.forEach(([folderId, unread]) => {
    state.folderUnreadMap[folderId] = unread;
  });
}

function renderFolders() {
  if (!els.folderSelect) return;
  els.folderSelect.innerHTML = '';
  if (!state.folders.length) {
    const empty = document.createElement('option');
    empty.value = '';
    empty.textContent = 'まだフォルダがなかです';
    els.folderSelect.appendChild(empty);
    els.folderSelect.value = '';
    els.folderDetail.classList.add('hidden');
    state.selectedFolder = null;
    return;
  }

  const head = document.createElement('option');
  head.value = '';
  head.textContent = 'フォルダを選択してください';
  els.folderSelect.appendChild(head);

  state.folders.forEach((folder) => {
    const option = document.createElement('option');
    option.value = folder.folderId;
    const unread = state.folderUnreadMap[folder.folderId];
    const locked = Boolean(folder.hasPassword);
    option.textContent = `${folder.folderCode || 'F---'} ${folder.title}${locked ? ' [鍵]' : ''}${unread ? ' ●新着' : ''}`;
    els.folderSelect.appendChild(option);
  });

  if (state.selectedFolder) {
    els.folderSelect.value = state.selectedFolder.folderId;
  }
}

async function selectFolder(folder) {
  if (folder.hasPassword && !state.folderPasswordById[folder.folderId]) {
    const entered = window.prompt('このフォルダは鍵付きです。パスワードを入力してください。', '');
    if (entered === null) return;
    const pw = String(entered || '').trim();
    if (!pw) {
      showError('フォルダパスワードが必要です。');
      return;
    }
    state.folderPasswordById[folder.folderId] = pw;
  }
  state.selectedFolder = folder;
  els.folderDetail.classList.remove('hidden');
  els.folderDetailTitle.textContent = `フォルダ: ${folder.folderCode || 'F---'} ${folder.title}`;
  await loadPhotos();
}

async function selectFolderById(folderId) {
  if (!folderId) {
    state.selectedFolder = null;
    els.folderDetail.classList.add('hidden');
    return;
  }
  const folder = state.folders.find((f) => f.folderId === folderId);
  if (!folder) return;
  await selectFolder(folder);
}

async function loadPhotos() {
  const folderId = state.selectedFolder.folderId;
  const data = await api(`/folders/${folderId}/photos`, {
    method: 'GET',
    headers: { ...folderPasswordHeader(folderId) },
  });
  state.photos = data.items || [];
  await renderPhotos();
  await refreshFolderUnread([state.selectedFolder.folderId]);
  renderFolders();
  await loadTeamMe();
  if (els.uploadBtn) els.uploadBtn.disabled = Boolean(state.uploadBlocked);
  if (state.restoreScrollY !== null) {
    window.scrollTo(0, state.restoreScrollY);
    state.restoreScrollY = null;
  }
}

async function uploadFiles() {
  if (state.isUploading) return;
  const files = Array.from(els.photoFiles.files || []);
  if (!files.length) return;

  setUploadLoading(true);
  try {
    const resizeToJpeg = async (file, maxLongSide = 2048, quality = 0.82) => {
      // Best-effort client-side resize; if anything fails, fall back to original.
      let bitmap = null;
      try {
        if (window.createImageBitmap) {
          bitmap = await window.createImageBitmap(file);
        } else {
          const url = URL.createObjectURL(file);
          const img = new Image();
          img.decoding = 'async';
          img.src = url;
          await new Promise((resolve, reject) => {
            img.onload = resolve;
            img.onerror = reject;
          });
          bitmap = img;
          URL.revokeObjectURL(url);
        }
      } catch (_) {
        return null;
      }

      const srcW = bitmap.width;
      const srcH = bitmap.height;
      if (!srcW || !srcH) return null;

      const longSide = Math.max(srcW, srcH);
      const scale = longSide > maxLongSide ? maxLongSide / longSide : 1;
      const dstW = Math.max(1, Math.round(srcW * scale));
      const dstH = Math.max(1, Math.round(srcH * scale));

      const canvas = document.createElement('canvas');
      canvas.width = dstW;
      canvas.height = dstH;
      const ctx = canvas.getContext('2d', { alpha: false });
      if (!ctx) return null;
      ctx.drawImage(bitmap, 0, 0, dstW, dstH);

      const blob = await new Promise((resolve) => {
        canvas.toBlob(
          (b) => resolve(b),
          'image/jpeg',
          quality
        );
      });
      return blob || null;
    };

    for (const file of files) {
      const folderId = state.selectedFolder.folderId;
      const up = await api(`/folders/${folderId}/photos/upload-url`, {
        method: 'POST',
        headers: { ...folderPasswordHeader(folderId) },
        body: JSON.stringify({ fileName: file.name, contentType: file.type || 'image/jpeg' }),
      });

      let putRes;
      try {
        putRes = await fetch(up.originalUploadUrl, {
          method: 'PUT',
          headers: { 'content-type': file.type || 'image/jpeg' },
          body: file,
        });
      } catch (error) {
        throw new Error(`画像アップロード通信エラー: ${asMessage(error)}`);
      }
      if (!putRes.ok) {
        throw new Error(`画像アップロード失敗(${putRes.status})`);
      }

      const resized = await resizeToJpeg(file, 2048, 0.82);
      if (resized) {
        let previewRes;
        try {
          previewRes = await fetch(up.previewUploadUrl, {
            method: 'PUT',
            headers: { 'content-type': 'image/jpeg' },
            body: resized,
          });
        } catch (error) {
          throw new Error(`リサイズ画像アップロード通信エラー: ${asMessage(error)}`);
        }
        if (!previewRes.ok) {
          throw new Error(`リサイズ画像アップロード失敗(${previewRes.status})`);
        }
      }

      await api(`/folders/${folderId}/photos`, {
        method: 'POST',
        headers: { ...folderPasswordHeader(folderId) },
        body: JSON.stringify({
          photoId: up.photoId,
          originalS3Key: up.originalS3Key,
          previewS3Key: resized ? up.previewS3Key : null,
          fileName: file.name,
        }),
      });
    }

    els.photoFiles.value = '';
    await loadPhotos();
  } catch (error) {
    const message = asMessage(error);
    if (message.includes('APIエラー(402)')) {
      await loadTeamMe();
      if (els.uploadBtn) els.uploadBtn.disabled = Boolean(state.uploadBlocked);
      showError('アップロード停止中です（残量不足）。管理者が容量チケットを追加するか、写真を削除してください。');
      return;
    }
    throw error;
  } finally {
    setUploadLoading(false);
  }
}

async function loadComments(photoId) {
  const data = await api(`/photos/${photoId}/comments`, { method: 'GET' });
  return data.items || [];
}

function canDelete(item) {
  return item.createdBy === state.userKey || state.isAdmin;
}

function formatDateTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString('ja-JP');
}

async function renderPhotos() {
  els.photoList.innerHTML = '';
  for (const photo of state.photos) {
    const card = el('div', { class: 'photo-card' });

    const img = el('img', { src: photo.viewUrl || '', alt: photo.fileName || photo.photoId });
    card.appendChild(img);

    const codeRow = el('div');
    codeRow.appendChild(el('strong', {}, photo.photoCode || 'P---'));
    card.appendChild(codeRow);

    const titleRow = el('div');
    const photoTitle = el('strong', { class: 'js-photo-title' }, photo.fileName || photo.photoId);
    titleRow.appendChild(photoTitle);
    card.appendChild(titleRow);

    card.appendChild(el('div', { class: 'muted' }, `投稿: ${photo.createdByName}`));

    const photoEditWrap = el('div', { class: 'inline-edit js-photo-edit-wrap hidden' });
    if (canDelete(photo)) {
      const actions = el('div', { class: 'comment-actions' });
      const editPhotoBtn = el(
        'button',
        { class: 'icon-btn js-edit-photo', type: 'button', title: '写真名修正' },
        '✎ 写真名'
      );
      const delBtn = el(
        'button',
        { class: 'icon-btn danger js-del-photo', type: 'button', title: '写真削除' },
        '🗑'
      );
      actions.appendChild(editPhotoBtn);
      actions.appendChild(delBtn);
      card.appendChild(actions);
    }
    card.appendChild(photoEditWrap);

    const latestAt = photo.latestCommentAt || '';
    const latestBy = photo.latestCommentBy || '';
    let latestIncomingCommentAt = latestAt && latestBy && latestBy !== state.userKey ? latestAt : '';
    const unread = isUnread(photo.photoId, latestIncomingCommentAt);

    const accordion = el('details', { class: 'comments-accordion' });
    const summary = el('summary', { class: 'comments-summary' });
    summary.appendChild(el('span', { class: 'accordion-marker', 'aria-hidden': 'true' }, '▶'));
    const commentLabel = el('span', {}, 'コメント');
    summary.appendChild(commentLabel);
    if (unread) summary.appendChild(el('span', { class: 'unread-badge' }, '未読'));
    accordion.appendChild(summary);

    const commentWrap = el('div', { class: 'comments' });
    commentWrap.appendChild(el('div', { class: 'muted' }, '開いたら読み込みます'));
    let commentsLoaded = false;

    const renderLoadedComments = (comments) => {
      commentWrap.innerHTML = '';
      comments.forEach((comment) => {
        const stamp = comment.updatedAt ? '修正' : '投稿';
        const stampAt = comment.updatedAt || comment.createdAt;

        const row = el('div', { class: 'comment' });
        const meta = el('div', { class: 'comment-meta' });
        meta.appendChild(
          el('span', { class: 'comment-meta-text' }, `${stamp} ${formatDateTime(stampAt)} ${comment.createdByName}`)
        );
        row.appendChild(meta);
        row.appendChild(el('div', { class: 'comment-text' }, comment.text));

        if (canDelete(comment)) {
          const actions = el('div', { class: 'comment-actions' });
          const editBtn = el('button', { class: 'icon-btn', type: 'button', title: 'コメント修正' }, '✎');
          const deleteBtn = el('button', { class: 'icon-btn danger', type: 'button', title: 'コメント削除' }, '🗑');

          editBtn.onclick = async () => {
            if (row.querySelector('.js-comment-editor')) return;
            const editor = el('div', { class: 'inline-edit js-comment-editor' });
            const ta = el('textarea', { class: 'js-edit-text', rows: '3', style: 'flex:1' });
            ta.value = comment.text || '';
            const saveBtn = el('button', { class: 'js-save-edit', type: 'button' }, '保存');
            const cancelBtn = el('button', { class: 'js-cancel-edit danger', type: 'button' }, '取消');
            editor.appendChild(ta);
            editor.appendChild(saveBtn);
            editor.appendChild(cancelBtn);
            row.appendChild(editor);

            saveBtn.onclick = async () => {
              const nextText = ta.value.trim();
              if (!nextText) return;
              preserveCurrentView(photo.photoId);
              await api(`/photos/${photo.photoId}/comments/${comment.commentId}`, {
                method: 'PUT',
                body: JSON.stringify({ text: nextText }),
              });
              await loadPhotos();
            };

            cancelBtn.onclick = () => {
              editor.remove();
            };
          };

          deleteBtn.onclick = async () => {
            if (!window.confirm('このコメントを削除してよかですか？')) return;
            await api(`/photos/${photo.photoId}/comments/${comment.commentId}`, { method: 'DELETE' });
            await loadPhotos();
          };

          actions.appendChild(editBtn);
          actions.appendChild(deleteBtn);
          row.appendChild(actions);
        }

        commentWrap.appendChild(row);
      });
    };
    accordion.appendChild(commentWrap);

    const addRow = el('div', { class: 'row', style: 'margin-top:8px;' });
    const textArea = el('textarea', {
      class: 'js-comment-text',
      placeholder: 'コメント',
      rows: '2',
      style: 'flex:1',
    });
    const addBtn = el('button', { class: 'js-add-comment', type: 'button' }, '追加');
    addRow.appendChild(textArea);
    addRow.appendChild(addBtn);
    accordion.appendChild(addRow);

    if (state.openAccordions.has(photo.photoId)) {
      accordion.open = true;
    }
    accordion.addEventListener('toggle', async () => {
      if (accordion.open) {
        state.openAccordions.add(photo.photoId);
        if (!commentsLoaded) {
          commentWrap.innerHTML = '';
          commentWrap.appendChild(el('div', { class: 'muted' }, '読み込み中...'));
          const comments = await loadComments(photo.photoId);
          commentsLoaded = true;
          commentLabel.textContent = `コメント (${comments.length})`;
          latestIncomingCommentAt = getLatestIncomingCommentAt(comments);
          renderLoadedComments(comments);
        }
        markAsRead(photo.photoId, latestIncomingCommentAt);
        const badge = summary.querySelector('.unread-badge');
        if (badge) badge.remove();
      } else {
        state.openAccordions.delete(photo.photoId);
      }
      if (state.selectedFolder) {
        await refreshFolderUnread([state.selectedFolder.folderId]);
        renderFolders();
      }
    });

    addBtn.onclick = async () => {
      if (!textArea.value.trim()) return;
      state.openAccordions.add(photo.photoId);
      state.restoreScrollY = window.scrollY;
      await api(`/photos/${photo.photoId}/comments`, {
        method: 'POST',
        body: JSON.stringify({ text: textArea.value.trim() }),
      });
      await loadPhotos();
    };

    const delBtn = card.querySelector('.js-del-photo');
    const editPhotoBtn = card.querySelector('.js-edit-photo');
    if (editPhotoBtn) {
      editPhotoBtn.onclick = async () => {
        if (!photoEditWrap.classList.contains('hidden')) return;
        photoEditWrap.classList.remove('hidden');
        photoEditWrap.innerHTML = '';
        const input = el('input', { class: 'js-photo-name-input' });
        input.value = photo.fileName || '';
        const saveBtn = el('button', { class: 'js-photo-name-save', type: 'button' }, '保存');
        const cancelBtn = el('button', { class: 'js-photo-name-cancel danger', type: 'button' }, '取消');
        photoEditWrap.appendChild(input);
        photoEditWrap.appendChild(saveBtn);
        photoEditWrap.appendChild(cancelBtn);

        saveBtn.onclick = async () => {
          const nextFileName = input.value.trim();
          if (!nextFileName) return;
          preserveCurrentView(photo.photoId);
          await api(`/photos/${photo.photoId}`, {
            method: 'PUT',
            body: JSON.stringify({ fileName: nextFileName }),
          });
          await loadPhotos();
        };

        cancelBtn.onclick = () => {
          photoEditWrap.classList.add('hidden');
          photoEditWrap.innerHTML = '';
          photoTitle.textContent = photo.fileName || photo.photoId;
        };
      };
    }

    if (delBtn) {
      delBtn.onclick = async () => {
        if (!window.confirm('この写真を削除してよかですか？')) return;
        await api(`/photos/${photo.photoId}`, { method: 'DELETE' });
        await loadPhotos();
      };
    }

    card.appendChild(accordion);
    card.appendChild(el('div', { class: 'muted', style: 'margin-top: 6px;' }, unread ? '未読コメントがあります' : '未読コメントなし'));
    els.photoList.appendChild(card);
  }
}

if (els.loginBtn) {
  els.loginBtn.onclick = safeAction(async () => {
    await startLogin();
  }, 'ログイン');
}

if (els.signupBtn) {
  els.signupBtn.onclick = safeAction(async () => {
    await startSignup();
  }, '新規登録');
}

if (els.resetUserBtn) {
  els.resetUserBtn.onclick = safeAction(async () => {
    const current = state.userName || '';
    const next = window.prompt('新しい表示名を入力してください。', current);
    if (next === null) {
      closeMenu();
      return;
    }
    const displayName = next.trim();
    if (!displayName) {
      window.alert('表示名は必須です。');
      closeMenu();
      return;
    }
    await saveDisplayName(displayName);
    state.userName = displayName;
    if (els.currentName) {
      els.currentName.textContent = state.userName;
    }
    showToast('表示名を更新しました。');
    closeMenu();
  }, 'ユーザー名変更');
}

if (els.logoutBtn) {
  els.logoutBtn.onclick = () => {
    resetRoomContext();
    clearAuth();
    closeMenu();

    if (hasCognitoConfig()) {
      const logoutUrl = new URL(`https://${COGNITO_DOMAIN}.auth.${COGNITO_REGION}.amazoncognito.com/logout`);
      logoutUrl.searchParams.set('client_id', COGNITO_CLIENT_ID);
      logoutUrl.searchParams.set('logout_uri', COGNITO_REDIRECT_URI);
      window.location.href = logoutUrl.toString();
      return;
    }

    if (els.userSetup) els.userSetup.classList.remove('hidden');
    if (els.roomSetup) els.roomSetup.classList.add('hidden');
    if (els.app) els.app.classList.add('hidden');
  };
}

if (els.leaveRoomBtn) {
  els.leaveRoomBtn.onclick = safeAction(async () => {
    try {
      const me = await api('/team/me', { method: 'GET' });
      if (me && me.isAdmin) {
        window.alert('管理者は退出できません。お部屋管理から「お部屋を削除（全データ）」を実行してください。');
        closeMenu();
        return;
      }
    } catch (_) {
      // If /team/me fails, keep old behavior.
    }
    // "退出" means: clear active room selection, but keep membership.
    try {
      await api('/team/leave', { method: 'POST' });
    } catch (_) {
      // Ignore; local "leave" still proceeds.
    }
    resetRoomContext();
    closeMenu();
    showRoomSetup();
  }, '退出');
}

if (els.refreshMyRoomsBtn) {
  els.refreshMyRoomsBtn.onclick = safeAction(async () => {
    await loadMyRooms();
  }, '一覧更新');
}

els.createRoomBtn.onclick = async () => {
  clearError();
  const roomName = (els.createRoomName.value || '').trim();
  if (!roomName) {
    showError('お部屋名を入力してください。');
    return;
  }
  try {
    await api('/rooms/create', {
      method: 'POST',
      body: JSON.stringify({ roomName }),
    });
    window.alert(`お部屋：${roomName} が作成されました。`);
    state.roomName = roomName;
    showApp();
  } catch (error) {
    const message = asMessage(error);
    if (message.includes('409')) {
      if (message.includes('already has a room')) {
        window.alert('すでにお部屋を作成済みです（1人1部屋）。別のお部屋は作れません。');
      } else {
        window.alert('同じ部屋名は作成できません。別の部屋名にしてください。');
      }
    } else {
      showError(`お部屋作成失敗: ${message}`);
    }
  }
};

els.createFolderBtn.onclick = safeAction(async () => {
  const title = els.folderTitle.value.trim();
  if (!title) return;
  const folderPassword = String(els.folderPassword?.value || '').trim();
  const created = await api('/folders', {
    method: 'POST',
    body: JSON.stringify({ title, folderPassword: folderPassword || null }),
  });
  els.folderTitle.value = '';
  if (els.folderPassword) els.folderPassword.value = '';
  showToast(`フォルダ：${created.title} を作成しました。`);
  await loadFolders();
  await selectFolderById(created.folderId);
}, 'フォルダ作成');

els.uploadBtn.onclick = safeAction(async () => {
  if (state.isUploading) return;
  await uploadFiles();
}, '写真アップロード');

els.exportBtn.onclick = safeAction(async () => {
  if (!state.selectedFolder) return;
  const preOpened = window.open('', '_blank');
  try {
    const folderId = state.selectedFolder.folderId;
    const res = await api(`/folders/${folderId}/export`, { method: 'POST', headers: { ...folderPasswordHeader(folderId) } });
    if (preOpened) {
      preOpened.location.href = res.downloadUrl;
    } else {
      window.location.href = res.downloadUrl;
    }
  } catch (error) {
    if (preOpened) preOpened.close();
    throw error;
  }
}, 'PPT出力');

if (els.teamAdminBtn && els.teamAdminCard) {
  els.teamAdminBtn.onclick = safeAction(async () => {
    els.teamAdminCard.classList.toggle('hidden');
    closeMenu();
    setTeamAdminMode(!els.teamAdminCard.classList.contains('hidden'));
    await loadAdminPanel();
  }, 'お部屋管理');
}

if (els.teamAdminBackBtn && els.teamAdminCard) {
  els.teamAdminBackBtn.onclick = () => {
    els.teamAdminCard.classList.add('hidden');
    setTeamAdminMode(false);
  };
}

async function purchaseSku(sku) {
  const returnUrl = window.location.origin + window.location.pathname;
  const res = await api('/team/purchase/checkout', {
    method: 'POST',
    body: JSON.stringify({ sku, successUrl: returnUrl, cancelUrl: returnUrl }),
  });
  if (res && res.url) {
    window.location.href = res.url;
    return;
  }
  throw new Error('Stripe決済URLが取得できませんでした。');
}

if (els.purchase1Btn) els.purchase1Btn.onclick = safeAction(() => purchaseSku('1gbm'), '購入');
if (els.purchase10Btn) els.purchase10Btn.onclick = safeAction(() => purchaseSku('10gbm'), '購入');
if (els.purchase50Btn) els.purchase50Btn.onclick = safeAction(() => purchaseSku('50gbm'), '購入');

if (els.deleteTeamBtn) {
  els.deleteTeamBtn.onclick = safeAction(async () => {
    const ok = window.confirm('このお部屋を削除すると、フォルダ/写真/コメント/課金情報も全て消えます。よかですか？');
    if (!ok) return;
    const ok2 = window.confirm('本当によかですか？（取り消せません）');
    if (!ok2) return;
    await api('/team/delete', { method: 'POST' });
    window.alert('お部屋を削除しました。');
    resetRoomContext();
    showRoomSetup();
  }, 'お部屋削除');
}

if (els.folderDeleteBtn) {
  els.folderDeleteBtn.onclick = safeAction(async () => {
    if (!state.selectedFolder) return;
    const ok = window.confirm('このフォルダを削除すると、写真とコメントも消えます。よかですか？');
    if (!ok) return;
    const folderId = state.selectedFolder.folderId;
    await api(`/folders/${folderId}`, { method: 'DELETE', headers: { ...folderPasswordHeader(folderId) } });
    showToast('フォルダを削除しました。');
    state.selectedFolder = null;
    els.folderDetail.classList.add('hidden');
    await loadFolders();
    await loadTeamMe();
  }, 'フォルダ削除');
}

if (els.setFolderPasswordBtn) {
  els.setFolderPasswordBtn.onclick = safeAction(async () => {
    if (!state.selectedFolder) return;
    const folderId = state.selectedFolder.folderId;
    const next = String(els.folderPasswordSet?.value || '').trim();
    await api(`/folders/${folderId}/password`, {
      method: 'PUT',
      headers: { ...folderPasswordHeader(folderId) },
      body: JSON.stringify({ folderPassword: next }),
    });
    if (next) state.folderPasswordById[folderId] = next;
    else delete state.folderPasswordById[folderId];
    if (els.folderPasswordSet) els.folderPasswordSet.value = '';
    showToast('フォルダの鍵を更新しました。');
    await loadFolders();
  }, '鍵設定');
}

window.addEventListener('unhandledrejection', (event) => {
  showError(`予期しないエラー: ${asMessage(event.reason)}`);
});

window.addEventListener('error', (event) => {
  showError(`実行エラー: ${asMessage(event.error || event.message)}`);
});

if (els.toggleThemeBtn) {
  els.toggleThemeBtn.onclick = () => {
    const next = document.body.classList.contains('dark') ? 'light' : 'dark';
    localStorage.setItem('kansa_theme', next);
    applyTheme(next);
    closeMenu();
  };
}

if (els.seasonSelect) {
  els.seasonSelect.onchange = () => {
    const next = normalizeSeason(els.seasonSelect.value);
    localStorage.setItem('kansa_season', next);
    applySeason(next);
    closeMenu();
  };
}

if (els.menuBtn && els.menuPanel) {
  els.menuBtn.onclick = (event) => {
    event.stopPropagation();
    els.menuPanel.classList.toggle('hidden');
  };
  document.addEventListener('click', (event) => {
    if (!els.menuPanel.contains(event.target) && event.target !== els.menuBtn) {
      els.menuPanel.classList.add('hidden');
    }
  });
}

if (els.folderSelect) {
  els.folderSelect.addEventListener('change', async (event) => {
    await safeAction(async () => {
      const folderId = event.target.value;
      await selectFolderById(folderId);
    }, 'フォルダ選択')();
  });
}

initUser().catch((error) => {
  console.error(error);
  showError(`初期化失敗: ${asMessage(error)}`);
});
