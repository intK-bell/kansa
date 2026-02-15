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
  roomPassword: null,
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
  state.idToken = null;
  state.userKey = null;
  state.userName = null;
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
  createRoomPassword: document.querySelector('#create-room-password'),
  createRoomPasswordConfirm: document.querySelector('#create-room-password-confirm'),
  createRoomBtn: document.querySelector('#create-room-btn'),
  enterRoomName: document.querySelector('#enter-room-name'),
  enterRoomPassword: document.querySelector('#enter-room-password'),
  enterRoomBtn: document.querySelector('#enter-room-btn'),
  leaveRoomBtn: document.querySelector('#leave-room-btn'),
  menuBtn: document.querySelector('#menu-btn'),
  menuPanel: document.querySelector('#menu-panel'),
  toggleThemeBtn: document.querySelector('#toggle-theme-btn'),
  seasonSelect: document.querySelector('#season-select'),
  resetUserBtn: document.querySelector('#reset-user-btn'),
  currentName: document.querySelector('#current-name'),
  currentRoom: document.querySelector('#current-room'),
  folderTitle: document.querySelector('#folder-title'),
  createFolderBtn: document.querySelector('#create-folder-btn'),
  folderSelect: document.querySelector('#folder-select'),
  folderDetail: document.querySelector('#folder-detail'),
  folderDetailTitle: document.querySelector('#folder-detail-title'),
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
  await completeLoginFromCallback();
  const idToken = localStorage.getItem('kansa_id_token');
  const roomName = localStorage.getItem('kansa_room_name');
  const roomPassword = localStorage.getItem('kansa_room_password');
  const claims = parseJwt(idToken);
  const now = Math.floor(Date.now() / 1000);

  if (idToken && claims && claims.sub && (!claims.exp || claims.exp > now)) {
    state.idToken = idToken;
    state.userKey = claims.sub;
    state.userName =
      claims['cognito:username'] || claims.name || claims.email || claims.preferred_username || 'unknown';
    await ensureDisplayName();
    if (roomName && roomPassword) {
      state.roomName = roomName;
      state.roomPassword = roomPassword;
      showApp();
    } else {
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
  } else {
    if (els.globalMenuWrap) els.globalMenuWrap.classList.add('hidden');
    if (els.logoutBtn) els.logoutBtn.classList.add('hidden');
  }
  setMenuActionVisibility(false);
  closeMenu();
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
  loadFolders();
}

function headers(method = 'GET') {
  const upper = String(method || 'GET').toUpperCase();
  const authHeader = state.idToken ? { Authorization: `Bearer ${state.idToken}` } : {};
  const safeRoomName = encodeURIComponent(state.roomName || '');
  const safeRoomPassword = encodeURIComponent(state.roomPassword || '');
  const roomHeaders =
    state.roomName && state.roomPassword
      ? {
          'x-room-name': safeRoomName,
          'x-room-password': safeRoomPassword,
        }
      : {};
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
    throw new Error(`APIエラー(${res.status}): ${text || 'unknown error'}`);
  }

  return res.json();
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
    const commentsData = await api(`/photos/${photo.photoId}/comments`, { method: 'GET' });
    const comments = commentsData.items || [];
    const latestIncoming = getLatestIncomingCommentAt(comments);
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
    option.textContent = `${folder.folderCode || 'F---'} ${folder.title}${unread ? ' ●新着' : ''}`;
    els.folderSelect.appendChild(option);
  });

  if (state.selectedFolder) {
    els.folderSelect.value = state.selectedFolder.folderId;
  }
}

async function selectFolder(folder) {
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
  const data = await api(`/folders/${state.selectedFolder.folderId}/photos`, { method: 'GET' });
  state.photos = data.items || [];
  await renderPhotos();
  await refreshFolderUnread([state.selectedFolder.folderId]);
  renderFolders();
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
      const up = await api(`/folders/${state.selectedFolder.folderId}/photos/upload-url`, {
        method: 'POST',
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

      await api(`/folders/${state.selectedFolder.folderId}/photos`, {
        method: 'POST',
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
  } finally {
    setUploadLoading(false);
  }
}

async function loadComments(photoId) {
  const data = await api(`/photos/${photoId}/comments`, { method: 'GET' });
  return data.items || [];
}

function canDelete(item) {
  return item.createdBy === state.userKey;
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

    const comments = await loadComments(photo.photoId);
    const latestIncomingCommentAt = getLatestIncomingCommentAt(comments);
    const unread = isUnread(photo.photoId, latestIncomingCommentAt);

    const accordion = el('details', { class: 'comments-accordion' });
    const summary = el('summary', { class: 'comments-summary' });
    summary.appendChild(el('span', { class: 'accordion-marker', 'aria-hidden': 'true' }, '▶'));
    summary.appendChild(el('span', {}, `コメント (${comments.length})`));
    if (unread) summary.appendChild(el('span', { class: 'unread-badge' }, '未読'));
    accordion.appendChild(summary);

    const commentWrap = el('div', { class: 'comments' });
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
    localStorage.removeItem('kansa_room_name');
    localStorage.removeItem('kansa_room_password');
    state.roomName = null;
    state.roomPassword = null;
    state.selectedFolder = null;
    state.folders = [];
    state.photos = [];
    state.openAccordions.clear();
    state.restoreScrollY = null;
    clearAuth();
    closeMenu();
    if (els.folderDetail) els.folderDetail.classList.add('hidden');

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
  els.leaveRoomBtn.onclick = () => {
    localStorage.removeItem('kansa_room_name');
    localStorage.removeItem('kansa_room_password');
    state.roomName = null;
    state.roomPassword = null;
    state.selectedFolder = null;
    state.folders = [];
    state.photos = [];
    state.openAccordions.clear();
    state.restoreScrollY = null;
    els.folderDetail.classList.add('hidden');
    showRoomSetup();
  };
}

els.createRoomBtn.onclick = async () => {
  clearError();
  const roomName = (els.createRoomName.value || '').trim();
  const roomPassword = (els.createRoomPassword.value || '').trim();
  const roomPasswordConfirm = (els.createRoomPasswordConfirm.value || '').trim();
  if (!roomName || !roomPassword || !roomPasswordConfirm) {
    showError('お部屋名とパスワードを入力してください。');
    return;
  }
  if (roomPassword !== roomPasswordConfirm) {
    showError('パスワードと確認用パスワードが一致しません。');
    return;
  }
  try {
    await api('/rooms/create', {
      method: 'POST',
      body: JSON.stringify({ roomName, roomPassword }),
    });
    window.alert(`お部屋：${roomName} が作成されました。`);
    state.roomName = roomName;
    state.roomPassword = roomPassword;
    localStorage.setItem('kansa_room_name', roomName);
    localStorage.setItem('kansa_room_password', roomPassword);
    showApp();
  } catch (error) {
    const message = asMessage(error);
    if (message.includes('409')) {
      window.alert('同じ部屋名は作成できません。別の部屋名にしてください。');
    } else {
      showError(`お部屋作成失敗: ${message}`);
    }
  }
};

els.enterRoomBtn.onclick = async () => {
  clearError();
  const roomName = (els.enterRoomName.value || '').trim();
  const roomPassword = (els.enterRoomPassword.value || '').trim();
  if (!roomName || !roomPassword) {
    showError('お部屋名とパスワードを入力してください。');
    return;
  }
  try {
    await api('/rooms/enter', {
      method: 'POST',
      body: JSON.stringify({ roomName, roomPassword }),
    });
    window.alert(`お部屋：${roomName} に入室しました。`);
    state.roomName = roomName;
    state.roomPassword = roomPassword;
    localStorage.setItem('kansa_room_name', roomName);
    localStorage.setItem('kansa_room_password', roomPassword);
    showApp();
  } catch (_) {
    window.alert('お部屋名またはパスワードが違います。');
  }
};

els.createFolderBtn.onclick = safeAction(async () => {
  const title = els.folderTitle.value.trim();
  if (!title) return;
  const created = await api('/folders', { method: 'POST', body: JSON.stringify({ title }) });
  els.folderTitle.value = '';
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
    const res = await api(`/folders/${state.selectedFolder.folderId}/export`, { method: 'POST' });
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
