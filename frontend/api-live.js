import {
  ACCOUNT_ROOM_API_METHODS, FOLDER_API_METHODS, PHOTO_API_METHODS, QUEST_API_METHODS,
  SEARCH_EXPORT_API_METHODS, TEAM_INVITE_BILLING_API_METHODS, assertApiMethods,
} from './app-api-contract.js';
import { normalizeCognitoDomain } from './app-core.js';

export function resolveLiveEnvironment(windowRef = window) {
  const config = windowRef.KANSA_CONFIG || {};
  const storage = windowRef.localStorage;
  return {
    apiBase: storage.getItem('kansa_api_base') || config.apiBase || 'http://127.0.0.1:3000',
    cognito: {
      region: storage.getItem('kansa_cognito_region') || config.cognitoRegion || '',
      domain: normalizeCognitoDomain(storage.getItem('kansa_cognito_domain') || config.cognitoDomain || ''),
      clientId: storage.getItem('kansa_cognito_client_id') || config.cognitoClientId || '',
      redirectUri: config.cognitoRedirectUri || storage.getItem('kansa_cognito_redirect_uri') || windowRef.location.origin,
    },
  };
}

export function createCognitoClient({
  region, domain, clientId, redirectUri,
  windowRef = window, fetchImpl = fetch,
  translate = (label) => label,
  formatMessage = (label, values) => label.replace('{message}', values.message),
} = {}) {
  const storage = windowRef.localStorage;
  const configured = () => Boolean(region && domain && clientId && redirectUri);
  const randomString = (length = 64) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
    const bytes = new Uint8Array(length);
    windowRef.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => chars[byte % chars.length]).join('');
  };
  const challengeFor = async (verifier) => {
    if (!windowRef.crypto?.subtle?.digest) return { method: 'plain', challenge: verifier };
    const hash = await windowRef.crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    let binary = '';
    new Uint8Array(hash).forEach((byte) => { binary += String.fromCharCode(byte); });
    return { method: 'S256', challenge: windowRef.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') };
  };
  const start = async (path) => {
    if (!configured()) throw new Error(translate('Cognito設定が不足しています。config.jsを確認してください。'));
    const state = randomString(32);
    const verifier = randomString(64);
    storage.setItem('kansa_oauth_state', state);
    storage.setItem('kansa_oauth_code_verifier', verifier);
    const url = new URL(`https://${domain}.auth.${region}.amazoncognito.com/${path}`);
    url.searchParams.set('state', state);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('redirect_uri', redirectUri);
    const pkce = await challengeFor(verifier);
    url.searchParams.set('code_challenge_method', pkce.method);
    url.searchParams.set('code_challenge', pkce.challenge);
    windowRef.location.href = url.toString();
  };
  const clearCallback = (url) => {
    storage.removeItem('kansa_oauth_state');
    storage.removeItem('kansa_oauth_code_verifier');
    url.searchParams.delete('code');
    url.searchParams.delete('state');
    windowRef.history.replaceState({}, windowRef.document.title, url.pathname + url.search + url.hash);
  };
  return {
    isConfigured: configured,
    startLogin: () => start('oauth2/authorize'),
    startSignup: () => start('signup'),
    logoutUrl: () => {
      const url = new URL(`https://${domain}.auth.${region}.amazoncognito.com/logout`);
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('logout_uri', redirectUri);
      return url.toString();
    },
    completeLogin: async () => {
      const url = new URL(windowRef.location.href);
      const code = url.searchParams.get('code');
      if (!code) return false;
      const expectedState = storage.getItem('kansa_oauth_state');
      const verifier = storage.getItem('kansa_oauth_code_verifier');
      if (!expectedState || !verifier || url.searchParams.get('state') !== expectedState) {
        clearCallback(url);
        return false;
      }
      const body = new URLSearchParams({
        grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirectUri, code, code_verifier: verifier,
      });
      const response = await fetchImpl(`https://${domain}.auth.${region}.amazoncognito.com/oauth2/token`, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: body.toString(),
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(formatMessage('Cognitoトークン取得失敗: {message}', { message: text || response.status }));
      }
      const tokens = await response.json();
      if (!tokens.id_token) throw new Error(translate('Cognitoトークンが取得できませんでした。'));
      storage.setItem('kansa_id_token', tokens.id_token);
      clearCallback(url);
      return true;
    },
  };
}

export function createLiveRequest({
  baseUrl,
  getHeaders = () => ({}),
  fetchImpl = fetch,
  clearError = () => undefined,
  onUnauthorized = () => undefined,
  onNoActiveRoom = () => undefined,
  formatNetworkError = (message) => `ネットワークエラー: ${message}`,
} = {}) {
  if (typeof fetchImpl !== 'function') throw new TypeError('Live request fetch must be a function.');
  return async function liveRequest(path, options = {}) {
    clearError();
    const method = String(options.method || 'GET').toUpperCase();
    let response;
    try {
      response = await fetchImpl(`${baseUrl || ''}${path}`, {
        ...options,
        headers: { ...(options.headers || {}), ...getHeaders(method) },
      });
    } catch (error) {
      throw new Error(formatNetworkError(error?.message || String(error)));
    }
    if (!response.ok) {
      const text = await response.text();
      let body = null;
      try {
        body = text ? JSON.parse(text) : null;
      } catch (_) {
        body = null;
      }
      if (response.status === 401) onUnauthorized();
      if (response.status === 403 && text.includes('"no active room"')) onNoActiveRoom();
      const error = new Error(`APIエラー(${response.status}): ${text || 'unknown error'}`);
      error.status = response.status;
      error.body = body;
      throw error;
    }
    return response.json();
  };
}

export function createLiveApi(request, getFolderHeaders = () => ({}), fetchImpl = fetch) {
  if (typeof request !== 'function') throw new TypeError('Live API request must be a function.');
  return assertApiMethods({
    getCurrentUser: () => request('/me', { method: 'GET' }),
    saveDisplayName: (displayName) => request('/me/display-name', { method: 'PUT', body: JSON.stringify({ displayName }) }),
    listRooms: () => request('/rooms/mine', { method: 'GET' }),
    switchRoom: (roomId) => request('/rooms/switch', { method: 'POST', body: JSON.stringify({ roomId }) }),
    createRoom: (roomName) => request('/rooms/create', { method: 'POST', body: JSON.stringify({ roomName }) }),
    listFolders: () => request('/folders', { method: 'GET' }),
    createFolder: ({ title, mode, folderPassword }) =>
      request('/folders', { method: 'POST', body: JSON.stringify({ title, mode, folderPassword: folderPassword || null }) }),
    deleteFolder: (folderId) => request(`/folders/${folderId}`, { method: 'DELETE', headers: getFolderHeaders(folderId) }),
    setFolderPassword: (folderId, folderPassword) =>
      request(`/folders/${folderId}/password`, {
        method: 'PUT', headers: getFolderHeaders(folderId), body: JSON.stringify({ folderPassword }),
      }),
    listFolderMembers: (folderId) => request(`/folders/${encodeURIComponent(folderId)}/members`, { method: 'GET' }),
    removeFolderMember: (folderId, userKey) =>
      request(`/folders/${encodeURIComponent(folderId)}/members/${encodeURIComponent(userKey)}`, { method: 'DELETE' }),
    listPhotos: (folderId) =>
      request(`/folders/${folderId}/photos`, { method: 'GET', headers: getFolderHeaders(folderId) }),
    uploadPhoto: async ({ folderId, file, previewBlob, logTag, initialComment, questId }) => {
      const contentType = file.type || 'image/jpeg';
      const upload = await request(`/folders/${folderId}/photos/upload-url`, {
        method: 'POST',
        headers: getFolderHeaders(folderId),
        body: JSON.stringify({ fileName: file.name, contentType, size: file.size || 0 }),
      });
      let response;
      try {
        response = await fetchImpl(upload.originalUploadUrl, {
          method: 'PUT', headers: { 'content-type': contentType }, body: file,
        });
      } catch (error) {
        throw new Error(`画像アップロード通信エラー: ${error?.message || 'unknown error'}`);
      }
      if (!response.ok) throw new Error(`画像アップロード失敗(${response.status})`);
      if (previewBlob) {
        try {
          response = await fetchImpl(upload.previewUploadUrl, {
            method: 'PUT', headers: { 'content-type': 'image/jpeg' }, body: previewBlob,
          });
        } catch (error) {
          throw new Error(`リサイズ画像アップロード通信エラー: ${error?.message || 'unknown error'}`);
        }
        if (!response.ok) throw new Error(`リサイズ画像アップロード失敗(${response.status})`);
      }
      return request(`/folders/${folderId}/photos`, {
        method: 'POST',
        headers: getFolderHeaders(folderId),
        body: JSON.stringify({
          photoId: upload.photoId,
          originalS3Key: upload.originalS3Key,
          previewS3Key: previewBlob ? upload.previewS3Key : null,
          logTag,
          initialComment: questId ? null : initialComment || null,
          questId: questId || null,
        }),
      });
    },
    updatePhoto: (photoId, changes) =>
      request(`/photos/${photoId}`, { method: 'PUT', body: JSON.stringify(changes) }),
    deletePhoto: (photoId) => request(`/photos/${photoId}`, { method: 'DELETE' }),
    listPhotoComments: (photoId) => request(`/photos/${photoId}/comments`, { method: 'GET' }),
    createPhotoComment: (photoId, text) =>
      request(`/photos/${photoId}/comments`, { method: 'POST', body: JSON.stringify({ text }) }),
    updatePhotoComment: (photoId, commentId, text) =>
      request(`/photos/${photoId}/comments/${commentId}`, { method: 'PUT', body: JSON.stringify({ text }) }),
    deletePhotoComment: (photoId, commentId) =>
      request(`/photos/${photoId}/comments/${commentId}`, { method: 'DELETE' }),
    listQuests: (folderId) =>
      request(`/folders/${folderId}/quests`, { method: 'GET', headers: getFolderHeaders(folderId) }),
    createQuest: (folderId, text) =>
      request(`/folders/${folderId}/quests`, {
        method: 'POST', headers: getFolderHeaders(folderId), body: JSON.stringify({ text }),
      }),
    updateQuest: (questId, changes, folderId) =>
      request(`/quests/${questId}`, { method: 'PUT', headers: getFolderHeaders(folderId), body: JSON.stringify(changes) }),
    deleteQuest: (questId, folderId) =>
      request(`/quests/${questId}`, { method: 'DELETE', headers: getFolderHeaders(folderId) }),
    createQuestComment: (questId, text, folderId) =>
      request(`/quests/${questId}/comments`, {
        method: 'POST', headers: getFolderHeaders(folderId), body: JSON.stringify({ text }),
      }),
    deleteQuestComment: (questId, commentId, folderId) =>
      request(`/quests/${questId}/comments/${commentId}`, { method: 'DELETE', headers: getFolderHeaders(folderId) }),
    searchPhotos: ({ roomId, logTag = 'all', keyword = '', limit = 50, sort = 'newest' }) => {
      const params = new URLSearchParams({ logTag, sort, limit: String(limit) });
      if (keyword) params.set('keyword', keyword);
      return request(`/rooms/${encodeURIComponent(roomId)}/photos/search?${params.toString()}`, { method: 'GET' });
    },
    exportFolder: (folderId, format) =>
      request(`/folders/${folderId}/export`, {
        method: 'POST', headers: getFolderHeaders(folderId), body: JSON.stringify({ format }),
      }),
    getTeam: () => request('/team/me', { method: 'GET' }),
    listTeamMembers: () => request('/team/members', { method: 'GET' }),
    updateTeamMember: (userKey, changes) =>
      request(`/team/members/${encodeURIComponent(userKey)}`, { method: 'PUT', body: JSON.stringify(changes) }),
    leaveTeam: () => request('/team/leave', { method: 'POST' }),
    deleteTeam: () => request('/team/delete', { method: 'POST' }),
    deleteAccount: () => request('/account/delete', { method: 'POST', body: JSON.stringify({}) }),
    createInvite: (folderId = null) =>
      request('/invites/create', { method: 'POST', body: JSON.stringify(folderId ? { folderId } : {}) }),
    acceptInvite: (token) => request('/invites/accept', { method: 'POST', body: JSON.stringify({ token }) }),
    revokeInvite: (token) => request('/invites/revoke', { method: 'POST', body: JSON.stringify({ token }) }),
    getSubscription: () => request('/team/subscription', { method: 'GET' }),
    startSubscriptionCheckout: ({ plan, successUrl, cancelUrl }) =>
      request('/team/subscription/checkout', {
        method: 'POST', body: JSON.stringify({ plan, successUrl, cancelUrl }),
      }),
    changeSubscription: ({ action, targetPlan }) =>
      request('/team/subscription/change', {
        method: 'POST', body: JSON.stringify(targetPlan ? { action, targetPlan } : { action }),
      }),
  }, [
    ...ACCOUNT_ROOM_API_METHODS, ...FOLDER_API_METHODS, ...PHOTO_API_METHODS,
    ...QUEST_API_METHODS, ...SEARCH_EXPORT_API_METHODS, ...TEAM_INVITE_BILLING_API_METHODS,
  ], 'Live API adapter');
}
