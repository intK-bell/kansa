import {
  ACCOUNT_ROOM_API_METHODS, FOLDER_API_METHODS, PHOTO_API_METHODS, QUEST_API_METHODS,
  SEARCH_EXPORT_API_METHODS, TEAM_INVITE_BILLING_API_METHODS, assertApiMethods,
} from './app-api-contract.js';

export function createDemoApi(request, getFolderHeaders = () => ({})) {
  if (typeof request !== 'function') throw new TypeError('Demo API request must be a function.');
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
    uploadPhoto: ({ folderId, fileName, logTag, initialComment, questId }) =>
      request(`/folders/${folderId}/photos`, {
        method: 'POST',
        headers: getFolderHeaders(folderId),
        body: JSON.stringify({
          fileName,
          logTag,
          initialComment: questId ? null : initialComment || null,
          questId: questId || null,
        }),
      }),
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
  ], 'Demo API adapter');
}

export function createDemoBackend({
  store,
  planBytes,
  userKey,
  now,
  createPhoto,
  createPhotoVisual,
  buildExportUrl,
  planRank,
  translate,
  defaultLogTag,
  normalizeFolderMode,
  normalizeLogTag,
  questStatusText,
}) {
  const getActiveRoom = () =>
    store.rooms.find((room) => room.roomId === store.activeRoomId) || null;
  const findFolder = (folderId) => {
    for (const room of store.rooms) {
      const folder = room.folders.find((item) => item.folderId === folderId);
      if (folder) return { room, folder };
    }
    return { room: null, folder: null };
  };
  const findPhoto = (photoId) => {
    for (const room of store.rooms) {
      for (const folder of room.folders) {
        const photo = folder.photos.find((item) => item.photoId === photoId);
        if (photo) return { room, folder, photo };
      }
    }
    return { room: null, folder: null, photo: null };
  };
  const findQuest = (questId) => {
    for (const room of store.rooms) {
      for (const folder of room.folders) {
        const quest = (folder.quests || []).find((item) => item.questId === questId);
        if (quest) return { room, folder, quest };
      }
    }
    return { room: null, folder: null, quest: null };
  };
  const recalculate = () => {
    store.rooms.forEach((room) => {
      room.folders.forEach((folder, folderIndex) => {
        folder.folderCode = folder.folderCode || `F-${String(folderIndex + 1).padStart(3, '0')}`;
        folder.mode = normalizeFolderMode(folder.mode);
        folder.photos = Array.isArray(folder.photos) ? folder.photos : [];
        folder.quests = Array.isArray(folder.quests) ? folder.quests : [];
        folder.usageBytes = folder.photos.reduce((sum, photo, photoIndex) => {
          photo.photoCode = photo.photoCode || `P-${String(photoIndex + 1).padStart(3, '0')}`;
          const latest = (photo.comments || []).reduce((memo, comment) => {
            const stamp = comment.updatedAt || comment.createdAt || '';
            return !memo || stamp > memo.stamp ? { stamp, by: comment.createdBy || '' } : memo;
          }, null);
          photo.latestCommentAt = latest ? latest.stamp : '';
          photo.latestCommentBy = latest ? latest.by : '';
          return sum + Number(photo.sizeBytes || 0);
        }, 0);
        folder.quests.forEach((quest, questIndex) => {
          quest.questCode = quest.questCode || `${folder.folderCode || 'F-000'}-Q${String(questIndex + 1).padStart(3, '0')}`;
          quest.status = ['open', 'shooting', 'done'].includes(quest.status) ? quest.status : 'open';
          const latest = (quest.comments || []).reduce((memo, comment) => {
            const stamp = comment.updatedAt || comment.createdAt || '';
            return !memo || stamp > memo.stamp ? { stamp, by: comment.createdBy || '' } : memo;
          }, null);
          quest.latestCommentAt = latest ? latest.stamp : '';
          quest.latestCommentBy = latest ? latest.by : '';
        });
      });
      const usageBytes = room.folders.reduce((sum, folder) => sum + Number(folder.usageBytes || 0), 0);
      const currentPlan = String(room.subscriptionPlan || 'FREE').toUpperCase();
      const freeBytes = planBytes[currentPlan] || planBytes.FREE;
      room.billing = {
        usageBytes,
        freeBytes,
        billingMode: currentPlan === 'FREE' ? 'prepaid' : 'subscription',
        subscription: { currentPlan },
      };
      room.uploadBlocked = usageBytes >= freeBytes;
    });
  };
  const roomResponse = (room) => {
    const currentMember = room.members.find((member) => member.userKey === userKey) || {
      userKey,
      displayName: store.me.displayName,
      role: room.currentUserRole || 'member',
      status: room.memberStatus || 'active',
      folderScope: 'all',
    };
    return {
      roomId: room.roomId,
      roomName: room.roomName,
      role: currentMember.role,
      memberStatus: currentMember.status,
      folderScope: currentMember.folderScope || 'all',
    };
  };
  const folderSummary = (folder) => ({
    folderId: folder.folderId,
    folderCode: folder.folderCode,
    title: folder.title,
    createdBy: folder.createdBy,
    createdByName: folder.createdByName,
    mode: normalizeFolderMode(folder.mode),
    usageBytes: folder.usageBytes || 0,
    hasPassword: Boolean(folder.hasPassword),
  });
  const photoSummary = (photo) => ({
    photoId: photo.photoId,
    photoCode: photo.photoCode,
    fileName: photo.fileName,
    originalName: photo.originalName || photo.fileName,
    logTag: normalizeLogTag(photo.logTag),
    createdBy: photo.createdBy,
    createdByName: photo.createdByName,
    createdAt: photo.createdAt,
    viewUrl: photo.viewUrl,
    previewUrl: photo.previewUrl || photo.viewUrl,
    questId: photo.questId || null,
    questText: photo.questText || '',
    questCode: photo.questCode || null,
    latestCommentAt: photo.latestCommentAt || '',
    latestCommentBy: photo.latestCommentBy || '',
  });
  const commentSummary = (comment) => ({
    commentId: comment.commentId,
    text: comment.text,
    createdAt: comment.createdAt,
    updatedAt: comment.updatedAt || null,
    createdBy: comment.createdBy,
    createdByName: comment.createdByName,
  });
  const questSummary = (quest, folder) => ({
    questId: quest.questId,
    questCode: quest.questCode,
    folderId: folder.folderId,
    folderCode: folder.folderCode,
    text: quest.text,
    status: quest.status || 'open',
    statusLabel: questStatusText(quest.status),
    createdBy: quest.createdBy,
    createdByName: quest.createdByName,
    createdAt: quest.createdAt,
    updatedAt: quest.updatedAt || null,
    latestCommentAt: quest.latestCommentAt || '',
    latestCommentBy: quest.latestCommentBy || '',
    photos: (folder.photos || []).filter((photo) => photo.questId === quest.questId).map(photoSummary),
    comments: (quest.comments || []).map(commentSummary),
  });

  return {
    store, getActiveRoom, findFolder, findPhoto, findQuest, recalculate,
    roomResponse, folderSummary, photoSummary, questSummary, commentSummary,
    planBytes, userKey, now, createPhoto, createPhotoVisual, buildExportUrl,
    planRank, translate, defaultLogTag, normalizeFolderMode, normalizeLogTag,
  };
}

export function createDemoRequest(context) {
  const {
    clearError,
    demoBackend,
  } = context;
  const {
    store: demoStore,
    getActiveRoom: demoGetActiveRoom,
    findFolder: demoFindFolder,
    findPhoto: demoFindPhoto,
    findQuest: demoFindQuest,
    recalculate: demoRecalculate,
    roomResponse: demoRoomResponse,
    folderSummary: demoFolderSummary,
    photoSummary: demoPhotoSummary,
    questSummary: demoQuestSummary,
    commentSummary: demoCommentSummary,
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
  } = demoBackend;
  const demoClone = (value) => {
    if (typeof structuredClone === 'function') return structuredClone(value);
    return JSON.parse(JSON.stringify(value));
  };
  const demoError = (status, message, body = null) => {
    const error = new Error(`APIエラー(${status}): ${message}`);
    error.status = status;
    error.body = body;
    return error;
  };
  const demoSearchablePhotosForCurrentRoom = () => {
    const room = demoGetActiveRoom();
    if (!room) return [];
    return (room.folders || []).flatMap((folder) =>
      (folder.photos || []).map((photo) => ({
        ...demoPhotoSummary(photo),
        containerNumber: folder.title,
        folderTitle: folder.title,
        folderMode: normalizeFolderMode(folder.mode),
        commentText: (photo.comments || []).map((comment) => comment.text).join(' '),
      }))
    );
  };
  const UNHANDLED = Symbol('demo request not handled');
  const handleSearchRequest = ({ path, method }) => {
    if (!/^\/rooms\/[^/]+\/photos\/search(?:\?|$)/.test(path) || method !== 'GET') return UNHANDLED;
    const requestUrl = new URL(path, 'https://demo.local');
    const logTag = requestUrl.searchParams.get('logTag') || 'all';
    const keyword = String(requestUrl.searchParams.get('keyword') || '').trim().toLowerCase();
    const limit = Math.max(1, Math.min(100, Number(requestUrl.searchParams.get('limit') || 50)));
    const items = demoSearchablePhotosForCurrentRoom()
      .filter((photo) => logTag === 'all' || normalizeLogTag(photo.logTag, 'other') === logTag)
      .filter((photo) => {
        if (!keyword) return true;
        return [
          photo.containerNumber, photo.folderTitle, photo.fileName, photo.originalName,
          photo.createdByName, photo.createdBy, photo.questText, photo.commentText,
        ].filter(Boolean).join(' ').toLowerCase().includes(keyword);
      })
      .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
      .slice(0, limit);
    return { items, nextToken: null };
  };
  const handleAccountRequest = ({ path, method, body }) => {
    if (path === '/me' && method === 'GET') {
      return { userKey: DEMO_USER_KEY, displayName: demoStore.me.displayName };
    }
    if (path === '/me/display-name' && method === 'PUT') {
      demoStore.me.displayName = String(body.displayName || '').trim() || demoStore.me.displayName;
      demoStore.rooms.forEach((room) => {
        room.members.forEach((member) => {
          if (member.userKey === DEMO_USER_KEY) member.displayName = demoStore.me.displayName;
        });
        room.folders.forEach((folder) => {
          folder.photos.forEach((photo) => {
            if (photo.createdBy === DEMO_USER_KEY) photo.createdByName = demoStore.me.displayName;
            photo.comments.forEach((comment) => {
              if (comment.createdBy === DEMO_USER_KEY) comment.createdByName = demoStore.me.displayName;
            });
          });
        });
      });
      return { ok: true };
    }
    if (path === '/account/delete' && method === 'POST') return { ok: true };
    return UNHANDLED;
  };
  const handleInviteBillingRequest = ({ path, method, body, activeRoom }) => {
    if (path === '/invites/create' && method === 'POST') {
      if (!activeRoom) throw demoError(404, 'no active room');
      const token = `demo-invite-${demoStore.inviteCounter++}`;
      activeRoom.inviteToken = token;
      activeRoom.inviteFolderId = body.folderId || null;
      return { token, inviteScope: body.folderId ? 'folder' : 'room', folderId: body.folderId || null };
    }
    if (path === '/invites/revoke' && method === 'POST') {
      if (activeRoom) {
        activeRoom.inviteToken = null;
        activeRoom.inviteFolderId = null;
      }
      return { ok: true };
    }
    if (path !== '/team/subscription/change' || method !== 'POST') return UNHANDLED;
    if (!activeRoom) throw demoError(404, 'no active room');
    const action = String(body.action || '').toLowerCase();
    if (action === 'free') {
      const usageBytes = Number(activeRoom.billing?.usageBytes || 0);
      if (usageBytes > DEMO_PLAN_BYTES.FREE || activeRoom.folders.length > 2) {
        throw demoError(400, 'free plan requirements not met', {
          code: 'FREE_PLAN_REQUIREMENTS_NOT_MET',
          constraints: {
            usageBytes,
            maxUsageBytes: DEMO_PLAN_BYTES.FREE,
            folderCount: activeRoom.folders.length,
            maxFolderCount: 2,
          },
        });
      }
      activeRoom.subscriptionPlan = 'FREE';
      demoRecalculate();
    } else if (action === 'upgrade' || action === 'downgrade') {
      const targetPlan = String(body.targetPlan || '').toUpperCase();
      const currentPlan = String(activeRoom.subscriptionPlan || 'FREE').toUpperCase();
      const targetRank = subscriptionPlanRank(targetPlan);
      const currentRank = subscriptionPlanRank(currentPlan);
      if (!targetRank) throw demoError(400, 'targetPlan is required');
      if (action === 'upgrade' && targetRank <= currentRank) throw demoError(400, 'targetPlan must be higher than currentPlan');
      if (action === 'downgrade' && targetRank >= currentRank) throw demoError(400, 'targetPlan must be lower than currentPlan');
      if (action === 'downgrade' && Number(activeRoom.billing?.usageBytes || 0) > DEMO_PLAN_BYTES[targetPlan]) {
        throw demoError(400, 'current usage exceeds target plan limit; cannot schedule downgrade');
      }
      activeRoom.subscriptionPlan = targetPlan;
      demoRecalculate();
    }
    return { ok: true, billing: demoClone(activeRoom.billing) };
  };
  const handleRoomTeamRequest = ({ path, method, body, activeRoom }) => {
    if (path === '/team/me' && method === 'GET') {
      if (!activeRoom) return { hasRoom: false };
      const currentMember = activeRoom.members.find((member) => member.userKey === DEMO_USER_KEY);
      if (!currentMember || currentMember.status === 'left') return { hasRoom: false };
      const owner = activeRoom.members.find((member) => member.role === 'admin') || currentMember;
      return {
        hasRoom: true, roomId: activeRoom.roomId, roomName: activeRoom.roomName,
        role: currentMember.role, isAdmin: currentMember.role === 'admin',
        uploadBlocked: Boolean(activeRoom.uploadBlocked), billing: demoClone(activeRoom.billing),
        ownerUserKey: owner.userKey,
      };
    }
    if (path === '/rooms/mine' && method === 'GET') {
      return {
        activeRoomId: demoStore.activeRoomId || '',
        items: demoStore.rooms.map((room) => {
          const roomView = demoRoomResponse(room);
          return {
            roomId: room.roomId, roomName: room.roomName, role: roomView.role,
            memberStatus: roomView.memberStatus, folderScope: roomView.folderScope,
          };
        }).filter((room) => room.memberStatus !== 'left'),
      };
    }
    if (path === '/rooms/switch' && method === 'POST') {
      const target = demoStore.rooms.find((room) => room.roomId === body.roomId);
      if (!target) throw demoError(404, 'room not found');
      const currentMember = target.members.find((member) => member.userKey === DEMO_USER_KEY);
      if (!currentMember || currentMember.status === 'left' || currentMember.status === 'disabled') {
        throw demoError(403, 'room disabled');
      }
      demoStore.activeRoomId = target.roomId;
      return { roomId: target.roomId, roomName: target.roomName };
    }
    if (path === '/rooms/create' && method === 'POST') {
      const roomName = String(body.roomName || '').trim();
      if (!roomName) throw demoError(400, 'room name required');
      const hasOwnedRoom = demoStore.rooms.some((room) => {
        const currentMember = room.members.find((member) => member.userKey === DEMO_USER_KEY);
        return currentMember && currentMember.role === 'admin' && currentMember.status !== 'left' && currentMember.status !== 'disabled';
      });
      if (hasOwnedRoom) throw demoError(409, 'already has a room');
      demoStore.roomCounter += 1;
      const room = {
        roomId: `room-demo-${demoStore.roomCounter}`, roomName, currentUserRole: 'admin',
        memberStatus: 'active', subscriptionPlan: 'FREE', inviteToken: null,
        members: [{ userKey: DEMO_USER_KEY, displayName: demoStore.me.displayName, role: 'admin', status: 'active', folderScope: 'all' }],
        folders: [],
      };
      demoStore.rooms.push(room);
      demoStore.activeRoomId = room.roomId;
      demoRecalculate();
      return { roomId: room.roomId, roomName: room.roomName };
    }
    if (path === '/team/leave' && method === 'POST') {
      if (!activeRoom) return { ok: true };
      const currentMember = activeRoom.members.find((member) => member.userKey === DEMO_USER_KEY);
      if (currentMember) currentMember.status = 'left';
      const fallback = demoStore.rooms.find((room) => {
        const member = room.members.find((item) => item.userKey === DEMO_USER_KEY);
        return member && member.status === 'active' && room.roomId !== activeRoom.roomId;
      });
      demoStore.activeRoomId = fallback ? fallback.roomId : null;
      demoRecalculate();
      return { ok: true };
    }
    if (path === '/team/members' && method === 'GET') {
      if (!activeRoom) throw demoError(404, 'no active room');
      return {
        items: activeRoom.members.filter((member) => {
          if (member.status === 'left') return false;
          if (member.role === 'admin') return true;
          return member.folderScope !== 'invited';
        }).map((member) => demoClone(member)),
      };
    }
    if (path.startsWith('/team/members/') && method === 'PUT') {
      if (!activeRoom) throw demoError(404, 'no active room');
      const userKey = decodeURIComponent(path.split('/').pop() || '');
      const member = activeRoom.members.find((item) => item.userKey === userKey);
      if (!member) throw demoError(404, 'member not found');
      if (member.folderScope === 'invited') throw demoError(400, 'folder member cannot be managed as room member');
      if (body.folderScope) member.folderScope = body.folderScope;
      if (body.status) member.status = body.status;
      demoRecalculate();
      return { ok: true };
    }
    if (path === '/team/delete' && method === 'POST') {
      if (!activeRoom) throw demoError(404, 'no active room');
      demoStore.rooms = demoStore.rooms.filter((room) => room.roomId !== activeRoom.roomId);
      const fallback = demoStore.rooms.find((room) => {
        const member = room.members.find((item) => item.userKey === DEMO_USER_KEY);
        return member && member.status === 'active';
      });
      demoStore.activeRoomId = fallback ? fallback.roomId : null;
      return { ok: true };
    }
    return UNHANDLED;
  };
  const handlers = [handleSearchRequest, handleAccountRequest, handleInviteBillingRequest, handleRoomTeamRequest];
  return async function demoRequest(path, options = {}) {
  clearError();
  demoRecalculate();
  const method = String(options.method || 'GET').toUpperCase();
  const body = typeof options.body === 'string' ? JSON.parse(options.body || '{}') : options.body || {};
  const activeRoom = demoGetActiveRoom();
  const request = { path, method, body, activeRoom };
  for (const handler of handlers) {
    const result = handler(request);
    if (result !== UNHANDLED) return result;
  }

  if (path === '/folders' && method === 'GET') {
    if (!activeRoom) return { items: [] };
    return { items: activeRoom.folders.map((folder) => demoFolderSummary(folder)) };
  }

  if (path.startsWith('/folders/') && path.endsWith('/members') && method === 'GET') {
    if (!activeRoom) throw demoError(404, 'no active room');
    const folderId = decodeURIComponent(path.split('/')[2] || '');
    const folder = activeRoom.folders.find((item) => item.folderId === folderId);
    if (!folder) throw demoError(404, 'folder not found');
    return {
      items: activeRoom.members.filter((member) => {
        const folderIds = Array.isArray(member.folderIds) ? member.folderIds : [];
        return member.status === 'active' && member.role !== 'admin' && member.folderScope === 'invited' && folderIds.includes(folder.folderId);
      }).map((member) => {
        const folderIds = Array.isArray(member.folderIds) ? member.folderIds : [];
        const accessReason =
          member.role === 'admin'
            ? 'admin'
            : (member.folderScope || 'all') === 'all'
              ? 'all'
              : folderIds.includes(folder.folderId)
                ? 'invited'
                : 'owner';
        return { ...demoClone(member), accessReason };
      }),
    };
  }

  if (path.startsWith('/folders/') && path.includes('/members/') && method === 'DELETE') {
    if (!activeRoom) throw demoError(404, 'no active room');
    const parts = path.split('/');
    const folderId = decodeURIComponent(parts[2] || '');
    const userKey = decodeURIComponent(parts[4] || '');
    const folder = activeRoom.folders.find((item) => item.folderId === folderId);
    if (!folder) throw demoError(404, 'folder not found');
    const member = activeRoom.members.find((item) => item.userKey === userKey);
    if (!member || member.folderScope !== 'invited') throw demoError(404, 'folder member not found');
    const nextIds = (Array.isArray(member.folderIds) ? member.folderIds : []).filter((id) => id !== folderId);
    member.folderIds = nextIds;
    if (!nextIds.length) member.status = 'left';
    demoRecalculate();
    return { ok: true, status: member.status, folderIds: nextIds };
  }

  if (path === '/folders' && method === 'POST') {
    if (!activeRoom) throw demoError(404, 'no active room');
    if (String(activeRoom.subscriptionPlan || 'FREE').toUpperCase() === 'FREE' && activeRoom.folders.length >= 2) {
      throw demoError(400, 'folder limit exceeded', {
        code: 'FREE_PLAN_FOLDER_LIMIT_EXCEEDED',
        message: 'フリープランではコンテナは2つまでです。有料プランで無制限になります。',
      });
    }
    demoStore.folderCounter += 1;
    const folder = {
      folderId: `folder-demo-${demoStore.folderCounter}`,
      folderCode: `F-${String(demoStore.folderCounter).padStart(3, '0')}`,
      title: String(body.title || '').trim() || `TCLU${String(demoStore.folderCounter).padStart(7, '0')}`,
      mode: normalizeFolderMode(body.mode || body.folderMode),
      createdBy: DEMO_USER_KEY,
      createdByName: demoStore.me.displayName,
      hasPassword: Boolean(body.folderPassword),
      password: String(body.folderPassword || ''),
      photos: [],
      quests: [],
    };
    activeRoom.folders.unshift(folder);
    demoRecalculate();
    return demoFolderSummary(folder);
  }

  if (path.startsWith('/folders/') && path.endsWith('/password') && method === 'PUT') {
    const folderId = path.split('/')[2];
    const { folder } = demoFindFolder(folderId);
    if (!folder) throw demoError(404, 'folder not found');
    const password = String(body.folderPassword || '');
    folder.password = password;
    folder.hasPassword = Boolean(password);
    return { ok: true };
  }

  if (path.startsWith('/folders/') && path.endsWith('/quests') && method === 'GET') {
    const folderId = path.split('/')[2];
    const { folder } = demoFindFolder(folderId);
    if (!folder) throw demoError(404, 'folder not found');
    if (normalizeFolderMode(folder.mode) !== 'quest') return { items: [] };
    return { items: (folder.quests || []).map((quest) => demoQuestSummary(quest, folder)) };
  }

  if (path.startsWith('/folders/') && path.endsWith('/quests') && method === 'POST') {
    const folderId = path.split('/')[2];
    const { folder } = demoFindFolder(folderId);
    if (!folder) throw demoError(404, 'folder not found');
    if (normalizeFolderMode(folder.mode) !== 'quest') throw demoError(409, 'folder is not quest mode');
    const text = String(body.text || '').trim();
    if (!text) throw demoError(400, 'text is required');
    if (text.length > 100) throw demoError(400, 'text must be 100 chars or less');
    demoStore.questCounter = Number(demoStore.questCounter || 0) + 1;
    const quest = {
      questId: `quest-demo-${demoStore.questCounter}`,
      questCode: `${folder.folderCode || 'F-000'}-Q${String((folder.quests || []).length + 1).padStart(3, '0')}`,
      folderId,
      folderCode: folder.folderCode,
      text,
      status: 'open',
      createdBy: DEMO_USER_KEY,
      createdByName: demoStore.me.displayName,
      createdAt: demoNow(0),
      updatedAt: demoNow(0),
      comments: [],
    };
    folder.quests = Array.isArray(folder.quests) ? folder.quests : [];
    folder.quests.unshift(quest);
    demoRecalculate();
    return demoQuestSummary(quest, folder);
  }

  if (path.startsWith('/quests/') && path.includes('/comments/') && method === 'DELETE') {
    const parts = path.split('/');
    const questId = decodeURIComponent(parts[2] || '');
    const commentId = decodeURIComponent(parts[4] || '');
    const { quest } = demoFindQuest(questId);
    if (!quest) throw demoError(404, 'quest not found');
    quest.comments = (quest.comments || []).filter((comment) => comment.commentId !== commentId);
    demoRecalculate();
    return { ok: true };
  }

  if (path.startsWith('/quests/') && path.endsWith('/comments') && method === 'POST') {
    const questId = path.split('/')[2];
    const { quest } = demoFindQuest(questId);
    if (!quest) throw demoError(404, 'quest not found');
    const text = String(body.text || '').trim();
    if (!text) throw demoError(400, 'text is required');
    demoStore.questCommentCounter = Number(demoStore.questCommentCounter || 0) + 1;
    const comment = {
      commentId: `quest-comment-demo-${demoStore.questCommentCounter}`,
      text,
      createdAt: demoNow(0),
      createdBy: DEMO_USER_KEY,
      createdByName: demoStore.me.displayName,
    };
    quest.comments = Array.isArray(quest.comments) ? quest.comments : [];
    quest.comments.push(comment);
    quest.updatedAt = demoNow(0);
    demoRecalculate();
    return demoCommentSummary(comment);
  }

  if (path.startsWith('/quests/') && method === 'PUT') {
    const questId = path.split('/')[2];
    const { folder, quest } = demoFindQuest(questId);
    if (!quest) throw demoError(404, 'quest not found');
    const status = String(body.status || '').trim();
    if (['open', 'shooting', 'done'].includes(status)) {
      quest.status = status;
      if (status === 'done') {
        quest.completedAt = demoNow(0);
        quest.completedBy = DEMO_USER_KEY;
        quest.completedByName = demoStore.me.displayName;
      }
    }
    quest.updatedAt = demoNow(0);
    demoRecalculate();
    return demoQuestSummary(quest, folder);
  }

  if (path.startsWith('/quests/') && method === 'DELETE') {
    const questId = path.split('/')[2];
    const { folder, quest } = demoFindQuest(questId);
    if (!quest || !folder) throw demoError(404, 'quest not found');
    folder.photos = (folder.photos || []).filter((photo) => photo.questId !== questId);
    folder.quests = (folder.quests || []).filter((item) => item.questId !== questId);
    demoRecalculate();
    return { ok: true };
  }

  if (path.startsWith('/folders/') && path.endsWith('/photos') && method === 'GET') {
    const folderId = path.split('/')[2];
    const { folder } = demoFindFolder(folderId);
    if (!folder) throw demoError(404, 'folder not found');
    return {
      items: folder.photos.filter((photo) => !photo.questId).map((photo) => demoPhotoSummary(photo)),
      archivedCount: 0,
      archiveMode: 'visible',
      archiveDays: 30,
    };
  }

  if (path.startsWith('/folders/') && path.endsWith('/photos') && method === 'POST') {
    const folderId = path.split('/')[2];
    const { folder } = demoFindFolder(folderId);
    if (!folder) throw demoError(404, 'folder not found');
    const questId = String(body.questId || '').trim();
    const folderMode = normalizeFolderMode(folder.mode);
    if (folderMode === 'quest' && !questId) throw demoError(400, 'questId is required for quest folder');
    if (folderMode === 'photo' && questId) throw demoError(400, 'quest photos are not allowed in photo folder');
    let quest = null;
    if (questId) {
      quest = (folder.quests || []).find((item) => item.questId === questId);
      if (!quest) throw demoError(404, 'quest not found');
    }
    demoStore.photoCounter += 1;
    const photo = createDemoPhoto({
      photoId: body.photoId || `photo-demo-${demoStore.photoCounter}`,
      photoCode: `P-${String(demoStore.photoCounter).padStart(3, '0')}`,
      fileName: String(body.fileName || `${t('新規写真')}${demoStore.photoCounter}`).trim(),
      originalName: String(body.fileName || `${t('新規写真')}${demoStore.photoCounter}`).trim(),
      logTag: normalizeLogTag(body.logTag),
      viewUrl: demoSvg(String(body.fileName || t('新規写真')), '#1E90FF', '#dcecff'),
      sizeBytes: 6 * 1024 * 1024,
      questId: questId || null,
      questText: quest?.text || '',
      questCode: quest?.questCode || null,
      comments: !questId && body.initialComment
        ? [
            {
              commentId: `comment-demo-${++demoStore.commentCounter}`,
              text: String(body.initialComment).trim(),
              createdAt: demoNow(0),
              createdBy: DEMO_USER_KEY,
              createdByName: demoStore.me.displayName,
            },
          ]
        : [],
    });
    folder.photos.unshift(photo);
    if (quest) {
      const status = String(quest.status || 'open');
      quest.status = status === 'done' || status === 'open' ? 'shooting' : status;
      if (status === 'done') {
        delete quest.completedAt;
        delete quest.completedBy;
        delete quest.completedByName;
      }
      quest.updatedAt = demoNow(0);
    }
    demoRecalculate();
    return demoPhotoSummary(photo);
  }

  if (path.startsWith('/folders/') && path.endsWith('/export') && method === 'POST') {
    const format = String(body.format || 'pptx_high').toLowerCase();
    return {
      downloadUrl: buildDemoExportUrl(format),
      format,
    };
  }

  if (path.startsWith('/folders/') && method === 'DELETE') {
    const folderId = path.split('/')[2];
    const room = demoStore.rooms.find((item) => item.folders.some((folder) => folder.folderId === folderId));
    if (!room) throw demoError(404, 'folder not found');
    room.folders = room.folders.filter((folder) => folder.folderId !== folderId);
    demoRecalculate();
    return { ok: true };
  }

  if (path.startsWith('/photos/') && path.endsWith('/comments') && method === 'GET') {
    const photoId = path.split('/')[2];
    const { photo } = demoFindPhoto(photoId);
    if (!photo) throw demoError(404, 'photo not found');
    return { items: (photo.comments || []).map((comment) => demoCommentSummary(comment)) };
  }

  if (path.startsWith('/photos/') && path.endsWith('/comments') && method === 'POST') {
    const photoId = path.split('/')[2];
    const { photo } = demoFindPhoto(photoId);
    if (!photo) throw demoError(404, 'photo not found');
    const comment = {
      commentId: `comment-demo-${++demoStore.commentCounter}`,
      text: String(body.text || '').trim(),
      createdAt: demoNow(0),
      updatedAt: null,
      createdBy: DEMO_USER_KEY,
      createdByName: demoStore.me.displayName,
    };
    photo.comments.push(comment);
    demoRecalculate();
    return demoCommentSummary(comment);
  }

  if (path.startsWith('/photos/') && path.includes('/comments/') && method === 'PUT') {
    const parts = path.split('/');
    const photoId = parts[2];
    const commentId = parts[4];
    const { photo } = demoFindPhoto(photoId);
    if (!photo) throw demoError(404, 'photo not found');
    const comment = photo.comments.find((item) => item.commentId === commentId);
    if (!comment) throw demoError(404, 'comment not found');
    comment.text = String(body.text || comment.text).trim();
    comment.updatedAt = demoNow(0);
    demoRecalculate();
    return demoCommentSummary(comment);
  }

  if (path.startsWith('/photos/') && path.includes('/comments/') && method === 'DELETE') {
    const parts = path.split('/');
    const photoId = parts[2];
    const commentId = parts[4];
    const { photo } = demoFindPhoto(photoId);
    if (!photo) throw demoError(404, 'photo not found');
    photo.comments = photo.comments.filter((item) => item.commentId !== commentId);
    demoRecalculate();
    return { ok: true };
  }

  if (path.startsWith('/photos/') && method === 'PUT') {
    const photoId = path.split('/')[2];
    const { photo } = demoFindPhoto(photoId);
    if (!photo) throw demoError(404, 'photo not found');
    if (body.fileName) photo.fileName = String(body.fileName).trim() || photo.fileName;
    if (body.logTag) photo.logTag = normalizeLogTag(body.logTag, photo.logTag || DEFAULT_LOG_TAG);
    return demoPhotoSummary(photo);
  }

  if (path.startsWith('/photos/') && method === 'DELETE') {
    const photoId = path.split('/')[2];
    const { folder } = demoFindPhoto(photoId);
    if (!folder) throw demoError(404, 'photo not found');
    folder.photos = folder.photos.filter((item) => item.photoId !== photoId);
    demoRecalculate();
    return { ok: true };
  }

  throw demoError(501, `demo api not implemented: ${method} ${path}`);
  };
}
