const { randomUUID } = require('node:crypto');
const { pbkdf2Sync, randomBytes, timingSafeEqual } = require('node:crypto');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { CognitoIdentityProviderClient, AdminDeleteUserCommand } = require('@aws-sdk/client-cognito-identity-provider');
const {
  DynamoDBDocumentClient,
  QueryCommand,
  PutCommand,
  GetCommand,
  BatchGetCommand,
  DeleteCommand,
  UpdateCommand,
} = require('@aws-sdk/lib-dynamodb');
const {
  S3Client,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  PutObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
} = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const PptxGenJS = require('pptxgenjs');

const { stripeRequest } = require('./stripe-rest');

const {
  BILLING_MODE_PREPAID,
  BILLING_MODE_SUBSCRIPTION,
  SUBSCRIPTION_PLANS,
  formatJstDate,
  ensureBillingMeta,
  addUsageBytes,
  summarizeBilling,
  isUploadBlockedForBilling,
  normalizeSubscriptionPlanCode,
  subscriptionPlanLimitBytes,
} = require('./billing');

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});
const cognito = new CognitoIdentityProviderClient({});

const TABLE_NAME = process.env.TABLE_NAME;
const PHOTO_BUCKET = process.env.PHOTO_BUCKET;
const EXPORT_BUCKET = process.env.EXPORT_BUCKET;
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || '';

const json = (statusCode, body) => ({
  statusCode,
  headers: {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
  },
  body: JSON.stringify(body),
});

const badRequest = (message) => json(400, { message });

const PLAN_ORDER = ['FREE', 'BASIC', 'PLUS', 'PRO'];

function planRank(planCode) {
  const code = normalizeSubscriptionPlanCode(planCode);
  const idx = PLAN_ORDER.indexOf(code);
  return idx >= 0 ? idx : 0;
}

function isBillingCycleDue(nextBillingAt, now = new Date()) {
  const dueAt = Date.parse(String(nextBillingAt || ''));
  if (!Number.isFinite(dueAt)) return false;
  return now.getTime() >= dueAt;
}

function nextBillingBoundaryIsoJst(now = new Date()) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
  })
    .formatToParts(now)
    .reduce((acc, p) => {
      if (p.type === 'year' || p.type === 'month') acc[p.type] = Number(p.value);
      return acc;
    }, {});
  const year = Number(parts.year || 1970);
  const month = Number(parts.month || 1);
  const nextMonth = month === 12 ? 1 : month + 1;
  const nextYear = month === 12 ? year + 1 : year;
  const utcMs = Date.UTC(nextYear, nextMonth - 1, 1, -9, 0, 0, 0);
  return new Date(utcMs).toISOString();
}

function base64UrlFromBuffer(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function makeInviteToken() {
  // 24 chars-ish, URL-safe, high entropy.
  return `inv_${base64UrlFromBuffer(randomBytes(18))}`;
}

function hashRoomPassword(password) {
  const iterations = 120000;
  const salt = randomBytes(16);
  const hash = pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  return `pbkdf2$${iterations}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyRoomPassword(password, stored) {
  const value = String(stored || '');
  if (!value.startsWith('pbkdf2$')) return false;
  const parts = value.split('$');
  if (parts.length !== 4) return false;
  const iterations = Number(parts[1]);
  if (!Number.isFinite(iterations) || iterations < 10000) return false;
  const salt = Buffer.from(parts[2], 'base64');
  const expected = Buffer.from(parts[3], 'base64');
  const actual = pbkdf2Sync(password, salt, iterations, expected.length, 'sha256');
  try {
    return timingSafeEqual(actual, expected);
  } catch (_) {
    return false;
  }
}

function auditLog(entry) {
  console.log(
    JSON.stringify({
      kind: 'audit',
      ts: new Date().toISOString(),
      ...entry,
    })
  );
}

function getUserIdentity(event) {
  const claims = event?.requestContext?.authorizer?.jwt?.claims || null;
  if (claims && claims.sub) {
    const fallbackName =
      claims['cognito:username'] || claims.name || claims.email || claims.preferred_username || 'unknown';
    return {
      userKey: claims.sub,
      fallbackName,
      fromCognito: true,
      cognitoUsername: String(claims['cognito:username'] || '').trim() || null,
    };
  }

  const headers = event.headers || {};
  const userKey = headers['x-user-key'] || headers['X-User-Key'];
  const rawUserName = headers['x-user-name'] || headers['X-User-Name'] || 'unknown';
  let fallbackName = rawUserName;
  try {
    fallbackName = decodeURIComponent(rawUserName);
  } catch (_) {
    fallbackName = rawUserName;
  }
  if (!userKey) {
    throw new Error('MISSING_USER_KEY');
  }
  return { userKey, fallbackName, fromCognito: false };
}

function normalizeDisplayName(rawValue) {
  const value = String(rawValue || '').trim();
  if (!value) return '';
  if (value.length > 40) throw new Error('INVALID_DISPLAY_NAME_LENGTH');
  return value;
}

async function ensureUserProfile(identity) {
  const key = { PK: `USER#${identity.userKey}`, SK: 'PROFILE' };
  const existingRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: key,
    })
  );
  if (existingRes.Item) return existingRes.Item;

  const now = new Date().toISOString();
  const newItem = {
    ...key,
    type: 'user_profile',
    userKey: identity.userKey,
    displayName: '',
    cognitoName: identity.fallbackName || '',
    createdAt: now,
    updatedAt: now,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: newItem,
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
    return newItem;
  } catch (_) {
    const retryRes = await ddb.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: key,
      })
    );
    return retryRes.Item || newItem;
  }
}

async function getUser(event) {
  const identity = getUserIdentity(event);
  if (!identity.fromCognito) {
    return {
      userKey: identity.userKey,
      userName: identity.fallbackName || 'unknown',
      displayName: identity.fallbackName || '',
      fallbackName: identity.fallbackName || 'unknown',
      fromCognito: false,
      cognitoUsername: null,
    };
  }

  const profile = await ensureUserProfile(identity);
  const displayName = normalizeDisplayName(profile.displayName || '');
  const fallbackName = identity.fallbackName || 'unknown';
  return {
    userKey: identity.userKey,
    userName: displayName || fallbackName,
    displayName,
    fallbackName,
    fromCognito: true,
    cognitoUsername: identity.cognitoUsername || null,
  };
}

function decodeText(value) {
  if (!value) return '';
  try {
    return decodeURIComponent(value);
  } catch (_) {
    return value;
  }
}

function isRoomMatch(itemRoomName, requestedRoomName) {
  return Boolean(itemRoomName) && itemRoomName === requestedRoomName;
}

async function resolveActiveRoomForUser(userKey) {
  // Determine the user's current active room from the USER#... reverse index.
  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `USER#${userKey}`,
        ':sk': 'ROOMMEMBER#',
      },
      // Use a strongly consistent read so switching rooms is immediately reflected.
      ConsistentRead: true,
      ScanIndexForward: true,
      Limit: 25,
    })
  );
  const items = res.Items || [];
  const active = items.find((m) => {
    const selection = String(m.status || 'inactive').toLowerCase();
    if (selection !== 'active') return false;
    const memberStatus = String(m.memberStatus || 'active').toLowerCase();
    return memberStatus !== 'disabled' && memberStatus !== 'left';
  });
  if (!active?.roomId || !active?.roomName) return null;

  // Verify the room exists and createdBy is consistent.
  const roomRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `ROOM#${active.roomName}` },
    })
  );
  const roomItem = roomRes.Item;
  if (!roomItem || roomItem.roomId !== active.roomId) return null;
  return { roomId: roomItem.roomId, roomName: roomItem.roomName, createdBy: roomItem.createdBy || null };
}

async function listUserRoomMemberships(userKey) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `USER#${userKey}`,
        ':sk': 'ROOMMEMBER#',
      },
      ConsistentRead: true,
      ScanIndexForward: true,
      Limit: 100,
    })
  );
  return res.Items || [];
}

async function setActiveRoomForUser(userKey, nextRoomId) {
  const memberships = await listUserRoomMemberships(userKey);
  const nowIso = new Date().toISOString();

  const nextId = String(nextRoomId || '').trim();
  if (!nextId) throw new Error('ROOM_NOT_MEMBER');

  const target = memberships.find((m) => String(m.roomId || '') === nextId);
  if (!target) throw new Error('ROOM_NOT_MEMBER');
  const targetMemberStatus = String(target.memberStatus || 'active').toLowerCase();
  if (targetMemberStatus === 'left') throw new Error('ROOM_MEMBERSHIP_LEFT');
  if (targetMemberStatus === 'disabled') throw new Error('ROOM_MEMBERSHIP_DISABLED');

  // Always set the target first, then inactivate others. This avoids rare edge cases where
  // the user can temporarily end up with no active room.
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: userRoomMemberKey(userKey, target.roomId),
      UpdateExpression: 'SET #status = :s, updatedAt = :u',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':s': 'active', ':u': nowIso },
      ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
    })
  );

  // Keep exactly one "active" room; others become "inactive" (unless already left/disabled).
  for (const m of memberships) {
    if (!m?.roomId) continue;
    const memberStatus = String(m.memberStatus || 'active').toLowerCase();
    if (memberStatus === 'left' || memberStatus === 'disabled') continue;
    const current = String(m.status || 'inactive').toLowerCase();
    const rid = String(m.roomId || '');
    if (rid === nextId) continue;
    if (current === 'inactive') continue;
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: userRoomMemberKey(userKey, rid),
        UpdateExpression: 'SET #status = :s, updatedAt = :u',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':s': 'inactive', ':u': nowIso },
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
      })
    );
  }
  return { roomId: target.roomId, roomName: target.roomName, role: target.role || 'member' };
}

async function resolveRoomForRequest(event, user) {
  // Room headers are deprecated. Infer solely from membership.
  const active = await resolveActiveRoomForUser(user.userKey);
  if (!active) throw new Error('MISSING_ROOM');
  return active;
}

function getFolderPassword(event) {
  const headers = event.headers || {};
  return decodeText(headers['x-folder-password'] || headers['X-Folder-Password'] || '');
}

function verifyFolderPassword(folder, event) {
  if (!folder?.folderPasswordHash) return { ok: true };
  const supplied = getFolderPassword(event);
  if (!supplied) return { ok: false, reason: 'missing' };
  if (!verifyRoomPassword(supplied, folder.folderPasswordHash)) return { ok: false, reason: 'invalid' };
  return { ok: true };
}

function folderHasPassword(folder) {
  return Boolean(folder?.folderPasswordHash);
}

function roomMemberKey(roomId, userKey) {
  return { PK: `ROOM#${roomId}`, SK: `MEMBER#${userKey}` };
}

function userRoomMemberKey(userKey, roomId) {
  return { PK: `USER#${userKey}`, SK: `ROOMMEMBER#${roomId}` };
}

function userRoomConstraintKey(userKey) {
  return { PK: `USER#${userKey}`, SK: 'CONSTRAINT#ROOM' };
}

function isAdminRole(role) {
  return String(role || '').toLowerCase() === 'admin';
}

function normalizeFolderScope(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'all') return 'all';
  return 'own';
}

function normalizeMemberStatus(value) {
  const v = String(value || '').trim().toLowerCase();
  if (v === 'disabled') return 'disabled';
  if (v === 'left') return 'left';
  // Inactive is a room selection status (USER#...), not a membership status (ROOM#...).
  // Treat it as active for backward-compat data cleanup.
  return 'active';
}

async function upsertUserRoomMemberIndex(room, member, nowIso) {
  if (!room?.roomId || !member?.userKey) return;
  const key = userRoomMemberKey(member.userKey, room.roomId);
  const memberStatus = normalizeMemberStatus(member.status);
  const folderScope =
    isAdminRole(member.role) ? 'all' : normalizeFolderScope(member.folderScope || member.folder_scope || 'own');
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: key,
      UpdateExpression:
        // USER#... items store:
        // - status: active selection (active|inactive)
        // - memberStatus: membership status (active|disabled|left)
        'SET #type = if_not_exists(#type, :type), roomId = :roomId, roomName = :roomName, userKey = :userKey, #role = :role, memberStatus = :memberStatus, folderScope = :folderScope, joinedAt = if_not_exists(joinedAt, :joinedAt), updatedAt = :updatedAt, #status = if_not_exists(#status, :defaultSelection)',
      ExpressionAttributeNames: {
        '#type': 'type',
        '#role': 'role',
        '#status': 'status',
      },
      ExpressionAttributeValues: {
        ':type': 'user_room_member',
        ':roomId': room.roomId,
        ':roomName': room.roomName,
        ':userKey': member.userKey,
        ':role': member.role || 'member',
        ':memberStatus': memberStatus,
        ':folderScope': folderScope,
        ':joinedAt': member.joinedAt || nowIso,
        ':updatedAt': nowIso,
        ':defaultSelection': 'inactive',
      },
    })
  );
}

async function maybeUpsertUserRoomMemberIndex(room, member, nowIso) {
  if (!room?.roomId || !member?.userKey) return;
  const key = userRoomMemberKey(member.userKey, room.roomId);
  const desired = {
    roomId: room.roomId,
    roomName: room.roomName,
    role: member.role || 'member',
    memberStatus: normalizeMemberStatus(member.status),
    folderScope:
      isAdminRole(member.role) ? 'all' : normalizeFolderScope(member.folderScope || member.folder_scope || 'own'),
  };

  const existing = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: key,
      ConsistentRead: true,
    })
  );
  const item = existing.Item || null;
  if (!item) {
    await upsertUserRoomMemberIndex(room, member, nowIso);
    return;
  }
  const same =
    String(item.roomId || '') === String(desired.roomId) &&
    String(item.roomName || '') === String(desired.roomName) &&
    String(item.role || '') === String(desired.role) &&
    String(item.memberStatus || 'active').toLowerCase() === String(desired.memberStatus) &&
    String(item.folderScope || item.folder_scope || '').toLowerCase() === String(desired.folderScope);
  if (same) return;

  await upsertUserRoomMemberIndex(room, member, nowIso);
}

async function ensureRoomMember(room, user, nowIso, ctx) {
  const key = roomMemberKey(room.roomId, user.userKey);
  const existing = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: key }));
  if (existing.Item) {
    // Backfill for old data: ROOM member status must never be "inactive".
    if (String(existing.Item.status || 'active').toLowerCase() === 'inactive') {
      try {
        await ddb.send(
          new UpdateCommand({
            TableName: TABLE_NAME,
            Key: key,
            UpdateExpression: 'SET #status = :s, updatedAt = :u',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: { ':s': 'active', ':u': nowIso },
          })
        );
        existing.Item.status = 'active';
      } catch (_) {
        // Ignore; best-effort backfill.
      }
    }
    // Backfill defaults for older items.
    const currentScope = existing.Item.folderScope || existing.Item.folder_scope;
    const wantsScope = isAdminRole(existing.Item.role)
      ? 'all'
      : normalizeFolderScope(currentScope || 'own');
    if (!currentScope || String(currentScope) !== String(wantsScope)) {
      try {
        await ddb.send(
          new UpdateCommand({
            TableName: TABLE_NAME,
            Key: key,
            UpdateExpression: 'SET folderScope = :s, updatedAt = :u',
            ExpressionAttributeValues: { ':s': wantsScope, ':u': nowIso },
          })
        );
        existing.Item.folderScope = wantsScope;
      } catch (_) {
        // Ignore; best-effort backfill.
      }
    }
    await maybeUpsertUserRoomMemberIndex(room, existing.Item, nowIso);
    return existing.Item;
  }

  const role = room.createdBy && room.createdBy === user.userKey ? 'admin' : 'member';
  const item = {
    ...key,
    type: 'room_member',
    roomId: room.roomId,
    roomName: room.roomName,
    userKey: user.userKey,
    role,
    status: 'active',
    folderScope: isAdminRole(role) ? 'all' : 'own',
    joinedAt: nowIso,
    updatedAt: nowIso,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
    auditLog({
      requestId: ctx.requestId,
      action: 'team.member.join',
      actor: user.userKey,
      actorName: user.userName,
      roomName: room.roomName,
      roomId: room.roomId,
      role,
      result: 'success',
    });
    await upsertUserRoomMemberIndex(room, item, nowIso);
    return item;
  } catch (_) {
    const retry = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: key }));
    if (retry.Item) await maybeUpsertUserRoomMemberIndex(room, retry.Item, nowIso);
    return retry.Item || item;
  }
}

async function requireActiveMember(room, user, ctx) {
  const nowIso = new Date().toISOString();
  const activeRoomId = await getActiveRoomIdForUser(user.userKey);
  if (activeRoomId && activeRoomId !== room.roomId) {
    auditLog({
      requestId: ctx.requestId,
      action: 'team.member.access',
      actor: user.userKey,
      actorName: user.userName,
      roomName: room.roomName,
      roomId: room.roomId,
      result: 'denied',
      reason: 'already_in_another_room',
      activeRoomId,
    });
    return { ok: false, response: json(403, { message: 'already in another room' }) };
  }
  const member = await ensureRoomMember(room, user, nowIso, ctx);
  if (member.status === 'disabled' || member.status === 'left') {
    auditLog({
      requestId: ctx.requestId,
      action: 'team.member.access',
      actor: user.userKey,
      actorName: user.userName,
      roomName: room.roomName,
      roomId: room.roomId,
      result: 'denied',
      reason: member.status === 'left' ? 'member_left' : 'member_disabled',
    });
    return { ok: false, response: json(403, { message: 'forbidden' }) };
  }
  const billing = await ensureBillingMeta(ddb, {
    tableName: TABLE_NAME,
    roomId: room.roomId,
    roomName: room.roomName,
    nowIso,
  });
  const adjusted = await applyPendingSubscriptionIfDue(room, billing, ctx);
  return { ok: true, member, isAdmin: isAdminRole(member.role), billing: adjusted };
}

async function applyPendingSubscriptionIfDue(room, billing, ctx) {
  const mode = String(billing?.billingMode || BILLING_MODE_PREPAID).toLowerCase();
  if (mode !== BILLING_MODE_SUBSCRIPTION) return billing;
  if (!isBillingCycleDue(billing?.nextBillingAt)) return billing;

  const nowIso = new Date().toISOString();
  const usageBytes = Number(billing?.usageBytes || 0);
  const pendingRaw = String(billing?.pendingPlan || '').trim();
  const pendingPlan = pendingRaw ? normalizeSubscriptionPlanCode(pendingRaw) : null;
  const updates = ['updatedAt = :u', 'nextBillingAt = :nb'];
  const values = {
    ':u': nowIso,
    ':nb': nextBillingBoundaryIsoJst(),
    ':null': null,
    ':f': false,
  };
  const secretKey = process.env.STRIPE_SECRET_KEY || '';
  const stripeSubId = String(billing?.stripeSubscriptionId || '').trim();

  if (pendingPlan) {
    const targetLimit = subscriptionPlanLimitBytes(pendingPlan);
    if (targetLimit !== null && usageBytes > targetLimit) {
      // Reflect "downgrade skipped on boundary if over limit": clear reservation only.
      updates.push('pendingPlan = :null');
    } else {
      if (secretKey && stripeSubId) {
        const targetPriceId = subscriptionPriceIdForPlan(pendingPlan);
        if (targetPriceId) {
          const stripeSub = await stripeUpdateSubscriptionPlan(secretKey, stripeSubId, targetPriceId, 'none');
          updates.push('stripeSubscriptionStatus = :ss', 'stripeSubscriptionItemId = :si');
          values[':ss'] = stripeSub?.status || null;
          values[':si'] = stripeSub?.items?.data?.[0]?.id || null;
        }
      }
      updates.push('currentPlan = :cp', 'pendingPlan = :null');
      values[':cp'] = pendingPlan;
    }
  }

  if (Boolean(billing?.cancelAtPeriodEnd)) {
    updates.push('cancelAtPeriodEnd = :f', 'currentPlan = :free', 'pendingPlan = :null');
    values[':free'] = 'FREE';
  }

  const res = await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `ROOM#${room.roomId}`, SK: 'META#BILLING' },
      UpdateExpression: `SET ${updates.join(', ')}`,
      ExpressionAttributeValues: values,
      ReturnValues: 'ALL_NEW',
    })
  );

  auditLog({
    requestId: ctx?.requestId || null,
    action: 'subscription.cycle.apply',
    roomId: room.roomId,
    roomName: room.roomName,
    currentPlan: res.Attributes?.currentPlan || null,
    pendingPlan: pendingPlan || null,
    cancelAtPeriodEnd: Boolean(billing?.cancelAtPeriodEnd),
    result: 'success',
  });

  return res.Attributes || billing;
}

function folderScopeForMember(member, isAdmin) {
  if (isAdmin) return 'all';
  return normalizeFolderScope(member?.folderScope || member?.folder_scope || 'own');
}

function canAccessFolder(folder, user, authz) {
  if (!folder || !user || !authz) return false;
  if (authz.isAdmin) return true;
  const scope = folderScopeForMember(authz.member, authz.isAdmin);
  if (scope === 'all') return true;
  return folder.createdBy && folder.createdBy === user.userKey;
}

function isUploadBlocked(billing) {
  return isUploadBlockedForBilling(billing);
}

function pad3(num) {
  return String(num).padStart(3, '0');
}

async function nextFolderCode() {
  const res = await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: 'META#COUNTER' },
      UpdateExpression: 'ADD folderSeq :inc',
      ExpressionAttributeValues: { ':inc': 1 },
      ReturnValues: 'UPDATED_NEW',
    })
  );
  const seq = res.Attributes?.folderSeq || 1;
  return `F${pad3(seq)}`;
}

async function nextPhotoCode(folderId, folderCode) {
  const res = await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `FOLDER#${folderId}`, SK: 'META#COUNTER' },
      UpdateExpression: 'ADD photoSeq :inc',
      ExpressionAttributeValues: { ':inc': 1 },
      ReturnValues: 'UPDATED_NEW',
    })
  );
  const seq = res.Attributes?.photoSeq || 1;
  return `${folderCode}-P${pad3(seq)}`;
}

async function createRoom(event, user, ctx) {
  const body = JSON.parse(event.body || '{}');
  const roomName = (body.roomName || '').trim();
  if (!roomName) return badRequest('roomName is required');

  const roomId = randomUUID();
  const now = new Date().toISOString();

  // Enforce "1 user = 1 owned room" for creators using a constraint lock item.
  // This protects against missing/lagging reverse indexes and concurrent requests.
  try {
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: {
          ...userRoomConstraintKey(user.userKey),
          type: 'user_room_constraint',
          userKey: user.userKey,
          roomId,
          roomName,
          createdAt: now,
          updatedAt: now,
        },
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
  } catch (_) {
    return json(409, { message: 'already has a room' });
  }

  const item = {
    PK: 'ORG#DEFAULT',
    SK: `ROOM#${roomName}`,
    type: 'room',
    roomId,
    roomName,
    // Room password is deprecated. Joining happens via invite URL.
    createdBy: user.userKey,
    createdByName: user.userName,
    createdAt: now,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
  } catch (_) {
    // Roll back constraint lock so the user can retry with a different name.
    try {
      await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: userRoomConstraintKey(user.userKey) }));
    } catch (_) {
      // Ignore best-effort cleanup.
    }
    return json(409, { message: 'room already exists' });
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'room.create',
    actor: user.userKey,
    actorName: user.userName,
    roomName,
    result: 'success',
  });
  // Best-effort: create admin membership immediately so the 1-room constraint applies even before /team/me is hit.
  try {
    const memberKey = roomMemberKey(roomId, user.userKey);
    const member = {
      ...memberKey,
      type: 'room_member',
      roomId,
      roomName,
      userKey: user.userKey,
      role: 'admin',
      status: 'active',
      folderScope: 'all',
      joinedAt: now,
      updatedAt: now,
    };
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: member,
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
    await upsertUserRoomMemberIndex({ roomId, roomName }, member, now);
    await setActiveRoomForUser(user.userKey, roomId);
  } catch (_) {
    // Roll back in case we created the room but couldn't create membership/index.
    try {
      await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: 'ORG#DEFAULT', SK: `ROOM#${roomName}` } }));
    } catch (_) {
      // Ignore.
    }
    try {
      await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: userRoomConstraintKey(user.userKey) }));
    } catch (_) {
      // Ignore.
    }
    return json(500, { message: 'internal server error' });
  }
  return json(201, { roomName, roomId });
}

async function getActiveRoomIdForUser(userKey) {
  const active = await resolveActiveRoomForUser(userKey);
  return active?.roomId || null;
}

async function getMe(user) {
  return json(200, {
    userKey: user.userKey,
    displayName: user.displayName || '',
    fallbackName: user.fallbackName || user.userName || 'unknown',
  });
}

async function updateDisplayName(event, user, ctx) {
  const body = JSON.parse(event.body || '{}');
  const displayName = normalizeDisplayName(body.displayName || '');
  if (!displayName) return badRequest('displayName is required');

  const now = new Date().toISOString();
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `USER#${user.userKey}`, SK: 'PROFILE' },
      UpdateExpression:
        'SET #type = if_not_exists(#type, :type), userKey = if_not_exists(userKey, :userKey), displayName = :displayName, updatedAt = :updatedAt, createdAt = if_not_exists(createdAt, :createdAt), cognitoName = if_not_exists(cognitoName, :cognitoName)',
      ExpressionAttributeNames: {
        '#type': 'type',
      },
      ExpressionAttributeValues: {
        ':type': 'user_profile',
        ':userKey': user.userKey,
        ':displayName': displayName,
        ':updatedAt': now,
        ':createdAt': now,
        ':cognitoName': user.fallbackName || '',
      },
    })
  );

  auditLog({
    requestId: ctx.requestId,
    action: 'user.display_name.update',
    actor: user.userKey,
    actorName: displayName,
    result: 'success',
  });
  return json(200, { ok: true, displayName });
}

async function teamMe(room, authz) {
  const billing = summarizeBilling(authz.billing);
  return json(200, {
    roomId: room.roomId,
    roomName: room.roomName,
    ownerUserKey: room.createdBy || null,
    role: authz.member.role || 'member',
    status: authz.member.status || 'active',
    isAdmin: Boolean(authz.isAdmin),
    uploadBlocked: isUploadBlocked(authz.billing),
    billing,
  });
}

async function teamMeAuto(event, user, ctx) {
  // /team/me is used as "my room" discovery after login. It must not require room headers.
  const active = await resolveActiveRoomForUser(user.userKey);
  if (!active) {
    return json(200, { hasRoom: false });
  }
  const authzRes = await requireActiveMember(active, user, ctx);
  if (!authzRes.ok) return authzRes.response;
  return await teamMe(active, authzRes);
}

async function listMyRooms(user) {
  const items = await listUserRoomMemberships(user.userKey);
  const mapped = (items || []).map((m) => ({
    roomId: m.roomId || null,
    roomName: m.roomName || null,
    role: m.role || 'member',
    status: String(m.status || 'inactive').toLowerCase(),
    memberStatus: String(m.memberStatus || 'active').toLowerCase(),
    folderScope: normalizeFolderScope(m.folderScope || m.folder_scope || (isAdminRole(m.role) ? 'all' : 'own')),
    updatedAt: m.updatedAt || null,
  }));
  const active = mapped.find((m) => m.status === 'active') || null;
  return json(200, { items: mapped, activeRoomId: active?.roomId || null });
}

async function switchActiveRoom(event, user, ctx) {
  const body = event.body ? JSON.parse(event.body) : {};
  const roomId = String(body.roomId || '').trim();
  if (!roomId) return badRequest('roomId is required');
  try {
    const next = await setActiveRoomForUser(user.userKey, roomId);
    // Read back with a strongly consistent read to avoid "no active room" right after switching.
    const active = await resolveActiveRoomForUser(user.userKey);
    if (!active || active.roomId !== roomId) {
      return json(409, { message: 'room switch not applied yet; retry' });
    }
    auditLog({
      requestId: ctx.requestId,
      action: 'room.switch',
      actor: user.userKey,
      actorName: user.userName,
      roomId: next.roomId,
      roomName: next.roomName,
      result: 'success',
    });
    return json(200, { ok: true, roomId: next.roomId, roomName: next.roomName });
  } catch (error) {
    if (error.message === 'ROOM_NOT_MEMBER') return json(404, { message: 'room not found' });
    if (error.message === 'ROOM_MEMBERSHIP_LEFT') return json(403, { message: 'forbidden' });
    if (error.message === 'ROOM_MEMBERSHIP_DISABLED') return json(403, { message: 'forbidden' });
    throw error;
  }
}

async function createInvite(event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  if (!room.createdBy || room.createdBy !== user.userKey) return json(403, { message: 'forbidden' });

  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  const ttlSeconds = Math.floor(now / 1000) + 7 * 24 * 60 * 60;
  const expiresAtIso = new Date(ttlSeconds * 1000).toISOString();
  const token = makeInviteToken();

  const item = {
    PK: 'ORG#DEFAULT',
    SK: `INVITE#${token}`,
    type: 'invite',
    token,
    roomId: room.roomId,
    roomName: room.roomName,
    createdBy: room.createdBy || null,
    createdAt: nowIso,
    expiresAt: expiresAtIso,
    expiresAtEpoch: ttlSeconds,
    usedCount: 0,
    ttl: ttlSeconds,
  };

  await ddb.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: item,
      ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
    })
  );

  auditLog({
    requestId: ctx.requestId,
    action: 'invite.create',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    token,
    expiresAt: expiresAtIso,
    result: 'success',
  });

  return json(201, { token, expiresAt: expiresAtIso, days: 7 });
}

async function revokeInvite(event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  if (!room.createdBy || room.createdBy !== user.userKey) return json(403, { message: 'forbidden' });

  const body = event.body ? JSON.parse(event.body) : {};
  const token = String(body.token || '').trim();
  if (!token || !token.startsWith('inv_')) return badRequest('token is required');

  const nowEpoch = Math.floor(Date.now() / 1000);
  const nowIso = new Date().toISOString();

  try {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { PK: 'ORG#DEFAULT', SK: `INVITE#${token}` },
        UpdateExpression:
          'SET expiresAtEpoch = :e, expiresAt = :expiresAt, revokedAt = :revokedAt, revokedBy = :revokedBy, ttl = :ttl, updatedAt = :u',
        ExpressionAttributeValues: {
          ':e': 0,
          ':expiresAt': nowIso,
          ':revokedAt': nowIso,
          ':revokedBy': user.userKey,
          ':ttl': nowEpoch,
          ':u': nowIso,
          ':roomId': room.roomId,
        },
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK) and roomId = :roomId',
      })
    );
  } catch (_) {
    return json(404, { message: 'invite not found' });
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'invite.revoke',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    token,
    result: 'success',
  });

  return json(200, { ok: true });
}

async function acceptInvite(event, user, ctx) {
  const body = event.body ? JSON.parse(event.body) : {};
  const token = String(body.token || '').trim();
  if (!token || !token.startsWith('inv_')) return badRequest('token is required');

  const nowEpoch = Math.floor(Date.now() / 1000);
  const nowIso = new Date().toISOString();

  let inviteItem = null;
  try {
    const updateRes = await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { PK: 'ORG#DEFAULT', SK: `INVITE#${token}` },
        UpdateExpression: 'ADD usedCount :inc SET lastUsedAt = :u',
        ExpressionAttributeValues: { ':inc': 1, ':u': nowIso, ':now': nowEpoch },
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK) and expiresAtEpoch > :now',
        ReturnValues: 'ALL_NEW',
      })
    );
    inviteItem = updateRes.Attributes || null;
  } catch (error) {
    const name = error?.name || '';
    if (name === 'ConditionalCheckFailedException') {
      return json(410, { message: 'invite expired or invalid' });
    }
    throw error;
  }

  if (!inviteItem?.roomId || !inviteItem?.roomName) return json(410, { message: 'invite expired or invalid' });

  // Verify the room still exists and is consistent.
  const roomRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `ROOM#${inviteItem.roomName}` },
    })
  );
  const roomItem = roomRes.Item;
  if (!roomItem || roomItem.roomId !== inviteItem.roomId) {
    return json(410, { message: 'invite expired or invalid' });
  }
  const room = { roomId: roomItem.roomId, roomName: roomItem.roomName, createdBy: roomItem.createdBy || null };

  const member = await ensureRoomMember(room, user, nowIso, ctx);
  if (member.status === 'disabled') return json(403, { message: 'forbidden' });
  if (member.status === 'left') {
    // Allow re-joining after being removed/left: reactivate membership on invite acceptance.
    try {
      await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME,
          Key: roomMemberKey(room.roomId, user.userKey),
          UpdateExpression: 'SET #status = :s, updatedAt = :u',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: { ':s': 'active', ':u': nowIso },
          ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
        })
      );
      member.status = 'active';
      member.updatedAt = nowIso;
    } catch (_) {
      return json(403, { message: 'forbidden' });
    }
  }
  await maybeUpsertUserRoomMemberIndex(room, member, nowIso);
  const billing = await ensureBillingMeta(ddb, {
    tableName: TABLE_NAME,
    roomId: room.roomId,
    roomName: room.roomName,
    nowIso,
  });

  // Make this room active (and others inactive) so the user lands in the invited room.
  await setActiveRoomForUser(user.userKey, room.roomId);

  auditLog({
    requestId: ctx.requestId,
    action: 'invite.accept',
    actor: user.userKey,
    actorName: user.userName,
    token,
    roomId: room.roomId,
    roomName: room.roomName,
    result: 'success',
  });

  return json(200, {
    ok: true,
    roomId: room.roomId,
    roomName: room.roomName,
    role: member.role || 'member',
    billing: summarizeBilling(billing),
  });
}

async function teamBilling(authz) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const billing = summarizeBilling(authz.billing);
  return json(200, { billing });
}

function subscriptionPriceIdForPlan(planCode) {
  const code = normalizeSubscriptionPlanCode(planCode);
  if (code === 'BASIC') return process.env.STRIPE_SUB_PRICE_1GB || '';
  if (code === 'PLUS') return process.env.STRIPE_SUB_PRICE_5GB || '';
  if (code === 'PRO') return process.env.STRIPE_SUB_PRICE_10GB || '';
  return '';
}

function planCodeFromSubscriptionPriceId(priceId) {
  const id = String(priceId || '').trim();
  if (!id) return null;
  if (id === String(process.env.STRIPE_SUB_PRICE_1GB || '')) return 'BASIC';
  if (id === String(process.env.STRIPE_SUB_PRICE_5GB || '')) return 'PLUS';
  if (id === String(process.env.STRIPE_SUB_PRICE_10GB || '')) return 'PRO';
  return null;
}

function isoFromUnixSec(sec) {
  const n = Number(sec || 0);
  if (!Number.isFinite(n) || n <= 0) return null;
  return new Date(n * 1000).toISOString();
}

async function stripeGetSubscription(secretKey, subscriptionId) {
  return await stripeRequest({
    secretKey,
    method: 'GET',
    path: `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
  });
}

async function stripeUpdateSubscriptionPlan(secretKey, subscriptionId, targetPriceId, prorationBehavior) {
  const sub = await stripeGetSubscription(secretKey, subscriptionId);
  const itemId = sub?.items?.data?.[0]?.id || '';
  if (!itemId) throw new Error('stripe subscription item not found');
  const params = new URLSearchParams();
  params.append('items[0][id]', itemId);
  params.append('items[0][price]', targetPriceId);
  params.append('proration_behavior', prorationBehavior || 'always_invoice');
  return await stripeRequest({
    secretKey,
    method: 'POST',
    path: `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
    params,
  });
}

async function stripeSetCancelAtPeriodEnd(secretKey, subscriptionId, flag) {
  const params = new URLSearchParams();
  params.append('cancel_at_period_end', flag ? 'true' : 'false');
  return await stripeRequest({
    secretKey,
    method: 'POST',
    path: `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
    params,
  });
}

async function stripeCancelSubscriptionNow(secretKey, subscriptionId) {
  return await stripeRequest({
    secretKey,
    method: 'DELETE',
    path: `/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
  });
}

async function teamSubscription(room, authz) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const billing = summarizeBilling(authz.billing);
  return json(200, {
    billingMode: billing.billingMode || BILLING_MODE_PREPAID,
    subscription: billing.subscription || null,
    usageBytes: Number(billing.usageBytes || 0),
  });
}

async function teamSubscriptionCheckout(event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const secretKey = process.env.STRIPE_SECRET_KEY || '';
  if (!secretKey) return json(500, { message: 'stripe is not configured (missing STRIPE_SECRET_KEY)' });

  const body = JSON.parse(event.body || '{}');
  const plan = normalizeSubscriptionPlanCode(body.plan || '');
  if (!plan || plan === 'FREE') return badRequest('plan is required (BASIC|PLUS|PRO)');
  const priceId = subscriptionPriceIdForPlan(plan);
  if (!priceId) return json(500, { message: `stripe is not configured (missing subscription price for ${plan})` });

  const allowedOrigins = parseAllowedReturnOrigins();
  const fallback = stripeCheckoutUrls();
  const requestedSuccess = normalizeReturnUrl(body.successUrl);
  const requestedCancel = normalizeReturnUrl(body.cancelUrl);
  const successUrl =
    requestedSuccess && isAllowedReturnUrl(requestedSuccess, allowedOrigins) ? requestedSuccess : fallback.successUrl;
  const cancelUrl =
    requestedCancel && isAllowedReturnUrl(requestedCancel, allowedOrigins) ? requestedCancel : fallback.cancelUrl;
  if (!successUrl || !cancelUrl) return json(500, { message: 'stripe is not configured (missing return urls)' });

  const nowIso = new Date().toISOString();
  const params = new URLSearchParams();
  params.append('mode', 'subscription');
  params.append('line_items[0][price]', priceId);
  params.append('line_items[0][quantity]', '1');
  params.append('success_url', successUrl);
  params.append('cancel_url', cancelUrl);
  params.append('client_reference_id', room.roomId);
  params.append('metadata[roomId]', room.roomId);
  params.append('metadata[roomName]', room.roomName);
  params.append('metadata[selectedPlan]', plan);
  params.append('metadata[purchasedBy]', user.userKey);
  params.append('metadata[purchasedByName]', user.userName);
  params.append('metadata[createdAt]', nowIso);

  const session = await stripeRequest({ secretKey, method: 'POST', path: '/v1/checkout/sessions', params });
  auditLog({
    requestId: ctx.requestId,
    action: 'subscription.checkout.create',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    plan,
    stripeSessionId: session.id || null,
    result: 'success',
  });
  return json(200, { url: session.url, sessionId: session.id, plan });
}

async function changeTeamSubscription(event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const body = JSON.parse(event.body || '{}');
  const action = String(body.action || '').trim().toLowerCase();
  if (!action) return badRequest('action is required (upgrade|downgrade|cancel|resume|free)');

  const currentMode = String(authz.billing?.billingMode || BILLING_MODE_PREPAID).toLowerCase();
  if (currentMode !== BILLING_MODE_SUBSCRIPTION) {
    return badRequest('subscription change is available only in subscription mode');
  }
  const currentPlan = normalizeSubscriptionPlanCode(authz.billing?.currentPlan || 'FREE');
  const targetPlan = body.targetPlan ? normalizeSubscriptionPlanCode(body.targetPlan) : null;
  const usageBytes = Number(authz.billing?.usageBytes || 0);
  const nowIso = new Date().toISOString();
  const nextBillingAt = nextBillingBoundaryIsoJst();
  const updates = ['updatedAt = :u'];
  const values = {
    ':u': nowIso,
    ':null': null,
    ':f': false,
  };

  if (action === 'upgrade') {
    if (!targetPlan) return badRequest('targetPlan is required for upgrade');
    if (planRank(targetPlan) <= planRank(currentPlan)) return badRequest('targetPlan must be higher than currentPlan');
    updates.push('billingMode = :ms', 'nextBillingAt = :nb', 'currentPlan = :cp', 'pendingPlan = :null', 'cancelAtPeriodEnd = :f');
    values[':ms'] = BILLING_MODE_SUBSCRIPTION;
    values[':nb'] = nextBillingAt;
    values[':cp'] = targetPlan;
  } else if (action === 'downgrade') {
    if (!targetPlan) return badRequest('targetPlan is required for downgrade');
    if (planRank(targetPlan) >= planRank(currentPlan)) return badRequest('targetPlan must be lower than currentPlan');
    const targetLimit = subscriptionPlanLimitBytes(targetPlan);
    if (targetLimit !== null && usageBytes > targetLimit) {
      return badRequest(
        `current usage (${usageBytes} bytes) exceeds target plan limit (${targetLimit} bytes); cannot schedule downgrade`
      );
    }
    updates.push('billingMode = :ms', 'nextBillingAt = :nb', 'pendingPlan = :pp', 'cancelAtPeriodEnd = :f');
    values[':ms'] = BILLING_MODE_SUBSCRIPTION;
    values[':nb'] = nextBillingAt;
    values[':pp'] = targetPlan;
  } else if (action === 'cancel') {
    if (currentMode !== BILLING_MODE_SUBSCRIPTION) return badRequest('cancel is available only in subscription mode');
    updates.push('billingMode = :ms', 'nextBillingAt = :nb', 'cancelAtPeriodEnd = :t');
    values[':ms'] = BILLING_MODE_SUBSCRIPTION;
    values[':nb'] = nextBillingAt;
    values[':t'] = true;
  } else if (action === 'resume') {
    if (currentMode !== BILLING_MODE_SUBSCRIPTION) return badRequest('resume is available only in subscription mode');
    updates.push('billingMode = :ms', 'nextBillingAt = :nb', 'cancelAtPeriodEnd = :f');
    values[':ms'] = BILLING_MODE_SUBSCRIPTION;
    values[':nb'] = nextBillingAt;
  } else if (action === 'free') {
    if (currentMode !== BILLING_MODE_SUBSCRIPTION) return badRequest('free is available only in subscription mode');
    updates.push(
      'billingMode = :mp',
      'currentPlan = :free',
      'pendingPlan = :null',
      'cancelAtPeriodEnd = :f',
      'nextBillingAt = :null'
    );
    values[':mp'] = BILLING_MODE_PREPAID;
    values[':free'] = 'FREE';
  } else {
    return badRequest('action must be upgrade|downgrade|cancel|resume|free');
  }

  const res = await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `ROOM#${room.roomId}`, SK: 'META#BILLING' },
      UpdateExpression: `SET ${updates.join(', ')}`,
      ExpressionAttributeValues: values,
      ReturnValues: 'ALL_NEW',
    })
  );

  let updated = res.Attributes || authz.billing;
  const secretKey = process.env.STRIPE_SECRET_KEY || '';
  const stripeSubId = String(updated?.stripeSubscriptionId || '').trim();
  if (secretKey && stripeSubId) {
    if (action === 'upgrade') {
      const targetPriceId = subscriptionPriceIdForPlan(targetPlan);
      if (!targetPriceId) return json(500, { message: `stripe price not configured for plan ${targetPlan}` });
      const stripeSub = await stripeUpdateSubscriptionPlan(secretKey, stripeSubId, targetPriceId, 'always_invoice');
      const itemId = stripeSub?.items?.data?.[0]?.id || null;
      const stripePlan = planCodeFromSubscriptionPriceId(stripeSub?.items?.data?.[0]?.price?.id) || targetPlan;
      const reflect = await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME,
          Key: { PK: `ROOM#${room.roomId}`, SK: 'META#BILLING' },
          UpdateExpression:
            'SET currentPlan = :cp, pendingPlan = :null, stripeSubscriptionStatus = :ss, stripeSubscriptionItemId = :si, updatedAt = :u',
          ExpressionAttributeValues: {
            ':cp': stripePlan,
            ':null': null,
            ':ss': stripeSub?.status || 'active',
            ':si': itemId,
            ':u': new Date().toISOString(),
          },
          ReturnValues: 'ALL_NEW',
        })
      );
      updated = reflect.Attributes || updated;
    } else if (action === 'cancel' || action === 'resume') {
      const stripeSub = await stripeSetCancelAtPeriodEnd(secretKey, stripeSubId, action === 'cancel');
      const reflect = await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME,
          Key: { PK: `ROOM#${room.roomId}`, SK: 'META#BILLING' },
          UpdateExpression: 'SET cancelAtPeriodEnd = :c, stripeSubscriptionStatus = :ss, updatedAt = :u',
          ExpressionAttributeValues: {
            ':c': Boolean(stripeSub?.cancel_at_period_end),
            ':ss': stripeSub?.status || updated?.stripeSubscriptionStatus || null,
            ':u': new Date().toISOString(),
          },
          ReturnValues: 'ALL_NEW',
        })
      );
      updated = reflect.Attributes || updated;
    } else if (action === 'free') {
      const stripeSub = await stripeCancelSubscriptionNow(secretKey, stripeSubId);
      const reflect = await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME,
          Key: { PK: `ROOM#${room.roomId}`, SK: 'META#BILLING' },
          UpdateExpression:
            'SET billingMode = :mp, currentPlan = :free, pendingPlan = :null, cancelAtPeriodEnd = :f, nextBillingAt = :null, stripeSubscriptionStatus = :ss, updatedAt = :u',
          ExpressionAttributeValues: {
            ':mp': BILLING_MODE_PREPAID,
            ':free': 'FREE',
            ':null': null,
            ':f': false,
            ':ss': stripeSub?.status || 'canceled',
            ':u': new Date().toISOString(),
          },
          ReturnValues: 'ALL_NEW',
        })
      );
      updated = reflect.Attributes || updated;
    }
  }

  auditLog({
    requestId: ctx?.requestId || null,
    action: 'subscription.change',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    changeAction: action,
    currentPlan,
    targetPlan: targetPlan || null,
    result: 'success',
  });

  return json(200, { ok: true, billing: summarizeBilling(updated) });
}

function stripeCheckoutUrls() {
  return {
    successUrl: process.env.STRIPE_CHECKOUT_SUCCESS_URL || '',
    cancelUrl: process.env.STRIPE_CHECKOUT_CANCEL_URL || '',
  };
}

function parseAllowedReturnOrigins() {
  const raw = process.env.STRIPE_ALLOWED_RETURN_ORIGINS || '';
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function normalizeReturnUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
    // Strip fragments; keep path/query so the app can handle it.
    u.hash = '';
    return u.toString();
  } catch (_) {
    return '';
  }
}

function isAllowedReturnUrl(url, allowedOrigins) {
  try {
    const u = new URL(url);
    return allowedOrigins.includes(u.origin);
  } catch (_) {
    return false;
  }
}

async function listTeamMembers(room, authz) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `ROOM#${room.roomId}`,
        ':sk': 'MEMBER#',
      },
      ScanIndexForward: true,
    })
  );
  const raw = res.Items || [];
  const nameMap = await loadDisplayNameMap(raw.map((m) => m.userKey));
  const items = raw.map((m) => ({
    userKey: m.userKey,
    displayName: nameMap[m.userKey] || '',
    role: m.role || 'member',
    status: normalizeMemberStatus(m.status),
    folderScope: normalizeFolderScope(m.folderScope || m.folder_scope || (isAdminRole(m.role) ? 'all' : 'own')),
    joinedAt: m.joinedAt || null,
    updatedAt: m.updatedAt || null,
  }));
  return json(200, { items });
}

async function updateTeamMember(targetUserKey, event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const body = JSON.parse(event.body || '{}');
  const nextStatus = body.status ? String(body.status).toLowerCase() : null;
  const nextFolderScopeRaw = body.folderScope || body.folder_scope || null;
  const nextFolderScope = nextFolderScopeRaw ? normalizeFolderScope(nextFolderScopeRaw) : null;
  if (nextStatus && nextStatus !== 'active' && nextStatus !== 'disabled' && nextStatus !== 'left') {
    return badRequest('status must be active|disabled|left');
  }
  if (nextFolderScope && nextFolderScope !== 'own' && nextFolderScope !== 'all') return badRequest('folderScope must be own|all');
  if (targetUserKey === room.createdBy) return badRequest('cannot change owner status');
  if (targetUserKey === user.userKey) return badRequest('cannot change self status');

  const key = roomMemberKey(room.roomId, targetUserKey);
  const nowIso = new Date().toISOString();

  const updates = [];
  const values = { ':u': nowIso };
  if (nextStatus) {
    updates.push('status = :s');
    values[':s'] = nextStatus;
  }
  if (nextFolderScope) {
    updates.push('folderScope = :fs');
    values[':fs'] = nextFolderScope;
  }
  if (!updates.length) return badRequest('status or folderScope is required');

  let after = null;
  try {
    const res = await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: key,
        UpdateExpression: `SET ${updates.join(', ')}, updatedAt = :u`,
        ExpressionAttributeValues: values,
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
        ReturnValues: 'ALL_NEW',
      })
    );
    after = res.Attributes || null;
  } catch (_) {
    return json(404, { message: 'member not found' });
  }

  if (!after) {
    const afterRes = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: key }));
    after = afterRes.Item || null;
  }
  if (after) await upsertUserRoomMemberIndex(room, after, nowIso);
  if (nextStatus === 'left') {
    // If the user was currently selecting this room, force-clear it.
    // Keep membership record (status=left) so we can audit and allow re-invite later.
    try {
      await ddb.send(
        new UpdateCommand({
          TableName: TABLE_NAME,
          Key: userRoomMemberKey(targetUserKey, room.roomId),
          UpdateExpression: 'SET #status = :sel, memberStatus = :ms, updatedAt = :u',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: { ':sel': 'inactive', ':ms': 'left', ':u': nowIso },
          ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
        })
      );
    } catch (_) {
      // If the reverse index doesn't exist yet, ignore.
    }
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'team.member.update',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    targetUserKey,
    updates: { status: nextStatus || undefined, folderScope: nextFolderScope || undefined },
    result: 'success',
  });

  return json(200, { ok: true });
}

async function teamLeave(user, room, authz, ctx) {
  // Owner stays as admin; leaving would orphan the team.
  if (authz.isAdmin) return badRequest('owner cannot leave team');

  const nowIso = new Date().toISOString();

  // Mark membership as "left" but keep the record for audit and allow re-invite later.
  // This matches the UI label "メンバーやめる".
  try {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: roomMemberKey(room.roomId, user.userKey),
        UpdateExpression: 'SET #status = :s, updatedAt = :u',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':s': 'left', ':u': nowIso },
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
      })
    );
  } catch (_) {
    // If it doesn't exist, treat as already left.
  }

  try {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: userRoomMemberKey(user.userKey, room.roomId),
        // Clear room selection and reflect membership as left in the reverse index.
        UpdateExpression: 'SET #status = :sel, memberStatus = :ms, updatedAt = :u',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':sel': 'inactive', ':ms': 'left', ':u': nowIso },
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
      })
    );
  } catch (_) {
    // If it doesn't exist yet, ignore.
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'team.leave',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    result: 'success',
  });
  return json(200, { ok: true });
}

async function accountDelete(event, user, ctx) {
  if (!user.fromCognito) return badRequest('account delete requires Cognito login');
  if (!COGNITO_USER_POOL_ID) return json(500, { message: 'cognito is not configured (missing COGNITO_USER_POOL_ID)' });
  const cognitoUsername = String(user.cognitoUsername || '').trim();
  if (!cognitoUsername) return badRequest('cognito username is missing');

  // Room owner must delete their room first.
  const constraint = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: userRoomConstraintKey(user.userKey) }));
  if (constraint.Item) {
    auditLog({
      requestId: ctx.requestId,
      action: 'account.delete',
      actor: user.userKey,
      actorName: user.userName,
      result: 'denied',
      reason: 'owner_must_delete_room_first',
    });
    return badRequest('room owner must delete team first');
  }

  const memberships = await listUserRoomMemberships(user.userKey);
  let removedRoomMemberships = 0;
  for (const m of memberships) {
    const roomId = String(m.roomId || '').trim();
    if (!roomId) continue;
    try {
      await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: roomMemberKey(roomId, user.userKey) }));
      removedRoomMemberships += 1;
    } catch (_) {
      // Best effort.
    }
  }

  const deletedUserItems = await deleteAllByPk(TABLE_NAME, `USER#${user.userKey}`);

  try {
    await cognito.send(
      new AdminDeleteUserCommand({
        UserPoolId: COGNITO_USER_POOL_ID,
        Username: cognitoUsername,
      })
    );
  } catch (error) {
    if (error?.name !== 'UserNotFoundException') throw error;
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'account.delete',
    actor: user.userKey,
    actorName: user.userName,
    removedRoomMemberships,
    deletedUserItems,
    result: 'success',
  });

  return json(200, { ok: true, removedRoomMemberships, deletedUserItems });
}

async function deleteAllByPk(tableName, pk) {
  let lastKey = null;
  let deleted = 0;
  do {
    const res = await ddb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'PK = :pk',
        ExpressionAttributeValues: { ':pk': pk },
        ...(lastKey ? { ExclusiveStartKey: lastKey } : {}),
      })
    );
    const items = res.Items || [];
    for (const item of items) {
      if (!item?.PK || !item?.SK) continue;
      await ddb.send(new DeleteCommand({ TableName: tableName, Key: { PK: item.PK, SK: item.SK } }));
      deleted += 1;
    }
    lastKey = res.LastEvaluatedKey || null;
  } while (lastKey);
  return deleted;
}

async function teamDelete(event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  if (!room.createdBy || room.createdBy !== user.userKey) return json(403, { message: 'forbidden' });

  const nowIso = new Date().toISOString();
  let purgedFolders = 0;
  let purgedPhotos = 0;
  let deletedMembers = 0;
  let deletedBillingItems = 0;
  let deletedExports = 0;

  // 1) Purge folders/photos/comments/S3 in this room.
  const foldersRes = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: { ':pk': 'ORG#DEFAULT', ':sk': 'FOLDER#' },
      ScanIndexForward: true,
    })
  );
  const folders = (foldersRes.Items || []).filter((f) => isRoomMatch(f.roomName, room.roomName));

  for (const folder of folders) {
    const folderId = folder.folderId;
    if (!folderId) continue;

    // Purge photos under this folder via GSI.
    let lastKey = null;
    do {
      const photosRes = await ddb.send(
        new QueryCommand({
          TableName: TABLE_NAME,
          IndexName: 'GSI1',
          KeyConditionExpression: 'GSI1PK = :pk and begins_with(GSI1SK, :sk)',
          ExpressionAttributeValues: {
            ':pk': `FOLDER#${folderId}`,
            ':sk': 'PHOTO#',
          },
          ...(lastKey ? { ExclusiveStartKey: lastKey } : {}),
        })
      );
      const photos = (photosRes.Items || []).filter((p) => isRoomMatch(p.roomName, room.roomName));
      for (const photo of photos) {
        await purgePhotoByItem(photo, room, ctx, user);
        purgedPhotos += 1;
      }
      lastKey = photosRes.LastEvaluatedKey || null;
    } while (lastKey);

    // Delete folder meta + counters.
    await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` } }));
    await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: `FOLDER#${folderId}`, SK: 'META#COUNTER' } }));
    purgedFolders += 1;

    // Delete exports under this folder prefix (best-effort).
    try {
      deletedExports += await deleteS3Prefix(EXPORT_BUCKET, `exports/${room.roomId}/${folderId}/`);
    } catch (_) {
      // ignore
    }
  }

  // 2) Delete membership items for this room + reverse indexes.
  let memberLastKey = null;
  do {
    const res = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
        ExpressionAttributeValues: { ':pk': `ROOM#${room.roomId}`, ':sk': 'MEMBER#' },
        ...(memberLastKey ? { ExclusiveStartKey: memberLastKey } : {}),
      })
    );
    const members = res.Items || [];
    for (const m of members) {
      if (!m?.userKey) continue;
      await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: m.PK, SK: m.SK } }));
      deletedMembers += 1;
      await ddb.send(
        new DeleteCommand({
          TableName: TABLE_NAME,
          Key: userRoomMemberKey(m.userKey, room.roomId),
        })
      );
    }
    memberLastKey = res.LastEvaluatedKey || null;
  } while (memberLastKey);

  // 3) Delete billing meta/charges/purchases/stripe session markers under ROOM#<roomId>.
  deletedBillingItems += await deleteAllByPk(TABLE_NAME, `ROOM#${room.roomId}`);

  // 4) Delete room meta itself.
  await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: 'ORG#DEFAULT', SK: `ROOM#${room.roomName}` } }));

  // 5) Release creator constraint lock so the owner can create a new room later.
  try {
    await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: userRoomConstraintKey(user.userKey) }));
  } catch (_) {
    // Ignore best-effort cleanup.
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'team.delete',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    purgedFolders,
    purgedPhotos,
    deletedMembers,
    deletedBillingItems,
    deletedExports,
    result: 'success',
  });

  return json(200, {
    ok: true,
    purgedFolders,
    purgedPhotos,
    deletedMembers,
    deletedBillingItems,
    deletedExports,
    deletedAt: nowIso,
  });
}

async function loadDisplayNameMap(userKeys) {
  const uniqueKeys = Array.from(new Set((userKeys || []).filter(Boolean)));
  if (!uniqueKeys.length) return {};

  const requestItems = {
    [TABLE_NAME]: {
      Keys: uniqueKeys.map((userKey) => ({ PK: `USER#${userKey}`, SK: 'PROFILE' })),
      ProjectionExpression: 'userKey, displayName',
    },
  };

  const result = await ddb.send(
    new BatchGetCommand({
      RequestItems: requestItems,
    })
  );

  const map = {};
  const rows = result?.Responses?.[TABLE_NAME] || [];
  rows.forEach((row) => {
    const displayName = normalizeDisplayName(row.displayName || '');
    if (row.userKey && displayName) {
      map[row.userKey] = displayName;
    }
  });
  return map;
}

function applyResolvedDisplayName(item, nameMap) {
  if (!item || !item.createdBy) return item;
  const resolved = nameMap[item.createdBy];
  if (!resolved) return item;
  return { ...item, createdByName: resolved };
}

async function listFolders(room, user, authz) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': 'ORG#DEFAULT',
        ':sk': 'FOLDER#',
      },
      ScanIndexForward: false,
    })
  );
  const items = (res.Items || []).filter((item) => isRoomMatch(item.roomName, room.roomName));
  const visible = items.filter((folder) => canAccessFolder(folder, user, authz));
  const nameMap = await loadDisplayNameMap(items.map((item) => item.createdBy));
  const hydrated = visible.map((item) => {
    const base = applyResolvedDisplayName(item, nameMap);
    return { ...base, hasPassword: folderHasPassword(base) };
  });
  const withUsage = await Promise.all(
    hydrated.map(async (folder) => {
      const usageBytes = await sumFolderUsageBytes(folder.folderId, room.roomName);
      return { ...folder, usageBytes };
    })
  );
  return json(200, { items: withUsage });
}

async function sumFolderUsageBytes(folderId, roomName) {
  let lastEvaluatedKey = null;
  let total = 0;
  do {
    const res = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        IndexName: 'GSI1',
        KeyConditionExpression: 'GSI1PK = :pk and begins_with(GSI1SK, :sk)',
        ExpressionAttributeValues: {
          ':pk': `FOLDER#${folderId}`,
          ':sk': 'PHOTO#',
        },
        ProjectionExpression: 'totalBytes, originalBytes, previewBytes, roomName',
        ExclusiveStartKey: lastEvaluatedKey || undefined,
      })
    );
    (res.Items || []).forEach((photo) => {
      if (!isRoomMatch(photo.roomName, roomName)) return;
      const bytes =
        Number(photo.totalBytes || 0) ||
        Number(photo.originalBytes || 0) + Number(photo.previewBytes || 0);
      total += Math.max(0, bytes);
    });
    lastEvaluatedKey = res.LastEvaluatedKey || null;
  } while (lastEvaluatedKey);
  return total;
}

async function createFolder(event, user, room, ctx) {
  const body = JSON.parse(event.body || '{}');
  if (!body.title) return badRequest('title is required');
  const folderPassword = String(body.folderPassword || '').trim();
  if (folderPassword && folderPassword.length > 64) return badRequest('folderPassword is too long');

  const folderId = randomUUID();
  const folderCode = await nextFolderCode();
  const now = new Date().toISOString();
  const item = {
    PK: 'ORG#DEFAULT',
    SK: `FOLDER#${folderId}`,
    type: 'folder',
    folderId,
    folderCode,
    roomName: room.roomName,
    title: body.title,
    createdBy: user.userKey,
    createdByName: user.userName,
    createdAt: now,
    folderPasswordHash: folderPassword ? hashRoomPassword(folderPassword) : null,
    GSI1PK: `FOLDER#${folderId}`,
    GSI1SK: 'META',
  };

  await ddb.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
  auditLog({
    requestId: ctx.requestId,
    action: 'folder.create',
    actor: user.userKey,
    actorName: user.userName,
    folderId,
    folderCode,
    roomName: room.roomName,
    result: 'success',
  });
  return json(201, { ...item, hasPassword: folderHasPassword(item) });
}

async function listPhotos(event, folderId, user, room, authz) {
  const folderRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
    })
  );
  const folder = folderRes.Item;
  if (!folder || !isRoomMatch(folder.roomName, room.roomName)) {
    return json(404, { message: 'folder not found' });
  }
  if (!canAccessFolder(folder, user, authz)) {
    return json(403, { message: 'forbidden' });
  }
  const pw = authz?.isAdmin ? { ok: true } : verifyFolderPassword(folder, event);
  if (!pw.ok) return json(403, { message: 'invalid folder password' });

  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: 'GSI1',
      KeyConditionExpression: 'GSI1PK = :pk and begins_with(GSI1SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `FOLDER#${folderId}`,
        ':sk': 'PHOTO#',
      },
      ScanIndexForward: false,
    })
  );

  const items = (res.Items || []).filter((item) => isRoomMatch(item.roomName, room.roomName));
  const nameMap = await loadDisplayNameMap(items.map((item) => item.createdBy));
  const hydrated = items.map((item) => applyResolvedDisplayName(item, nameMap));

  const withUrls = await Promise.all(
    hydrated.map(async (photo) => {
      const keyForView = photo.previewKey || photo.s3Key;
      if (!keyForView) return photo;
      const viewUrl = await getSignedUrl(
        s3,
        new GetObjectCommand({ Bucket: PHOTO_BUCKET, Key: keyForView }),
        { expiresIn: 600 }
      );
      return { ...photo, viewUrl };
    })
  );

  return json(200, { items: withUrls });
}

async function createUploadUrl(event, folderId, body, user, room, authz) {
  const folderRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
    })
  );
  const folder = folderRes.Item;
  if (!folder || !isRoomMatch(folder.roomName, room.roomName)) {
    return json(404, { message: 'folder not found' });
  }
  if (!canAccessFolder(folder, user, authz)) {
    return json(403, { message: 'forbidden' });
  }
  const pw = authz?.isAdmin ? { ok: true } : verifyFolderPassword(folder, event);
  if (!pw.ok) return json(403, { message: 'invalid folder password' });

  if (isUploadBlocked(authz.billing)) {
    const summary = summarizeBilling(authz.billing);
    return json(402, {
      message: 'storage credits depleted',
      uploadBlocked: true,
      billing: summary,
    });
  }

  const contentType = body.contentType || 'image/jpeg';
  const extension = (body.fileName || 'image.jpg').split('.').pop();
  const photoId = randomUUID();
  const originalKey = `${folderId}/${photoId}.orig.${extension}`;
  const previewKey = `${folderId}/${photoId}.preview.jpg`;

  const originalCmd = new PutObjectCommand({
    Bucket: PHOTO_BUCKET,
    Key: originalKey,
    ContentType: contentType,
  });
  const previewCmd = new PutObjectCommand({
    Bucket: PHOTO_BUCKET,
    Key: previewKey,
    ContentType: 'image/jpeg',
  });

  const originalUploadUrl = await getSignedUrl(s3, originalCmd, { expiresIn: 300 });
  const previewUploadUrl = await getSignedUrl(s3, previewCmd, { expiresIn: 300 });
  return json(200, {
    photoId,
    // Backward compatibility for older frontends.
    uploadUrl: originalUploadUrl,
    s3Key: originalKey,
    originalUploadUrl,
    previewUploadUrl,
    originalS3Key: originalKey,
    previewS3Key: previewKey,
  });
}

async function finalizePhoto(event, folderId, body, user, room, authz, ctx) {
  const originalS3Key = body.originalS3Key || body.s3Key || null;
  const previewS3Key = body.previewS3Key || null;
  if (!body.photoId || !originalS3Key) return badRequest('photoId and originalS3Key are required');
  const folderRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
    })
  );
  const folder = folderRes.Item;
  if (!folder) return json(404, { message: 'folder not found' });
  if (!isRoomMatch(folder.roomName, room.roomName)) return json(404, { message: 'folder not found' });
  if (!canAccessFolder(folder, user, authz)) {
    return json(403, { message: 'forbidden' });
  }
  const pw = authz?.isAdmin ? { ok: true } : verifyFolderPassword(folder, event);
  if (!pw.ok) return json(403, { message: 'invalid folder password' });

  if (isUploadBlocked(authz.billing)) {
    const summary = summarizeBilling(authz.billing);
    return json(402, {
      message: 'storage credits depleted',
      uploadBlocked: true,
      billing: summary,
    });
  }

  const folderCode = folder.folderCode || 'F000';
  const photoCode = await nextPhotoCode(folderId, folderCode);

  // Count original + derived objects (e.g., preview/thumbnail) toward usage.
  let originalBytes = 0;
  let previewBytes = 0;
  try {
    const head = await s3.send(new HeadObjectCommand({ Bucket: PHOTO_BUCKET, Key: originalS3Key }));
    originalBytes = Number(head.ContentLength || 0);
  } catch (_) {
    return badRequest('original object not found (upload may not be completed)');
  }
  if (previewS3Key) {
    try {
      const head = await s3.send(new HeadObjectCommand({ Bucket: PHOTO_BUCKET, Key: previewS3Key }));
      previewBytes = Number(head.ContentLength || 0);
    } catch (_) {
      // Preview is optional; tolerate missing for backward compatibility.
      previewBytes = 0;
    }
  }
  const totalBytes = originalBytes + previewBytes;

  const now = new Date().toISOString();
  const item = {
    PK: `PHOTO#${body.photoId}`,
    SK: 'META',
    type: 'photo',
    photoId: body.photoId,
    folderId,
    folderCode,
    roomName: room.roomName,
    photoCode,
    s3Key: originalS3Key,
    previewKey: previewS3Key,
    originalBytes,
    previewBytes,
    totalBytes,
    fileName: body.fileName || null,
    createdBy: user.userKey,
    createdByName: user.userName,
    createdAt: now,
    GSI1PK: `FOLDER#${folderId}`,
    GSI1SK: `PHOTO#${now}#${body.photoId}`,
  };

  await ddb.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
  if (totalBytes) {
    await addUsageBytes(ddb, {
      tableName: TABLE_NAME,
      roomId: room.roomId,
      deltaBytes: totalBytes,
      nowIso: now,
    });
  }
  auditLog({
    requestId: ctx.requestId,
    action: 'photo.create',
    actor: user.userKey,
    actorName: user.userName,
    folderId,
    photoId: body.photoId,
    photoCode,
    roomName: room.roomName,
    bytes: totalBytes,
    result: 'success',
  });
  return json(201, item);
}

async function deletePhoto(photoId, user, room, authz, ctx) {
  const getRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
    })
  );

  const item = getRes.Item;
  if (!item) return json(404, { message: 'photo not found' });
  if (!isRoomMatch(item.roomName, room.roomName)) return json(404, { message: 'photo not found' });
  if (item.createdBy !== user.userKey && !authz.isAdmin) {
    auditLog({
      requestId: ctx.requestId,
      action: 'photo.delete',
      actor: user.userKey,
      actorName: user.userName,
      photoId,
      result: 'denied',
      reason: 'owner_mismatch',
      owner: item.createdBy,
    });
    return json(403, { message: 'forbidden' });
  }

  await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: `PHOTO#${photoId}`, SK: 'META' } }));
  if (item.s3Key) await s3.send(new DeleteObjectCommand({ Bucket: PHOTO_BUCKET, Key: item.s3Key }));
  if (item.previewKey) await s3.send(new DeleteObjectCommand({ Bucket: PHOTO_BUCKET, Key: item.previewKey }));

  const totalBytes =
    Number(item.totalBytes || 0) ||
    Number(item.originalBytes || 0) + Number(item.previewBytes || 0);
  if (totalBytes) {
    const nowIso = new Date().toISOString();
    await addUsageBytes(ddb, {
      tableName: TABLE_NAME,
      roomId: room.roomId,
      deltaBytes: -totalBytes,
      nowIso,
    });
  }
  auditLog({
    requestId: ctx.requestId,
    action: 'photo.delete',
    actor: user.userKey,
    actorName: user.userName,
    photoId,
    photoCode: item.photoCode || null,
    bytes: totalBytes || 0,
    result: 'success',
  });

  return json(200, { ok: true });
}

async function updatePhoto(photoId, body, user, room, authz, ctx) {
  const nextFileName = (body.fileName || '').trim();
  if (!nextFileName) return badRequest('fileName is required');

  const getRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
    })
  );

  const item = getRes.Item;
  if (!item) return json(404, { message: 'photo not found' });
  if (!isRoomMatch(item.roomName, room.roomName)) return json(404, { message: 'photo not found' });
  if (item.createdBy !== user.userKey && !authz.isAdmin) {
    auditLog({
      requestId: ctx.requestId,
      action: 'photo.update',
      actor: user.userKey,
      actorName: user.userName,
      photoId,
      result: 'denied',
      reason: 'owner_mismatch',
      owner: item.createdBy,
    });
    return json(403, { message: 'forbidden' });
  }

  const updatedAt = new Date().toISOString();
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
      UpdateExpression: 'SET fileName = :fileName, updatedAt = :updatedAt',
      ExpressionAttributeValues: {
        ':fileName': nextFileName,
        ':updatedAt': updatedAt,
      },
    })
  );
  auditLog({
    requestId: ctx.requestId,
    action: 'photo.update',
    actor: user.userKey,
    actorName: user.userName,
    photoId,
    photoCode: item.photoCode || null,
    updates: { fileName: nextFileName },
    result: 'success',
  });

  return json(200, { ok: true });
}

async function listComments(photoId, room) {
  const photoRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
    })
  );
  const photo = photoRes.Item;
  if (!photo || !isRoomMatch(photo.roomName, room.roomName)) {
    return json(404, { message: 'photo not found' });
  }

  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `PHOTO#${photoId}`,
        ':sk': 'COMMENT#',
      },
      ScanIndexForward: true,
    })
  );

  const items = (res.Items || []).filter((item) => isRoomMatch(item.roomName, room.roomName));
  const nameMap = await loadDisplayNameMap(items.map((item) => item.createdBy));
  const hydrated = items.map((item) => applyResolvedDisplayName(item, nameMap));
  return json(200, { items: hydrated });
}

async function createComment(photoId, body, user, room, ctx) {
  if (!body.text) return badRequest('text is required');
  const photoRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
    })
  );
  const photo = photoRes.Item;
  if (!photo || !isRoomMatch(photo.roomName, room.roomName)) {
    return json(404, { message: 'photo not found' });
  }
  const commentId = randomUUID();
  const now = new Date().toISOString();

  const item = {
    PK: `PHOTO#${photoId}`,
    SK: `COMMENT#${now}#${commentId}`,
    type: 'comment',
    photoId,
    commentId,
    roomName: room.roomName,
    text: body.text,
    createdBy: user.userKey,
    createdByName: user.userName,
    createdAt: now,
    GSI1PK: `PHOTO#${photoId}`,
    GSI1SK: `COMMENT#${now}#${commentId}`,
  };

  await ddb.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
  // Best-effort: maintain comment summary on the photo to avoid N+1 comment fetches in the frontend.
  try {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
        UpdateExpression: 'SET latestCommentAt = :t, latestCommentBy = :b, latestCommentByName = :bn, updatedAt = :u',
        ExpressionAttributeValues: {
          ':t': now,
          ':b': user.userKey,
          ':bn': user.userName,
          ':u': now,
        },
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
      })
    );
  } catch (_) {
    // Ignore best-effort summary updates.
  }
  auditLog({
    requestId: ctx.requestId,
    action: 'comment.create',
    actor: user.userKey,
    actorName: user.userName,
    photoId,
    commentId,
    result: 'success',
  });
  return json(201, item);
}

async function deleteComment(photoId, commentId, user, room, authz, ctx) {
  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `PHOTO#${photoId}`,
        ':sk': 'COMMENT#',
      },
    })
  );

  const found = (res.Items || []).find(
    (item) => item.commentId === commentId && isRoomMatch(item.roomName, room.roomName)
  );
  if (!found) return json(404, { message: 'comment not found' });
  if (found.createdBy !== user.userKey && !authz.isAdmin) {
    auditLog({
      requestId: ctx.requestId,
      action: 'comment.delete',
      actor: user.userKey,
      actorName: user.userName,
      photoId,
      commentId,
      result: 'denied',
      reason: 'owner_mismatch',
      owner: found.createdBy,
    });
    return json(403, { message: 'forbidden' });
  }

  await ddb.send(
    new DeleteCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: found.SK },
    })
  );
  auditLog({
    requestId: ctx.requestId,
    action: 'comment.delete',
    actor: user.userKey,
    actorName: user.userName,
    photoId,
    commentId,
    result: 'success',
  });

  return json(200, { ok: true });
}

async function updateComment(photoId, commentId, body, user, room, authz, ctx) {
  if (!body.text || !body.text.trim()) return badRequest('text is required');

  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `PHOTO#${photoId}`,
        ':sk': 'COMMENT#',
      },
    })
  );

  const found = (res.Items || []).find(
    (item) => item.commentId === commentId && isRoomMatch(item.roomName, room.roomName)
  );
  if (!found) return json(404, { message: 'comment not found' });
  if (found.createdBy !== user.userKey && !authz.isAdmin) {
    auditLog({
      requestId: ctx.requestId,
      action: 'comment.update',
      actor: user.userKey,
      actorName: user.userName,
      photoId,
      commentId,
      result: 'denied',
      reason: 'owner_mismatch',
      owner: found.createdBy,
    });
    return json(403, { message: 'forbidden' });
  }

  const updatedAt = new Date().toISOString();
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: found.SK },
      UpdateExpression: 'SET #t = :text, updatedAt = :updatedAt',
      ExpressionAttributeNames: { '#t': 'text' },
      ExpressionAttributeValues: {
        ':text': body.text.trim(),
        ':updatedAt': updatedAt,
      },
      ReturnValues: 'ALL_NEW',
    })
  );
  auditLog({
    requestId: ctx.requestId,
    action: 'comment.update',
    actor: user.userKey,
    actorName: user.userName,
    photoId,
    commentId,
    result: 'success',
  });

  return json(200, { ok: true });
}

async function exportFolder(event, folderId, user, room, authz, ctx) {
  const folderRes = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': 'ORG#DEFAULT',
        ':sk': `FOLDER#${folderId}`,
      },
      Limit: 1,
    })
  );

  const folder = (folderRes.Items || [])[0];
  if (!folder) return json(404, { message: 'folder not found' });
  if (!isRoomMatch(folder.roomName, room.roomName)) return json(404, { message: 'folder not found' });
  if (!canAccessFolder(folder, user, authz)) return json(403, { message: 'forbidden' });
  const pw = authz?.isAdmin ? { ok: true } : verifyFolderPassword(folder, event);
  if (!pw.ok) return json(403, { message: 'invalid folder password' });

  const photosRes = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      IndexName: 'GSI1',
      KeyConditionExpression: 'GSI1PK = :pk and begins_with(GSI1SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `FOLDER#${folderId}`,
        ':sk': 'PHOTO#',
      },
    })
  );

  const photos = (photosRes.Items || []).filter((item) => isRoomMatch(item.roomName, room.roomName));
  const pptx = new PptxGenJS();
  pptx.layout = 'LAYOUT_WIDE';

  for (const photo of photos) {
    const slide = pptx.addSlide();
    slide.addText(`${folder.folderCode || 'F000'} ${folder.title}`, {
      x: 0.5,
      y: 0.2,
      w: 12,
      h: 0.4,
      fontSize: 16,
      bold: true,
    });
    slide.addText(`${photo.photoCode || '-'} ${photo.fileName || photo.photoId}`, {
      x: 0.5,
      y: 0.7,
      w: 12,
      h: 0.3,
      fontSize: 11,
    });

    const signed = await getSignedUrl(
      s3,
      new GetObjectCommand({ Bucket: PHOTO_BUCKET, Key: photo.s3Key }),
      { expiresIn: 300 }
    );

    const imageX = 0.5;
    const imageY = 1.2;
    const imageW = 8.5;
    const imageH = 4.8;
    slide.addImage({
      path: signed,
      x: imageX,
      y: imageY,
      w: imageW,
      h: imageH,
      // Keep original aspect ratio and fit inside the frame.
      sizing: { type: 'contain', x: imageX, y: imageY, w: imageW, h: imageH },
    });

    const commentsRes = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
        ExpressionAttributeValues: {
          ':pk': `PHOTO#${photo.photoId}`,
          ':sk': 'COMMENT#',
        },
      })
    );

    const comments = commentsRes.Items || [];
    const commentNameMap = await loadDisplayNameMap(comments.map((c) => c.createdBy));
    const commentLines = comments.map((c, idx) => {
      const createdByName = commentNameMap[c.createdBy] || c.createdByName || 'unknown';
      return `${idx + 1}. ${c.text} (${createdByName})`;
    });

    slide.addText(commentLines.length ? commentLines.join('\n') : 'コメントなし', {
      x: 9.2,
      y: 1.2,
      w: 3.8,
      h: 4.8,
      fontSize: 10,
      valign: 'top',
      color: '333333',
    });
  }

  const pptxBuffer = await pptx.write({ outputType: 'nodebuffer' });
  // Include roomId/folderId in the key so we can delete exports on folder/team deletion.
  const safeTitle = String(folder.title || 'folder').replace(/[^a-zA-Z0-9_-]+/g, '_').slice(0, 40) || 'folder';
  const key = `exports/${room.roomId}/${folderId}/${safeTitle}_${Date.now()}.pptx`;
  await s3.send(
    new PutObjectCommand({
      Bucket: EXPORT_BUCKET,
      Key: key,
      Body: pptxBuffer,
      ContentType:
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    })
  );

  const downloadUrl = await getSignedUrl(
    s3,
    new GetObjectCommand({ Bucket: EXPORT_BUCKET, Key: key }),
    { expiresIn: 600 }
  );
  auditLog({
    requestId: ctx.requestId,
    action: 'folder.export_pptx',
    actor: user.userKey,
    actorName: user.userName,
    folderId,
    result: 'success',
    exportKey: key,
  });

  return json(200, { key, downloadUrl });
}

async function deleteAllCommentsForPhoto(photoId) {
  let lastKey = null;
  do {
    const res = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
        ExpressionAttributeValues: {
          ':pk': `PHOTO#${photoId}`,
          ':sk': 'COMMENT#',
        },
        ...(lastKey ? { ExclusiveStartKey: lastKey } : {}),
      })
    );
    const items = res.Items || [];
    for (const item of items) {
      await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: item.PK, SK: item.SK } }));
    }
    lastKey = res.LastEvaluatedKey || null;
  } while (lastKey);
}

async function purgePhotoByItem(photoItem, room, ctx, actor) {
  if (!photoItem || !photoItem.photoId) return;
  if (!isRoomMatch(photoItem.roomName, room.roomName)) return;

  await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: `PHOTO#${photoItem.photoId}`, SK: 'META' } }));
  if (photoItem.s3Key) await s3.send(new DeleteObjectCommand({ Bucket: PHOTO_BUCKET, Key: photoItem.s3Key }));
  if (photoItem.previewKey) await s3.send(new DeleteObjectCommand({ Bucket: PHOTO_BUCKET, Key: photoItem.previewKey }));
  await deleteAllCommentsForPhoto(photoItem.photoId);

  const totalBytes =
    Number(photoItem.totalBytes || 0) ||
    Number(photoItem.originalBytes || 0) + Number(photoItem.previewBytes || 0);
  if (totalBytes) {
    const nowIso = new Date().toISOString();
    await addUsageBytes(ddb, {
      tableName: TABLE_NAME,
      roomId: room.roomId,
      deltaBytes: -totalBytes,
      nowIso,
    });
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'photo.purge',
    actor: actor.userKey,
    actorName: actor.userName,
    photoId: photoItem.photoId,
    photoCode: photoItem.photoCode || null,
    bytes: totalBytes || 0,
    result: 'success',
  });
}

async function deleteS3Prefix(bucket, prefix) {
  if (!bucket || !prefix) return 0;
  let deleted = 0;
  let token = null;
  do {
    const res = await s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: token || undefined,
      })
    );
    const contents = res.Contents || [];
    const objects = contents.map((c) => ({ Key: c.Key })).filter((o) => o.Key);
    if (objects.length) {
      await s3.send(
        new DeleteObjectsCommand({
          Bucket: bucket,
          Delete: { Objects: objects, Quiet: true },
        })
      );
      deleted += objects.length;
    }
    token = res.IsTruncated ? res.NextContinuationToken : null;
  } while (token);
  return deleted;
}

async function deleteFolder(event, folderId, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });

  const folderRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
    })
  );
  const folder = folderRes.Item;
  if (!folder || !isRoomMatch(folder.roomName, room.roomName)) {
    return json(404, { message: 'folder not found' });
  }
  const pw = authz?.isAdmin ? { ok: true } : verifyFolderPassword(folder, event);
  if (!pw.ok) return json(403, { message: 'invalid folder password' });

  let lastKey = null;
  let purgedPhotos = 0;
  do {
    const photosRes = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        IndexName: 'GSI1',
        KeyConditionExpression: 'GSI1PK = :pk and begins_with(GSI1SK, :sk)',
        ExpressionAttributeValues: {
          ':pk': `FOLDER#${folderId}`,
          ':sk': 'PHOTO#',
        },
        ...(lastKey ? { ExclusiveStartKey: lastKey } : {}),
      })
    );
    const photos = (photosRes.Items || []).filter((p) => isRoomMatch(p.roomName, room.roomName));
    for (const photo of photos) {
      await purgePhotoByItem(photo, room, ctx, user);
      purgedPhotos += 1;
    }
    lastKey = photosRes.LastEvaluatedKey || null;
  } while (lastKey);

  await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` } }));
  // Best-effort: remove per-folder counter item too.
  await ddb.send(new DeleteCommand({ TableName: TABLE_NAME, Key: { PK: `FOLDER#${folderId}`, SK: 'META#COUNTER' } }));
  // Best-effort: delete exports created under this folder.
  try {
    await deleteS3Prefix(EXPORT_BUCKET, `exports/${room.roomId}/${folderId}/`);
  } catch (_) {
    // Ignore.
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'folder.delete',
    actor: user.userKey,
    actorName: user.userName,
    folderId,
    folderCode: folder.folderCode || null,
    roomName: room.roomName,
    purgedPhotos,
    result: 'success',
  });
  return json(200, { ok: true, purgedPhotos });
}

async function updateFolderPassword(event, folderId, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const body = JSON.parse(event.body || '{}');
  const next = String(body.folderPassword || '').trim();
  if (next && next.length > 64) return badRequest('folderPassword is too long');

  const folderRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
    })
  );
  const folder = folderRes.Item;
  if (!folder || !isRoomMatch(folder.roomName, room.roomName)) return json(404, { message: 'folder not found' });

  const nowIso = new Date().toISOString();
  if (!next) {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
        UpdateExpression: 'REMOVE folderPasswordHash SET updatedAt = :u',
        ExpressionAttributeValues: { ':u': nowIso },
      })
    );
  } else {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
        UpdateExpression: 'SET folderPasswordHash = :h, updatedAt = :u',
        ExpressionAttributeValues: { ':h': hashRoomPassword(next), ':u': nowIso },
      })
    );
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'folder.password.update',
    actor: user.userKey,
    actorName: user.userName,
    folderId,
    roomName: room.roomName,
    result: 'success',
  });

  return json(200, { ok: true, hasPassword: Boolean(next) });
}

exports.handler = async (event) => {
  try {
    const method = event.requestContext.http.method;
    const path = event.requestContext.http.path;
    const isRoomCreate = method === 'POST' && path === '/rooms/create';
    let room = null;
    const user = await getUser(event);

    const p = event.pathParameters || {};
    const body = event.body ? JSON.parse(event.body) : {};
    const ctx = { requestId: event.requestContext?.requestId || null };

    if (method === 'GET' && path === '/me') return await getMe(user);
    if (method === 'PUT' && path === '/me/display-name') return await updateDisplayName(event, user, ctx);

    if (method === 'GET' && path === '/team/me') return await teamMeAuto(event, user, ctx);
    if (method === 'POST' && path === '/account/delete') return await accountDelete(event, user, ctx);

    if (method === 'GET' && path === '/rooms/mine') return await listMyRooms(user);
    if (method === 'POST' && path === '/rooms/switch') return await switchActiveRoom(event, user, ctx);

    if (method === 'POST' && path === '/invites/accept') return await acceptInvite(event, user, ctx);

    if (isRoomCreate) return await createRoom(event, user, ctx);

    room = await resolveRoomForRequest(event, user);
    const authzRes = await requireActiveMember(room, user, ctx);
    if (!authzRes.ok) return authzRes.response;
    const authz = authzRes;

    if (method === 'POST' && path === '/invites/create') return await createInvite(event, user, room, authz, ctx);
    if (method === 'POST' && path === '/invites/revoke') return await revokeInvite(event, user, room, authz, ctx);

    if (method === 'GET' && path === '/team/billing') return await teamBilling(authz);
    if (method === 'GET' && path === '/team/subscription') return await teamSubscription(room, authz);
    if (method === 'POST' && path === '/team/subscription/checkout') {
      return await teamSubscriptionCheckout(event, user, room, authz, ctx);
    }
    if (method === 'POST' && path === '/team/subscription/change') {
      return await changeTeamSubscription(event, user, room, authz, ctx);
    }
    if (method === 'GET' && path === '/team/members') return await listTeamMembers(room, authz);
    if (method === 'PUT' && p.userKey && path.endsWith(`/team/members/${p.userKey}`)) {
      return await updateTeamMember(p.userKey, event, user, room, authz, ctx);
    }
    if (method === 'POST' && path === '/team/leave') return await teamLeave(user, room, authz, ctx);
    if (method === 'POST' && path === '/team/delete') return await teamDelete(event, user, room, authz, ctx);

    if (method === 'GET' && path === '/folders') return await listFolders(room, user, authz);
    if (method === 'POST' && path === '/folders') return await createFolder(event, user, room, ctx);
    if (method === 'DELETE' && p.folderId && path.endsWith(`/folders/${p.folderId}`)) {
      return await deleteFolder(event, p.folderId, user, room, authz, ctx);
    }
    if (method === 'PUT' && p.folderId && path.endsWith(`/folders/${p.folderId}/password`)) {
      return await updateFolderPassword(event, p.folderId, user, room, authz, ctx);
    }

    if (method === 'GET' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos`)) {
      return await listPhotos(event, p.folderId, user, room, authz);
    }
    if (method === 'POST' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos/upload-url`)) {
      return await createUploadUrl(event, p.folderId, body, user, room, authz);
    }
    if (method === 'POST' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos`)) {
      return await finalizePhoto(event, p.folderId, body, user, room, authz, ctx);
    }

    if (method === 'DELETE' && p.photoId && path.endsWith(`/photos/${p.photoId}`)) {
      return await deletePhoto(p.photoId, user, room, authz, ctx);
    }
    if (method === 'PUT' && p.photoId && path.endsWith(`/photos/${p.photoId}`)) {
      return await updatePhoto(p.photoId, body, user, room, authz, ctx);
    }

    if (method === 'GET' && p.photoId && path.endsWith(`/photos/${p.photoId}/comments`)) {
      return await listComments(p.photoId, room);
    }
    if (method === 'POST' && p.photoId && path.endsWith(`/photos/${p.photoId}/comments`)) {
      return await createComment(p.photoId, body, user, room, ctx);
    }
    if (
      method === 'DELETE' &&
      p.photoId &&
      p.commentId &&
      path.endsWith(`/photos/${p.photoId}/comments/${p.commentId}`)
    ) {
      return await deleteComment(p.photoId, p.commentId, user, room, authz, ctx);
    }
    if (
      method === 'PUT' &&
      p.photoId &&
      p.commentId &&
      path.endsWith(`/photos/${p.photoId}/comments/${p.commentId}`)
    ) {
      return await updateComment(p.photoId, p.commentId, body, user, room, authz, ctx);
    }

    if (method === 'POST' && p.folderId && path.endsWith(`/folders/${p.folderId}/export`)) {
      return await exportFolder(event, p.folderId, user, room, authz, ctx);
    }

    return json(404, { message: 'not found' });
  } catch (error) {
    if (error.message === 'MISSING_USER_KEY') {
      return json(401, { message: 'unauthorized' });
    }
    if (error.message === 'MISSING_ROOM') {
      // Room selection is membership-based. Missing room means the user must create/join via invite URL.
      return json(403, { message: 'no active room' });
    }
    if (error.message === 'INVALID_ROOM') {
      return json(403, { message: 'invalid room credentials' });
    }
    if (error.message === 'INVALID_DISPLAY_NAME_LENGTH') {
      return badRequest('displayName must be 40 characters or fewer');
    }
    console.error(error);
    return json(500, { message: 'internal server error' });
  }
};
