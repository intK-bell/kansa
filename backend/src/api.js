const { randomUUID } = require('node:crypto');
const { pbkdf2Sync, randomBytes, timingSafeEqual } = require('node:crypto');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
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

const { encodeCheckoutSessionParams, stripePostForm } = require('./stripe-rest');

const {
  FREE_BYTES_DEFAULT,
  GBMONTH_DAYS,
  GIB_BYTES,
  formatJstDate,
  ensureBillingMeta,
  getBillingMeta,
  addGibDaysBalance,
  addUsageBytes,
  summarizeBilling,
} = require('./billing');

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});

const TABLE_NAME = process.env.TABLE_NAME;
const PHOTO_BUCKET = process.env.PHOTO_BUCKET;
const EXPORT_BUCKET = process.env.EXPORT_BUCKET;

const json = (statusCode, body) => ({
  statusCode,
  headers: {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
  },
  body: JSON.stringify(body),
});

const badRequest = (message) => json(400, { message });

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
    return { userKey: claims.sub, fallbackName, fromCognito: true };
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

function getRoomRequest(event, method) {
  const upper = String(method || 'GET').toUpperCase();
  const headers = event.headers || {};
  const fromHeaders = {
    roomName: decodeText(headers['x-room-name'] || headers['X-Room-Name'] || ''),
    roomPassword: decodeText(headers['x-room-password'] || headers['X-Room-Password'] || ''),
  };
  if (fromHeaders.roomName && fromHeaders.roomPassword) return fromHeaders;
  if (upper === 'GET') {
    const q = event.queryStringParameters || {};
    return {
      roomName: decodeText(q.roomName || ''),
      roomPassword: decodeText(q.roomPassword || ''),
    };
  }
  return fromHeaders;
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

async function resolveRoom(roomName, roomPassword) {
  if (!roomName || !roomPassword) {
    throw new Error('MISSING_ROOM');
  }

  const res = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `ROOM#${roomName}` },
    })
  );
  const room = res.Item;
  if (!room) throw new Error('INVALID_ROOM');

  if (room.passwordHash) {
    if (!verifyRoomPassword(roomPassword, room.passwordHash)) {
      throw new Error('INVALID_ROOM');
    }
    return { roomName: room.roomName, roomId: room.roomId, createdBy: room.createdBy || null };
  }

  // Legacy: plain password. Accept it once, then migrate to hash.
  if (room.password !== roomPassword) {
    throw new Error('INVALID_ROOM');
  }
  const migratedHash = hashRoomPassword(roomPassword);
  try {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { PK: 'ORG#DEFAULT', SK: `ROOM#${roomName}` },
        UpdateExpression: 'SET passwordHash = :h REMOVE password',
        ExpressionAttributeValues: { ':h': migratedHash },
      })
    );
  } catch (_) {
    // Best-effort migration; auth still succeeds.
  }
  return { roomName: room.roomName, roomId: room.roomId, createdBy: room.createdBy || null };
}

function roomMemberKey(roomId, userKey) {
  return { PK: `ROOM#${roomId}`, SK: `MEMBER#${userKey}` };
}

function userRoomMemberKey(userKey, roomId) {
  return { PK: `USER#${userKey}`, SK: `ROOMMEMBER#${roomId}` };
}

function isAdminRole(role) {
  return String(role || '').toLowerCase() === 'admin';
}

async function upsertUserRoomMemberIndex(room, member, nowIso) {
  if (!room?.roomId || !member?.userKey) return;
  const key = userRoomMemberKey(member.userKey, room.roomId);
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: key,
      UpdateExpression:
        'SET #type = if_not_exists(#type, :type), roomId = :roomId, roomName = :roomName, userKey = :userKey, #role = :role, #status = :status, joinedAt = if_not_exists(joinedAt, :joinedAt), updatedAt = :updatedAt',
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
        ':status': member.status || 'active',
        ':joinedAt': member.joinedAt || nowIso,
        ':updatedAt': nowIso,
      },
    })
  );
}

async function ensureRoomMember(room, user, nowIso, ctx) {
  const key = roomMemberKey(room.roomId, user.userKey);
  const existing = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: key }));
  if (existing.Item) {
    await upsertUserRoomMemberIndex(room, existing.Item, nowIso);
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
    if (retry.Item) await upsertUserRoomMemberIndex(room, retry.Item, nowIso);
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
  return { ok: true, member, isAdmin: isAdminRole(member.role), billing };
}

function isUploadBlocked(billing) {
  const usageBytes = Number(billing?.usageBytes || 0);
  const freeBytes = Number(billing?.freeBytes || FREE_BYTES_DEFAULT);
  const gibDaysBalance = Number(billing?.gibDaysBalance || 0);
  return gibDaysBalance <= 0 && usageBytes >= freeBytes;
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
  const roomPassword = (body.roomPassword || '').trim();
  if (!roomName || !roomPassword) return badRequest('roomName and roomPassword are required');

  // メンバーとしてチームに所属中のユーザーは、脱退するまで新しい部屋を作れない。
  // ここでは「1人1部屋」運用: active所属が1つでもあれば作成不可。
  try {
    const membershipRes = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
        ExpressionAttributeValues: {
          ':pk': `USER#${user.userKey}`,
          ':sk': 'ROOMMEMBER#',
        },
        ScanIndexForward: true,
      })
    );
    const memberships = membershipRes.Items || [];
    const hasActiveTeam = memberships.some((m) => String(m.status || 'active') === 'active');
    if (hasActiveTeam) {
      return json(409, { message: 'already has a room' });
    }
  } catch (_) {
    // If the index isn't populated yet, don't block room creation.
  }

  const roomId = randomUUID();
  const now = new Date().toISOString();
  const item = {
    PK: 'ORG#DEFAULT',
    SK: `ROOM#${roomName}`,
    type: 'room',
    roomId,
    roomName,
    passwordHash: hashRoomPassword(roomPassword),
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
  } catch (_) {
    // Ignore; membership will be ensured on first authenticated call.
  }
  return json(201, { roomName, roomId });
}

async function getActiveRoomIdForUser(userKey) {
  if (!userKey) return null;
  const res = await ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': `USER#${userKey}`,
        ':sk': 'ROOMMEMBER#',
      },
      ScanIndexForward: true,
    })
  );
  const items = res.Items || [];
  const active = items.find((m) => String(m.status || 'active') === 'active');
  return active?.roomId || null;
}

async function enterRoom(event, user, ctx) {
  const body = JSON.parse(event.body || '{}');
  const roomName = (body.roomName || '').trim();
  const roomPassword = (body.roomPassword || '').trim();
  const room = await resolveRoom(roomName, roomPassword);
  const activeRoomId = await getActiveRoomIdForUser(user.userKey);
  if (activeRoomId && activeRoomId !== room.roomId) {
    auditLog({
      requestId: ctx.requestId,
      action: 'room.enter',
      actor: user.userKey,
      actorName: user.userName,
      roomName,
      result: 'denied',
      reason: 'already_in_another_room',
      activeRoomId,
      requestedRoomId: room.roomId,
    });
    return json(403, { message: 'already in another room' });
  }
  return json(200, room);
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

async function teamBilling(authz) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const billing = summarizeBilling(authz.billing);
  return json(200, { billing });
}

function parsePurchaseSku(sku) {
  const value = String(sku || '').trim().toLowerCase();
  if (value === '1gbm') return { gbMonths: 1, yen: 1000 };
  if (value === '10gbm') return { gbMonths: 10, yen: 8000 };
  if (value === '50gbm') return { gbMonths: 50, yen: 35000 };
  return null;
}

function stripePriceIdForSku(sku) {
  const value = String(sku || '').trim().toLowerCase();
  if (value === '1gbm') return process.env.STRIPE_PRICE_1GBM || '';
  if (value === '10gbm') return process.env.STRIPE_PRICE_10GBM || '';
  if (value === '50gbm') return process.env.STRIPE_PRICE_50GBM || '';
  return '';
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

async function teamPurchaseCheckout(event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const secretKey = process.env.STRIPE_SECRET_KEY || '';
  if (!secretKey) return json(500, { message: 'stripe is not configured (missing STRIPE_SECRET_KEY)' });

  const body = JSON.parse(event.body || '{}');
  const parsed = parsePurchaseSku(body.sku);
  if (!parsed) return badRequest('sku is required (1gbm|10gbm|50gbm)');
  const priceId = stripePriceIdForSku(body.sku);
  if (!priceId) return json(500, { message: 'stripe is not configured (missing price id)' });

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
  const params = encodeCheckoutSessionParams({
    priceId,
    successUrl,
    cancelUrl,
    metadata: {
      sku: String(body.sku || '').trim().toLowerCase(),
      gbMonths: String(parsed.gbMonths),
      roomId: room.roomId,
      roomName: room.roomName,
      purchasedBy: user.userKey,
      purchasedByName: user.userName,
      createdAt: nowIso,
    },
  });

  const session = await stripePostForm({ secretKey, path: '/v1/checkout/sessions', params });

  auditLog({
    requestId: ctx.requestId,
    action: 'billing.checkout.create',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    sku: String(body.sku || ''),
    stripeSessionId: session.id || null,
    result: 'success',
  });

  return json(200, { url: session.url, sessionId: session.id });
}

async function teamPurchase(event, user, room, authz, ctx) {
  // Deprecated manual credit endpoint. Keep it for emergency/dev only.
  // Use Stripe Checkout (/team/purchase/checkout) + webhook crediting in normal operation.
  if ((process.env.ALLOW_MANUAL_CREDIT || '').toLowerCase() !== 'true') {
    return json(410, { message: 'purchase endpoint moved to stripe checkout' });
  }
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const body = JSON.parse(event.body || '{}');
  const parsed = parsePurchaseSku(body.sku);
  if (!parsed) return badRequest('sku is required (1gbm|10gbm|50gbm)');

  const nowIso = new Date().toISOString();
  const deltaGibDays = parsed.gbMonths * GBMONTH_DAYS;

  const updated = await addGibDaysBalance(ddb, {
    tableName: TABLE_NAME,
    roomId: room.roomId,
    deltaGibDays,
    nowIso,
  });

  const purchaseId = randomUUID();
  await ddb.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        PK: `ROOM#${room.roomId}`,
        SK: `PURCHASE#${nowIso}#${purchaseId}`,
        type: 'billing_purchase',
        roomId: room.roomId,
        roomName: room.roomName,
        sku: body.sku,
        gbMonths: parsed.gbMonths,
        deltaGibDays,
        yen: parsed.yen,
        purchasedBy: user.userKey,
        purchasedByName: user.userName,
        createdAt: nowIso,
      },
    })
  );

  auditLog({
    requestId: ctx.requestId,
    action: 'billing.purchase',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    sku: body.sku,
    gbMonths: parsed.gbMonths,
    yen: parsed.yen,
    result: 'success',
  });

  return json(200, { ok: true, billing: summarizeBilling(updated) });
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
  const items = (res.Items || []).map((m) => ({
    userKey: m.userKey,
    role: m.role || 'member',
    status: m.status || 'active',
    joinedAt: m.joinedAt || null,
    updatedAt: m.updatedAt || null,
  }));
  return json(200, { items });
}

async function updateTeamMember(targetUserKey, event, user, room, authz, ctx) {
  if (!authz.isAdmin) return json(403, { message: 'forbidden' });
  const body = JSON.parse(event.body || '{}');
  const nextStatus = body.status ? String(body.status).toLowerCase() : null;
  if (nextStatus && nextStatus !== 'active' && nextStatus !== 'disabled') return badRequest('status must be active|disabled');
  if (targetUserKey === room.createdBy) return badRequest('cannot change owner status');

  const key = roomMemberKey(room.roomId, targetUserKey);
  const nowIso = new Date().toISOString();

  const updates = [];
  const values = { ':u': nowIso };
  if (nextStatus) {
    updates.push('status = :s');
    values[':s'] = nextStatus;
  }
  if (!updates.length) return badRequest('status is required');

  try {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: key,
        UpdateExpression: `SET ${updates.join(', ')}, updatedAt = :u`,
        ExpressionAttributeValues: values,
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
        ReturnValues: 'ALL_NEW',
      })
    );
  } catch (_) {
    return json(404, { message: 'member not found' });
  }

  const afterRes = await ddb.send(new GetCommand({ TableName: TABLE_NAME, Key: key }));
  if (afterRes.Item) {
    await upsertUserRoomMemberIndex(room, afterRes.Item, nowIso);
  }

  auditLog({
    requestId: ctx.requestId,
    action: 'team.member.update',
    actor: user.userKey,
    actorName: user.userName,
    roomId: room.roomId,
    roomName: room.roomName,
    targetUserKey,
    updates: { status: nextStatus || undefined },
    result: 'success',
  });

  return json(200, { ok: true });
}

async function teamLeave(user, room, authz, ctx) {
  // Owner stays as admin; leaving would orphan the team.
  if (authz.isAdmin) return badRequest('owner cannot leave team');

  const nowIso = new Date().toISOString();
  const key = roomMemberKey(room.roomId, user.userKey);
  try {
    await ddb.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: key,
        UpdateExpression: 'SET #status = :s, updatedAt = :u',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: { ':s': 'left', ':u': nowIso },
        ConditionExpression: 'attribute_exists(PK) and attribute_exists(SK)',
      })
    );
  } catch (_) {
    // If it doesn't exist, treat as already left.
  }

  await upsertUserRoomMemberIndex(
    room,
    { userKey: user.userKey, role: authz.member.role || 'member', status: 'left', joinedAt: authz.member.joinedAt || nowIso },
    nowIso
  );

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

async function deleteAllByPk(tableName, pk) {
  let lastKey = null;
  let deleted = 0;
  do {
    const res = await ddb.send(
      new QueryCommand({
        TableName: tableName,
        KeyConditionExpression: 'PK = :pk',
        ExpressionAttributeValues: { ':pk': pk },
        ExclusiveStartKey: lastKey,
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
          ExclusiveStartKey: lastKey,
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
        ExclusiveStartKey: memberLastKey,
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

async function listFolders(room) {
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
  const nameMap = await loadDisplayNameMap(items.map((item) => item.createdBy));
  const hydrated = items.map((item) => {
    const base = applyResolvedDisplayName(item, nameMap);
    return { ...base, hasPassword: folderHasPassword(base) };
  });
  return json(200, { items: hydrated });
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

async function listPhotos(event, folderId, room) {
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
  const pw = verifyFolderPassword(folder, event);
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

async function createUploadUrl(event, folderId, body, room, authz) {
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
  const pw = verifyFolderPassword(folder, event);
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
  const pw = verifyFolderPassword(folder, event);
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

async function exportFolder(event, folderId, user, room, ctx) {
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
  const pw = verifyFolderPassword(folder, event);
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
        ExclusiveStartKey: lastKey,
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
  const pw = verifyFolderPassword(folder, event);
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
        ExclusiveStartKey: lastKey,
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
    const isRoomEnter = method === 'POST' && path === '/rooms/enter';
    let room = null;
    const user = await getUser(event);

    const p = event.pathParameters || {};
    const body = event.body ? JSON.parse(event.body) : {};
    const ctx = { requestId: event.requestContext?.requestId || null };

    if (method === 'GET' && path === '/me') return await getMe(user);
    if (method === 'PUT' && path === '/me/display-name') return await updateDisplayName(event, user, ctx);

    if (isRoomCreate) return await createRoom(event, user, ctx);
    if (isRoomEnter) return await enterRoom(event, user, ctx);

    const roomReq = getRoomRequest(event, method);
    room = await resolveRoom(roomReq.roomName, roomReq.roomPassword);
    const authzRes = await requireActiveMember(room, user, ctx);
    if (!authzRes.ok) return authzRes.response;
    const authz = authzRes;

    if (method === 'GET' && path === '/team/me') return await teamMe(room, authz);
    if (method === 'GET' && path === '/team/billing') return await teamBilling(authz);
    if (method === 'POST' && path === '/team/purchase') return await teamPurchase(event, user, room, authz, ctx);
    if (method === 'POST' && path === '/team/purchase/checkout') {
      return await teamPurchaseCheckout(event, user, room, authz, ctx);
    }
    if (method === 'GET' && path === '/team/members') return await listTeamMembers(room, authz);
    if (method === 'PUT' && p.userKey && path.endsWith(`/team/members/${p.userKey}`)) {
      return await updateTeamMember(p.userKey, event, user, room, authz, ctx);
    }
    if (method === 'POST' && path === '/team/leave') return await teamLeave(user, room, authz, ctx);
    if (method === 'POST' && path === '/team/delete') return await teamDelete(event, user, room, authz, ctx);

    if (method === 'GET' && path === '/folders') return await listFolders(room);
    if (method === 'POST' && path === '/folders') return await createFolder(event, user, room, ctx);
    if (method === 'DELETE' && p.folderId && path.endsWith(`/folders/${p.folderId}`)) {
      return await deleteFolder(event, p.folderId, user, room, authz, ctx);
    }
    if (method === 'PUT' && p.folderId && path.endsWith(`/folders/${p.folderId}/password`)) {
      return await updateFolderPassword(event, p.folderId, user, room, authz, ctx);
    }

    if (method === 'GET' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos`)) {
      return await listPhotos(event, p.folderId, room);
    }
    if (method === 'POST' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos/upload-url`)) {
      return await createUploadUrl(event, p.folderId, body, room, authz);
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
      return await exportFolder(event, p.folderId, user, room, ctx);
    }

    return json(404, { message: 'not found' });
  } catch (error) {
    if (error.message === 'MISSING_USER_KEY') {
      return json(401, { message: 'unauthorized' });
    }
    if (error.message === 'MISSING_ROOM') {
      return json(401, { message: 'roomName and roomPassword are required' });
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
