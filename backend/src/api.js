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
const { S3Client, DeleteObjectCommand, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const PptxGenJS = require('pptxgenjs');

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
    return { roomName: room.roomName, roomId: room.roomId };
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
  return { roomName: room.roomName, roomId: room.roomId };
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
  return json(201, { roomName, roomId });
}

async function enterRoom(event) {
  const body = JSON.parse(event.body || '{}');
  const roomName = (body.roomName || '').trim();
  const roomPassword = (body.roomPassword || '').trim();
  const room = await resolveRoom(roomName, roomPassword);
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
  const hydrated = items.map((item) => applyResolvedDisplayName(item, nameMap));
  return json(200, { items: hydrated });
}

async function createFolder(event, user, room, ctx) {
  const body = JSON.parse(event.body || '{}');
  if (!body.title) return badRequest('title is required');

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
  return json(201, item);
}

async function listPhotos(folderId, room) {
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

async function createUploadUrl(folderId, body, room) {
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

async function finalizePhoto(folderId, body, user, room, ctx) {
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
  const folderCode = folder.folderCode || 'F000';
  const photoCode = await nextPhotoCode(folderId, folderCode);

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
    fileName: body.fileName || null,
    createdBy: user.userKey,
    createdByName: user.userName,
    createdAt: now,
    GSI1PK: `FOLDER#${folderId}`,
    GSI1SK: `PHOTO#${now}#${body.photoId}`,
  };

  await ddb.send(new PutCommand({ TableName: TABLE_NAME, Item: item }));
  auditLog({
    requestId: ctx.requestId,
    action: 'photo.create',
    actor: user.userKey,
    actorName: user.userName,
    folderId,
    photoId: body.photoId,
    photoCode,
    roomName: room.roomName,
    result: 'success',
  });
  return json(201, item);
}

async function deletePhoto(photoId, user, room, ctx) {
  const getRes = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
    })
  );

  const item = getRes.Item;
  if (!item) return json(404, { message: 'photo not found' });
  if (!isRoomMatch(item.roomName, room.roomName)) return json(404, { message: 'photo not found' });
  if (item.createdBy !== user.userKey) {
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
  auditLog({
    requestId: ctx.requestId,
    action: 'photo.delete',
    actor: user.userKey,
    actorName: user.userName,
    photoId,
    photoCode: item.photoCode || null,
    result: 'success',
  });

  return json(200, { ok: true });
}

async function updatePhoto(photoId, body, user, room, ctx) {
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
  if (item.createdBy !== user.userKey) {
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

async function deleteComment(photoId, commentId, user, room, ctx) {
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
  if (found.createdBy !== user.userKey) {
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

async function updateComment(photoId, commentId, body, user, room, ctx) {
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
  if (found.createdBy !== user.userKey) {
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

async function exportFolder(folderId, user, room, ctx) {
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
  const key = `exports/${folder.title}_${Date.now()}.pptx`;
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
    if (isRoomEnter) return await enterRoom(event);

    const roomReq = getRoomRequest(event, method);
    room = await resolveRoom(roomReq.roomName, roomReq.roomPassword);

    if (method === 'GET' && path === '/folders') return await listFolders(room);
    if (method === 'POST' && path === '/folders') return await createFolder(event, user, room, ctx);

    if (method === 'GET' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos`)) {
      return await listPhotos(p.folderId, room);
    }
    if (method === 'POST' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos/upload-url`)) {
      return await createUploadUrl(p.folderId, body, room);
    }
    if (method === 'POST' && p.folderId && path.endsWith(`/folders/${p.folderId}/photos`)) {
      return await finalizePhoto(p.folderId, body, user, room, ctx);
    }

    if (method === 'DELETE' && p.photoId && path.endsWith(`/photos/${p.photoId}`)) {
      return await deletePhoto(p.photoId, user, room, ctx);
    }
    if (method === 'PUT' && p.photoId && path.endsWith(`/photos/${p.photoId}`)) {
      return await updatePhoto(p.photoId, body, user, room, ctx);
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
      return await deleteComment(p.photoId, p.commentId, user, room, ctx);
    }
    if (
      method === 'PUT' &&
      p.photoId &&
      p.commentId &&
      path.endsWith(`/photos/${p.photoId}/comments/${p.commentId}`)
    ) {
      return await updateComment(p.photoId, p.commentId, body, user, room, ctx);
    }

    if (method === 'POST' && p.folderId && path.endsWith(`/folders/${p.folderId}/export`)) {
      return await exportFolder(p.folderId, user, room, ctx);
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
