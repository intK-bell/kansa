const { randomUUID } = require('node:crypto');
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const {
  DynamoDBDocumentClient,
  QueryCommand,
  PutCommand,
  GetCommand,
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

function auditLog(entry) {
  console.log(
    JSON.stringify({
      kind: 'audit',
      ts: new Date().toISOString(),
      ...entry,
    })
  );
}

function getUser(event) {
  const claims = event?.requestContext?.authorizer?.jwt?.claims || null;
  if (claims && claims.sub) {
    const userName =
      claims['cognito:username'] || claims.name || claims.email || claims.preferred_username || 'unknown';
    return { userKey: claims.sub, userName };
  }

  const headers = event.headers || {};
  const userKey = headers['x-user-key'] || headers['X-User-Key'];
  const rawUserName = headers['x-user-name'] || headers['X-User-Name'] || 'unknown';
  let userName = rawUserName;
  try {
    userName = decodeURIComponent(rawUserName);
  } catch (_) {
    userName = rawUserName;
  }
  if (!userKey) {
    throw new Error('MISSING_USER_KEY');
  }
  return { userKey, userName };
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
  if (upper === 'GET') {
    const q = event.queryStringParameters || {};
    return {
      roomName: decodeText(q.roomName || ''),
      roomPassword: decodeText(q.roomPassword || ''),
    };
  }

  const headers = event.headers || {};
  return {
    roomName: decodeText(headers['x-room-name'] || headers['X-Room-Name'] || ''),
    roomPassword: decodeText(headers['x-room-password'] || headers['X-Room-Password'] || ''),
  };
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
  if (!room || room.password !== roomPassword) {
    throw new Error('INVALID_ROOM');
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
    password: roomPassword,
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
  return json(200, { items });
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
  return json(200, { items });
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
  const key = `${folderId}/${photoId}.${extension}`;

  const cmd = new PutObjectCommand({
    Bucket: PHOTO_BUCKET,
    Key: key,
    ContentType: contentType,
  });

  const uploadUrl = await getSignedUrl(s3, cmd, { expiresIn: 300 });
  return json(200, { uploadUrl, photoId, s3Key: key });
}

async function finalizePhoto(folderId, body, user, room, ctx) {
  if (!body.photoId || !body.s3Key) return badRequest('photoId and s3Key are required');
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
    s3Key: body.s3Key,
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
  await s3.send(new DeleteObjectCommand({ Bucket: PHOTO_BUCKET, Key: item.s3Key }));
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
  return json(200, { items });
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

    const commentLines = (commentsRes.Items || []).map(
      (c, idx) => `${idx + 1}. ${c.text} (${c.createdByName})`
    );

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
    const user = getUser(event);

    const p = event.pathParameters || {};
    const body = event.body ? JSON.parse(event.body) : {};
    const ctx = { requestId: event.requestContext?.requestId || null };

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
    console.error(error);
    return json(500, { message: 'internal server error' });
  }
};
