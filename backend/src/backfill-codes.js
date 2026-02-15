const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const {
  DynamoDBDocumentClient,
  QueryCommand,
  UpdateCommand,
  GetCommand,
} = require('@aws-sdk/lib-dynamodb');

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const TABLE_NAME = process.env.TABLE_NAME;

const FOLDER_CODE_RE = /^F(\d+)$/;
const PHOTO_CODE_RE = /^F(\d+)-P(\d+)$/;

function pad3(num) {
  return String(num).padStart(3, '0');
}

function parseFolderSeq(folderCode) {
  if (!folderCode) return null;
  const m = folderCode.match(FOLDER_CODE_RE);
  return m ? Number(m[1]) : null;
}

function parsePhotoSeq(photoCode) {
  if (!photoCode) return null;
  const m = photoCode.match(PHOTO_CODE_RE);
  return m ? Number(m[2]) : null;
}

async function queryAllByPk(pk, skPrefix) {
  let lastKey;
  const items = [];

  do {
    const res = await ddb.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
        ExpressionAttributeValues: {
          ':pk': pk,
          ':sk': skPrefix,
        },
        ExclusiveStartKey: lastKey,
      })
    );

    items.push(...(res.Items || []));
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);

  return items;
}

async function queryAllPhotosByFolder(folderId) {
  let lastKey;
  const items = [];

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
        ExclusiveStartKey: lastKey,
      })
    );

    items.push(...(res.Items || []));
    lastKey = res.LastEvaluatedKey;
  } while (lastKey);

  return items;
}

async function updateFolderCode(folderId, folderCode) {
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: 'ORG#DEFAULT', SK: `FOLDER#${folderId}` },
      UpdateExpression: 'SET folderCode = :folderCode',
      ExpressionAttributeValues: {
        ':folderCode': folderCode,
      },
    })
  );
}

async function updatePhotoCodes(photoId, folderCode, photoCode) {
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `PHOTO#${photoId}`, SK: 'META' },
      UpdateExpression: 'SET folderCode = :folderCode, photoCode = :photoCode',
      ExpressionAttributeValues: {
        ':folderCode': folderCode,
        ':photoCode': photoCode,
      },
    })
  );
}

async function getCounter(pk, sk, name) {
  const res = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: { PK: pk, SK: sk },
    })
  );
  return Number(res.Item?.[name] || 0);
}

async function setCounter(pk, sk, name, value) {
  await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: pk, SK: sk },
      UpdateExpression: `SET #n = :v`,
      ExpressionAttributeNames: { '#n': name },
      ExpressionAttributeValues: { ':v': value },
    })
  );
}

exports.handler = async (event = {}) => {
  const apply = event.apply === true;
  const dryRun = !apply;

  const folders = await queryAllByPk('ORG#DEFAULT', 'FOLDER#');
  folders.sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));

  let maxFolderSeq = 0;
  for (const folder of folders) {
    const seq = parseFolderSeq(folder.folderCode);
    if (seq && seq > maxFolderSeq) maxFolderSeq = seq;
  }

  const summary = {
    dryRun,
    totalFolders: folders.length,
    folderCodeAdded: 0,
    totalPhotos: 0,
    photoCodeAdded: 0,
    countersUpdated: 0,
    sample: {
      folders: [],
      photos: [],
    },
  };

  for (const folder of folders) {
    let folderCode = folder.folderCode;
    if (!parseFolderSeq(folderCode)) {
      maxFolderSeq += 1;
      folderCode = `F${pad3(maxFolderSeq)}`;
      summary.folderCodeAdded += 1;
      if (summary.sample.folders.length < 10) {
        summary.sample.folders.push({ folderId: folder.folderId, folderCode });
      }
      if (!dryRun) {
        await updateFolderCode(folder.folderId, folderCode);
      }
    }

    const photos = await queryAllPhotosByFolder(folder.folderId);
    summary.totalPhotos += photos.length;

    let maxPhotoSeq = 0;
    for (const photo of photos) {
      const seq = parsePhotoSeq(photo.photoCode);
      if (seq && seq > maxPhotoSeq) maxPhotoSeq = seq;
    }

    for (const photo of photos) {
      const seq = parsePhotoSeq(photo.photoCode);
      const needUpdate = !seq || photo.folderCode !== folderCode;
      if (!needUpdate) continue;

      const nextSeq = seq || maxPhotoSeq + 1;
      if (!seq) maxPhotoSeq = nextSeq;

      const photoCode = `${folderCode}-P${pad3(nextSeq)}`;
      summary.photoCodeAdded += 1;
      if (summary.sample.photos.length < 20) {
        summary.sample.photos.push({
          folderId: folder.folderId,
          photoId: photo.photoId,
          photoCode,
        });
      }

      if (!dryRun) {
        await updatePhotoCodes(photo.photoId, folderCode, photoCode);
      }
    }

    if (!dryRun) {
      const currentPhotoCounter = await getCounter(`FOLDER#${folder.folderId}`, 'META#COUNTER', 'photoSeq');
      if (maxPhotoSeq > currentPhotoCounter) {
        await setCounter(`FOLDER#${folder.folderId}`, 'META#COUNTER', 'photoSeq', maxPhotoSeq);
        summary.countersUpdated += 1;
      }
    }
  }

  if (!dryRun) {
    const currentFolderCounter = await getCounter('ORG#DEFAULT', 'META#COUNTER', 'folderSeq');
    if (maxFolderSeq > currentFolderCounter) {
      await setCounter('ORG#DEFAULT', 'META#COUNTER', 'folderSeq', maxFolderSeq);
      summary.countersUpdated += 1;
    }
  }

  return summary;
};
