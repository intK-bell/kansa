const { GetCommand, PutCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');

const FREE_BYTES_DEFAULT = 512 * 1024 * 1024; // 512MiB
const GIB_BYTES = 1024 * 1024 * 1024;
const GBMONTH_DAYS = 30; // Sell "GB-month", internally track "GiB-day" using a fixed 30-day month.

function formatJstDate(date = new Date()) {
  // "en-CA" yields YYYY-MM-DD.
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Tokyo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  }).format(date);
}

function roomBillingKey(roomId) {
  return { PK: `ROOM#${roomId}`, SK: 'META#BILLING' };
}

async function ensureBillingMeta(ddb, { tableName, roomId, roomName, nowIso }) {
  const key = roomBillingKey(roomId);
  const existing = await ddb.send(new GetCommand({ TableName: tableName, Key: key }));
  if (existing.Item) return existing.Item;

  const item = {
    ...key,
    type: 'billing_meta',
    version: 1,
    roomId,
    roomName,
    freeBytes: FREE_BYTES_DEFAULT,
    usageBytes: 0,
    gibDaysBalance: 0,
    lastChargeJstDate: null,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: tableName,
        Item: item,
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
    return item;
  } catch (_) {
    const retry = await ddb.send(new GetCommand({ TableName: tableName, Key: key }));
    return retry.Item || item;
  }
}

async function getBillingMeta(ddb, { tableName, roomId }) {
  const res = await ddb.send(new GetCommand({ TableName: tableName, Key: roomBillingKey(roomId) }));
  return res.Item || null;
}

async function addGibDaysBalance(ddb, { tableName, roomId, deltaGibDays, nowIso }) {
  const res = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: roomBillingKey(roomId),
      UpdateExpression:
        'SET #type = if_not_exists(#type, :type), version = if_not_exists(version, :v), updatedAt = :u ADD gibDaysBalance :d',
      ExpressionAttributeNames: { '#type': 'type' },
      ExpressionAttributeValues: {
        ':type': 'billing_meta',
        ':v': 1,
        ':u': nowIso,
        ':d': deltaGibDays,
      },
      ReturnValues: 'ALL_NEW',
    })
  );
  return res.Attributes;
}

async function addUsageBytes(ddb, { tableName, roomId, deltaBytes, nowIso }) {
  const res = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: roomBillingKey(roomId),
      UpdateExpression:
        'SET #type = if_not_exists(#type, :type), version = if_not_exists(version, :v), updatedAt = :u ADD usageBytes :d',
      ExpressionAttributeNames: { '#type': 'type' },
      ExpressionAttributeValues: {
        ':type': 'billing_meta',
        ':v': 1,
        ':u': nowIso,
        ':d': deltaBytes,
      },
      ReturnValues: 'ALL_NEW',
    })
  );
  return res.Attributes;
}

async function applyDailyChargeForRoom(ddb, { tableName, roomId, roomName, nowIso, jstDate }) {
  const meta =
    (await getBillingMeta(ddb, { tableName, roomId })) ||
    (await ensureBillingMeta(ddb, { tableName, roomId, roomName, nowIso }));

  if (meta.lastChargeJstDate === jstDate) {
    return { ok: true, skipped: true, meta };
  }

  const usageBytes = Number(meta.usageBytes || 0);
  const usageGiB = usageBytes / GIB_BYTES;
  const balanceBefore = Number(meta.gibDaysBalance || 0);
  const consumed = usageGiB; // GiB-day for 1 day
  const balanceAfter = Math.max(0, balanceBefore - consumed);

  // Best-effort charge record for transparency (idempotent per day).
  const chargeItem = {
    PK: `ROOM#${roomId}`,
    SK: `CHARGE#${jstDate}`,
    type: 'billing_charge',
    roomId,
    roomName,
    jstDate,
    usageBytes,
    usageGiB,
    consumedGibDays: consumed,
    balanceBeforeGibDays: balanceBefore,
    balanceAfterGibDays: balanceAfter,
    createdAt: nowIso,
  };

  try {
    await ddb.send(
      new PutCommand({
        TableName: tableName,
        Item: chargeItem,
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
  } catch (_) {
    // Another run already recorded it.
  }

  const updated = await ddb.send(
    new UpdateCommand({
      TableName: tableName,
      Key: roomBillingKey(roomId),
      UpdateExpression: 'SET lastChargeJstDate = :d, gibDaysBalance = :b, updatedAt = :u',
      ExpressionAttributeValues: {
        ':d': jstDate,
        ':b': balanceAfter,
        ':u': nowIso,
      },
      ReturnValues: 'ALL_NEW',
    })
  );

  return { ok: true, skipped: false, consumedGibDays: consumed, meta: updated.Attributes };
}

function summarizeBilling(meta) {
  const freeBytes = Number(meta?.freeBytes || FREE_BYTES_DEFAULT);
  const usageBytes = Number(meta?.usageBytes || 0);
  const gibDaysBalance = Number(meta?.gibDaysBalance || 0);
  const usageGiB = usageBytes / GIB_BYTES;

  const gbMonthEquivalent = gibDaysBalance / GBMONTH_DAYS;
  const estimatedDaysLeft = usageGiB > 0 ? gibDaysBalance / usageGiB : null;

  return {
    freeBytes,
    usageBytes,
    usageGiB,
    gibDaysBalance,
    gbMonthEquivalent,
    estimatedDaysLeft,
    lastChargeJstDate: meta?.lastChargeJstDate || null,
  };
}

module.exports = {
  FREE_BYTES_DEFAULT,
  GIB_BYTES,
  GBMONTH_DAYS,
  formatJstDate,
  ensureBillingMeta,
  getBillingMeta,
  addGibDaysBalance,
  addUsageBytes,
  applyDailyChargeForRoom,
  summarizeBilling,
};
