const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, QueryCommand } = require('@aws-sdk/lib-dynamodb');
const { formatJstDate, applyDailyChargeForRoom } = require('./billing');

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TABLE_NAME = process.env.TABLE_NAME;

const json = (statusCode, body) => ({
  statusCode,
  headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
  body: JSON.stringify(body),
});

async function listRoomsPage(exclusiveStartKey) {
  return ddb.send(
    new QueryCommand({
      TableName: TABLE_NAME,
      KeyConditionExpression: 'PK = :pk and begins_with(SK, :sk)',
      ExpressionAttributeValues: {
        ':pk': 'ORG#DEFAULT',
        ':sk': 'ROOM#',
      },
      ExclusiveStartKey: exclusiveStartKey,
    })
  );
}

exports.handler = async () => {
  const now = new Date();
  const nowIso = now.toISOString();
  const jstDate = formatJstDate(now);

  let scanned = 0;
  let charged = 0;
  let skipped = 0;
  let lastKey = null;

  do {
    const res = await listRoomsPage(lastKey);
    const rooms = res.Items || [];
    for (const room of rooms) {
      scanned += 1;
      const roomId = room.roomId;
      const roomName = room.roomName;
      if (!roomId || !roomName) continue;
      const out = await applyDailyChargeForRoom(ddb, { tableName: TABLE_NAME, roomId, roomName, nowIso, jstDate });
      if (out.skipped) skipped += 1;
      else charged += 1;
    }
    lastKey = res.LastEvaluatedKey || null;
  } while (lastKey);

  console.log(
    JSON.stringify({
      kind: 'audit',
      ts: nowIso,
      action: 'billing.daily_sweep',
      jstDate,
      scanned,
      charged,
      skipped,
      result: 'success',
    })
  );

  return json(200, { ok: true, jstDate, scanned, charged, skipped });
};
