const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand, PutCommand } = require('@aws-sdk/lib-dynamodb');

const { addGibDaysBalance, ensureBillingMeta, summarizeBilling, GBMONTH_DAYS } = require('./billing');
const { verifyStripeWebhook } = require('./stripe-rest');

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const TABLE_NAME = process.env.TABLE_NAME;

const json = (statusCode, body) => ({
  statusCode,
  headers: { 'content-type': 'application/json', 'access-control-allow-origin': '*' },
  body: JSON.stringify(body),
});

function getRawBody(event) {
  const body = event.body || '';
  if (event.isBase64Encoded) {
    return Buffer.from(body, 'base64').toString('utf8');
  }
  return String(body);
}

async function markSessionProcessed(roomId, sessionId, nowIso) {
  const item = {
    PK: `ROOM#${roomId}`,
    SK: `STRIPE_SESSION#${sessionId}`,
    type: 'stripe_session',
    roomId,
    sessionId,
    createdAt: nowIso,
  };
  try {
    await ddb.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
        ConditionExpression: 'attribute_not_exists(PK) and attribute_not_exists(SK)',
      })
    );
    return true;
  } catch (_) {
    return false;
  }
}

function parseSku(sku) {
  const v = String(sku || '').trim().toLowerCase();
  if (v === '1gbm') return { gbMonths: 1, yen: 1000 };
  if (v === '10gbm') return { gbMonths: 10, yen: 8000 };
  if (v === '50gbm') return { gbMonths: 50, yen: 35000 };
  return null;
}

async function creditFromSession(session) {
  const meta = session?.metadata || {};
  const sku = meta.sku;
  const parsed = parseSku(sku);
  if (!parsed) return { ok: false, reason: 'invalid_sku' };

  const roomId = meta.roomId;
  const roomName = meta.roomName;
  if (!roomId || !roomName) return { ok: false, reason: 'missing_room' };

  const sessionId = session.id;
  if (!sessionId) return { ok: false, reason: 'missing_session_id' };

  const nowIso = new Date().toISOString();
  const didMark = await markSessionProcessed(roomId, sessionId, nowIso);
  if (!didMark) return { ok: true, skipped: true };

  await ensureBillingMeta(ddb, { tableName: TABLE_NAME, roomId, roomName, nowIso });
  const deltaGibDays = parsed.gbMonths * GBMONTH_DAYS;
  const updated = await addGibDaysBalance(ddb, {
    tableName: TABLE_NAME,
    roomId,
    deltaGibDays,
    nowIso,
  });

  const purchaseId = session.payment_intent || sessionId;
  await ddb.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        PK: `ROOM#${roomId}`,
        SK: `PURCHASE#${nowIso}#stripe#${purchaseId}`,
        type: 'billing_purchase',
        source: 'stripe',
        roomId,
        roomName,
        sku,
        gbMonths: parsed.gbMonths,
        deltaGibDays,
        yen: parsed.yen,
        stripeSessionId: sessionId,
        stripePaymentIntent: session.payment_intent || null,
        purchasedBy: meta.purchasedBy || null,
        purchasedByName: meta.purchasedByName || null,
        createdAt: nowIso,
      },
    })
  );

  console.log(
    JSON.stringify({
      kind: 'audit',
      ts: nowIso,
      action: 'billing.purchase',
      source: 'stripe',
      roomId,
      roomName,
      sku,
      stripeSessionId: sessionId,
      stripePaymentIntent: session.payment_intent || null,
      result: 'success',
    })
  );

  return { ok: true, skipped: false, billing: summarizeBilling(updated) };
}

exports.handler = async (event) => {
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET || '';
  if (!webhookSecret) return json(500, { message: 'stripe webhook is not configured' });

  const rawBody = getRawBody(event);
  const sig = (event.headers || {})['stripe-signature'] || (event.headers || {})['Stripe-Signature'] || '';
  const verified = verifyStripeWebhook({ rawBody, signatureHeader: sig, webhookSecret });
  if (!verified.ok) {
    console.log(
      JSON.stringify({
        kind: 'audit',
        ts: new Date().toISOString(),
        action: 'stripe.webhook.verify',
        result: 'denied',
        reason: verified.reason,
      })
    );
    return json(400, { message: 'invalid signature' });
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (_) {
    return json(400, { message: 'invalid json' });
  }

  const type = payload.type;
  const obj = payload?.data?.object || null;

  if (type === 'checkout.session.completed') {
    if (obj?.payment_status !== 'paid') return json(200, { ok: true, ignored: true });
    const credited = await creditFromSession(obj);
    return json(200, { ok: true, credited });
  }

  if (type === 'checkout.session.async_payment_succeeded') {
    // For async payment methods, credit when it succeeds.
    const credited = await creditFromSession(obj);
    return json(200, { ok: true, credited });
  }

  // Ignore other event types.
  return json(200, { ok: true, ignored: true, type });
};
