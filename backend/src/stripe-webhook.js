const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, GetCommand, PutCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');

const {
  ensureBillingMeta,
  summarizeBilling,
  BILLING_MODE_SUBSCRIPTION,
  normalizeSubscriptionPlanCode,
} = require('./billing');
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

function subscriptionPlanFromPriceId(priceId) {
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

function subscriptionRoomKey(subscriptionId) {
  return { PK: `STRIPE_SUB#${subscriptionId}`, SK: 'META#ROOM' };
}

async function linkSubscriptionToRoom({ subscriptionId, customerId, roomId, roomName, nowIso }) {
  if (!subscriptionId || !roomId) return;
  await ddb.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        ...subscriptionRoomKey(subscriptionId),
        type: 'stripe_subscription_room',
        subscriptionId,
        customerId: customerId || null,
        roomId,
        roomName: roomName || null,
        createdAt: nowIso,
        updatedAt: nowIso,
      },
    })
  );
}

async function findRoomBySubscriptionId(subscriptionId) {
  if (!subscriptionId) return null;
  const res = await ddb.send(
    new GetCommand({
      TableName: TABLE_NAME,
      Key: subscriptionRoomKey(subscriptionId),
    })
  );
  return res.Item || null;
}

async function updateBillingMeta(roomId, fields, nowIso = new Date().toISOString()) {
  const names = {};
  const values = { ':u': nowIso };
  const sets = ['updatedAt = :u'];
  let i = 0;
  Object.entries(fields || {}).forEach(([k, v]) => {
    i += 1;
    const nk = `#k${i}`;
    const nv = `:v${i}`;
    names[nk] = k;
    values[nv] = v;
    sets.push(`${nk} = ${nv}`);
  });
  const res = await ddb.send(
    new UpdateCommand({
      TableName: TABLE_NAME,
      Key: { PK: `ROOM#${roomId}`, SK: 'META#BILLING' },
      UpdateExpression: `SET ${sets.join(', ')}`,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
      ReturnValues: 'ALL_NEW',
    })
  );
  return res.Attributes || null;
}

async function syncSubscriptionFromCheckoutSession(session) {
  const meta = session?.metadata || {};
  const roomId = String(meta.roomId || '').trim();
  const roomName = String(meta.roomName || '').trim();
  const selectedPlan = normalizeSubscriptionPlanCode(meta.selectedPlan || 'BASIC');
  const sessionId = String(session?.id || '').trim();
  const subscriptionId = String(session?.subscription || '').trim();
  const customerId = String(session?.customer || '').trim();
  const nowIso = new Date().toISOString();

  if (!roomId || !roomName || !sessionId || !subscriptionId) {
    return { ok: false, reason: 'missing_subscription_session_fields' };
  }

  const didMark = await markSessionProcessed(roomId, sessionId, nowIso);
  if (!didMark) return { ok: true, skipped: true };

  await ensureBillingMeta(ddb, { tableName: TABLE_NAME, roomId, roomName, nowIso });
  await updateBillingMeta(roomId, {
    billingMode: BILLING_MODE_SUBSCRIPTION,
    currentPlan: selectedPlan,
    pendingPlan: null,
    cancelAtPeriodEnd: false,
    nextBillingAt: null,
    stripeCustomerId: customerId || null,
    stripeSubscriptionId: subscriptionId,
    stripeSubscriptionStatus: 'active',
    stripeSubscriptionItemId: null,
  }, nowIso);
  await linkSubscriptionToRoom({
    subscriptionId,
    customerId,
    roomId,
    roomName,
    nowIso,
  });

  return { ok: true, skipped: false, roomId, subscriptionId, currentPlan: selectedPlan };
}

async function syncSubscriptionByEventObject(obj, mode) {
  const subscriptionId = String(obj?.subscription || obj?.id || '').trim();
  if (!subscriptionId) return { ok: false, reason: 'missing_subscription_id' };
  const roomRef = await findRoomBySubscriptionId(subscriptionId);
  if (!roomRef?.roomId) return { ok: false, reason: 'subscription_room_not_found', subscriptionId };

  const roomId = roomRef.roomId;
  const nowIso = new Date().toISOString();
  const nextBillingAt =
    isoFromUnixSec(obj?.current_period_end) || isoFromUnixSec(obj?.lines?.data?.[0]?.period?.end) || null;
  const planFromSub = subscriptionPlanFromPriceId(obj?.items?.data?.[0]?.price?.id);
  const planFromInvoice =
    Array.isArray(obj?.lines?.data) &&
    obj.lines.data
      .map((line) => subscriptionPlanFromPriceId(line?.price?.id))
      .find((plan) => Boolean(plan));

  if (mode === 'invoice.paid') {
    const fields = { stripeSubscriptionStatus: 'active' };
    if (nextBillingAt) fields.nextBillingAt = nextBillingAt;
    if (planFromInvoice) fields.currentPlan = planFromInvoice;
    const updated = await updateBillingMeta(roomId, fields, nowIso);
    return { ok: true, roomId, billing: summarizeBilling(updated) };
  }

  if (mode === 'invoice.payment_failed') {
    const fields = { stripeSubscriptionStatus: 'past_due' };
    if (nextBillingAt) fields.nextBillingAt = nextBillingAt;
    const updated = await updateBillingMeta(roomId, fields, nowIso);
    return { ok: true, roomId, billing: summarizeBilling(updated) };
  }

  if (mode === 'customer.subscription.updated') {
    const fields = {
      billingMode: BILLING_MODE_SUBSCRIPTION,
      stripeSubscriptionStatus: obj?.status || null,
      stripeSubscriptionItemId: obj?.items?.data?.[0]?.id || null,
      cancelAtPeriodEnd: Boolean(obj?.cancel_at_period_end),
    };
    if (nextBillingAt) fields.nextBillingAt = nextBillingAt;
    if (planFromSub) fields.currentPlan = normalizeSubscriptionPlanCode(planFromSub);
    const updated = await updateBillingMeta(roomId, fields, nowIso);
    return { ok: true, roomId, billing: summarizeBilling(updated) };
  }

  if (mode === 'customer.subscription.deleted') {
    const updated = await updateBillingMeta(
      roomId,
      {
        stripeSubscriptionStatus: 'canceled',
        cancelAtPeriodEnd: false,
        pendingPlan: null,
        currentPlan: 'FREE',
        nextBillingAt: null,
      },
      nowIso
    );
    return { ok: true, roomId, billing: summarizeBilling(updated) };
  }

  return { ok: true, ignored: true };
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
    if (String(obj?.mode || '') === 'subscription') {
      const synced = await syncSubscriptionFromCheckoutSession(obj);
      return json(200, { ok: true, subscription: synced });
    }
    return json(200, { ok: true, ignored: true, mode: obj?.mode || null });
  }

  if (type === 'invoice.paid') {
    const out = await syncSubscriptionByEventObject(obj, 'invoice.paid');
    return json(200, { ok: true, subscription: out });
  }

  if (type === 'invoice.payment_failed') {
    const out = await syncSubscriptionByEventObject(obj, 'invoice.payment_failed');
    return json(200, { ok: true, subscription: out });
  }

  if (type === 'customer.subscription.updated') {
    const out = await syncSubscriptionByEventObject(obj, 'customer.subscription.updated');
    return json(200, { ok: true, subscription: out });
  }

  if (type === 'customer.subscription.deleted') {
    const out = await syncSubscriptionByEventObject(obj, 'customer.subscription.deleted');
    return json(200, { ok: true, subscription: out });
  }

  // Ignore other event types.
  return json(200, { ok: true, ignored: true, type });
};
