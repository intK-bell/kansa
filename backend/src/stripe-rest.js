const { createHmac, timingSafeEqual } = require('node:crypto');

function encodeForm(data) {
  const params = new URLSearchParams();
  Object.entries(data || {}).forEach(([k, v]) => {
    if (v === undefined || v === null) return;
    params.append(k, String(v));
  });
  return params;
}

function encodeCheckoutSessionParams({ priceId, successUrl, cancelUrl, metadata }) {
  const params = new URLSearchParams();
  params.append('mode', 'payment');
  params.append('line_items[0][price]', priceId);
  params.append('line_items[0][quantity]', '1');
  params.append('success_url', successUrl);
  params.append('cancel_url', cancelUrl);
  Object.entries(metadata || {}).forEach(([k, v]) => {
    if (v === undefined || v === null) return;
    params.append(`metadata[${k}]`, String(v));
  });
  return params;
}

async function stripePostForm({ secretKey, path, params }) {
  return await stripeRequest({ secretKey, method: 'POST', path, params });
}

async function stripeRequest({ secretKey, method = 'GET', path, params = null }) {
  const upper = String(method || 'GET').toUpperCase();
  let url = `https://api.stripe.com${path}`;
  const headers = { Authorization: `Bearer ${secretKey}` };
  const req = { method: upper, headers };

  if (params && upper === 'GET') {
    const qs = typeof params.toString === 'function' ? params.toString() : new URLSearchParams(params).toString();
    if (qs) url += `?${qs}`;
  } else if (params && (upper === 'POST' || upper === 'DELETE')) {
    headers['content-type'] = 'application/x-www-form-urlencoded';
    req.body = typeof params.toString === 'function' ? params.toString() : new URLSearchParams(params).toString();
  }

  const res = await fetch(url, req);
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (_) {
    json = { raw: text };
  }
  if (!res.ok) {
    const msg = json?.error?.message || text || `Stripe error (${res.status})`;
    const err = new Error(msg);
    err.statusCode = res.status;
    err.stripe = json;
    throw err;
  }
  return json;
}

function parseStripeSignatureHeader(value) {
  const header = String(value || '');
  const parts = header.split(',').map((s) => s.trim());
  let t = 0;
  const v1s = [];
  parts.forEach((p) => {
    const idx = p.indexOf('=');
    if (idx <= 0) return;
    const k = p.slice(0, idx);
    const v = p.slice(idx + 1);
    if (k === 't') t = Number(v || 0);
    if (k === 'v1') v1s.push(v);
  });
  return { t, v1s };
}

function verifyStripeWebhook({ rawBody, signatureHeader, webhookSecret, toleranceSec = 300, nowMs = Date.now() }) {
  const { t, v1s } = parseStripeSignatureHeader(signatureHeader);
  if (!t || !v1s.length) return { ok: false, reason: 'missing_signature' };

  const ageSec = Math.abs(nowMs / 1000 - t);
  if (ageSec > toleranceSec) return { ok: false, reason: 'timestamp_out_of_tolerance' };

  const payload = `${t}.${rawBody}`;
  const expected = createHmac('sha256', webhookSecret).update(payload, 'utf8').digest('hex');

  try {
    const a = Buffer.from(expected, 'utf8');
    const ok = v1s.some((v1) => {
      const b = Buffer.from(String(v1 || ''), 'utf8');
      if (a.length !== b.length) return false;
      return timingSafeEqual(a, b);
    });
    if (!ok) return { ok: false, reason: 'signature_mismatch' };
  } catch (_) {
    return { ok: false, reason: 'signature_mismatch' };
  }

  return { ok: true };
}

module.exports = {
  encodeForm,
  encodeCheckoutSessionParams,
  stripeRequest,
  stripePostForm,
  verifyStripeWebhook,
};
