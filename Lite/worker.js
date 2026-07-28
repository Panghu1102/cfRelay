// cfRelay Lite: a Cloudflare Worker-based AI API relay with API key validation,
// monthly quota tracking, model name mapping, and single upstream forwarding.
// GitHub: https://github.com/Panghu1102/cfRelay   Please give a star!
// Author: Panghu1102
// Version: 1.0.0   Internal: 1.0.0

const VERSION = '1.0.0';
const INTERNAL_VERSION = '1.0.0';

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return handleOptions();
    }

    const configError = validateEnv(env);
    if (configError) {
      return jsonResponse({ error: configError }, 500);
    }

    return handleProxy(request, env);
  }
};

async function handleProxy(request, env) {
  const username = getBearerToken(request);
  if (!username) {
    return jsonResponse({ error: 'missing Authorization header' }, 401);
  }

  const userMeta = await getUserMeta(env, username);
  if (!userMeta) {
    return jsonResponse({ error: 'invalid API key' }, 403);
  }
  if (userMeta.status === 'banned') {
    return jsonResponse({ error: 'account banned' }, 403);
  }

  const quotaError = await checkAndIncrementQuota(env, username);
  if (quotaError) {
    return quotaError;
  }

  const bodylessMethod = ['GET', 'HEAD'].includes(request.method);
  const upstreamUrl = buildUpstreamUrl(request, env.UPSTREAM_BASE_URL);
  const headers = buildUpstreamHeaders(request.headers, env.REAL_API_KEY);
  let body = bodylessMethod ? undefined : request.body;

  if (request.method === 'POST') {
    const parsedBody = await request.clone().json().catch(() => null);
    if (!parsedBody || typeof parsedBody !== 'object' || Array.isArray(parsedBody)) {
      return jsonResponse({ error: 'request body must be a JSON object' }, 400);
    }

    const requiredModelName = env.REQUIRED_MODEL_NAME || 'example-model';
    if (parsedBody.model !== requiredModelName) {
      return jsonResponse({ error: `Invalid model ID. You must use "${requiredModelName}".` }, 400);
    }

    body = JSON.stringify({
      ...parsedBody,
      model: env.UPSTREAM_MODEL_ID
    });
    headers.set('Content-Type', 'application/json; charset=utf-8');
  }

  try {
    const upstreamResponse = await fetch(upstreamUrl, {
      method: request.method,
      headers,
      body,
      redirect: 'manual'
    });

    return withCors(upstreamResponse);
  } catch (err) {
    return jsonResponse({ error: 'upstream_fetch_failed', detail: String(err) }, 502);
  }
}

function validateEnv(env) {
  if (!env.USER_KEYS_KV) return 'USER_KEYS_KV binding is not configured.';
  if (!env.UPSTREAM_BASE_URL) return 'UPSTREAM_BASE_URL is not configured.';
  if (!env.REAL_API_KEY) return 'REAL_API_KEY is not configured.';
  if (!env.UPSTREAM_MODEL_ID) return 'UPSTREAM_MODEL_ID is not configured.';
  return '';
}

function getBearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return '';
  return auth.slice(7).trim().toLowerCase();
}

async function getUserMeta(env, username) {
  const raw = await env.USER_KEYS_KV.get(`userkey:${username}`);
  if (!raw) return null;

  try {
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

async function checkAndIncrementQuota(env, username) {
  const yyyyMm = new Date().toISOString().slice(0, 7);
  const quotaKey = `quota:${username}:${yyyyMm}`;
  const rawUsed = await env.USER_KEYS_KV.get(quotaKey);
  const used = rawUsed ? parseInt(rawUsed, 10) : 0;
  const quota = parseInt(env.QUOTA_PER_USER_PER_MONTH || '999', 10);

  if (Number.isNaN(quota) || quota < 1) {
    return jsonResponse({ error: 'QUOTA_PER_USER_PER_MONTH must be a positive integer.' }, 500);
  }
  if (used >= quota) {
    return jsonResponse({ error: 'monthly quota exceeded for this API key' }, 429);
  }

  await env.USER_KEYS_KV.put(quotaKey, String(used + 1), {
    expirationTtl: secondsUntilMonthEnd()
  });
  return null;
}

function buildUpstreamUrl(request, upstreamBaseUrl) {
  const incomingUrl = new URL(request.url);
  return new URL(incomingUrl.pathname + incomingUrl.search, upstreamBaseUrl).toString();
}

function buildUpstreamHeaders(incomingHeaders, apiKey) {
  const headers = new Headers();
  for (const [key, value] of incomingHeaders.entries()) {
    const lowerKey = key.toLowerCase();
    if (['authorization', 'cf-connecting-ip', 'x-forwarded-for', 'x-real-ip', 'host'].includes(lowerKey)) {
      continue;
    }
    if (['accept', 'content-type', 'user-agent', 'referer', 'x-request-id'].includes(lowerKey)) {
      headers.set(key, value);
    }
  }
  headers.set('Authorization', `Bearer ${apiKey}`);
  return headers;
}

async function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  headers.delete('server');

  const body = response.status === 204 || response.status === 304 ? null : await response.arrayBuffer();
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

function handleOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    }
  });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify({ ...obj, version: VERSION, internalVersion: INTERNAL_VERSION }), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    }
  });
}

function secondsUntilMonthEnd() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth();
  const nextMonth = new Date(Date.UTC(year, month + 1, 1, 0, 0, 0));
  return Math.ceil((nextMonth.getTime() - now.getTime()) / 1000) + 5;
}
