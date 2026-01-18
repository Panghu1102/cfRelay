// A Cloudflare Worker-based JS that implements an AI gateway, user signup, user management,
// forced prompt replacement and request body modification, BM25 and other features.
// Deployable in about 3 minutes.
// GitHub: https://github.com/Panghu1102/cfRelay   Please give a star!
// Author: Panghu1102
// Version: 1.0.0   Internal: v3.2.1
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
// Signup note: this needs to be used with the jyacssignup mail Worker in the same directory
    // --- v3.2 Signup routes ---
    if (request.method === 'GET' && (path === '/' || path === '/index.html')) {
      return serveSignupPage(); // Replaced with v3.2 page (includes activation code)
    }
    if (request.method === 'POST' && path === '/signup') {
      return handleSignup(request, env); // Replaced with v3.2 logic (includes activation code check)
    }
    // (new) v3.2 polling route
    if (request.method === 'GET' && path === '/signup-status') {
      return handleSignupStatus(request, env); 
    }
    // --- end ---

    if (path === '/admin' || path === '/admin/') {
      return handleAdmin(request, env); 
    }

    if (path === '/admin/login') {
      return serveAdminLogin(); 
    }

    if (path === '/admin/api/users') {
      return handleAdminAPI(request, env); 
    }

    if (path === '/admin/api/knowledge') {
      return handleAdminKnowledgeAPI(request, env); 
    }

    if (request.method === 'POST' && path === '/admin/api/action') {
      return handleAdminAction(request, env); 
    }

    if (request.method === 'POST' && path === '/admin/api/add-knowledge') {
      return handleAddKnowledge(request, env); 
    }

    if (request.method === 'POST' && path === '/admin/api/test-connection') {
      return handleTestConnection(request, env); 
    }

    // Proxy other paths (v2 unchanged)
    return handleProxy(request, env);
  }
};

// --- MODIFIED: HTML Signup Page (v3.2) ---
// Form updated to email, password, captcha, and activation
function serveSignupPage() {
  const html = `<!doctype html>
  <html>
  <head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Sign Up</title>
  <style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f7f7fb}
  .box{background:#fff;padding:24px;border-radius:10px;box-shadow:0 6px 20px rgba(0,0,0,0.08);width:320px;text-align:center}
  input{width:100%;padding:10px;margin:8px 0;border:1px solid #ddd;border-radius:6px}
  button{width:100%;padding:10px;border:0;border-radius:6px;background:#2563eb;color:#fff;font-weight:600}
  .note{font-size:13px;color:#666;margin-top:8px; text-align: left; line-height: 1.5;}
  </style>
  </head>
  <body>
    <div class="box">
      <h3>Sign Up</h3>
      <form id="signupForm">
        <input id="email" name="email" type="email" placeholder="Email (will be used as your API Key)" required />
        <input id="password" name="password" type="password" placeholder="Set a password (min 8 chars)" required minlength="8" />
        <input id="captcha" name="captcha" placeholder="Captcha (enter any 4 characters)" required minlength="4" />
        <input id="activation" name="activation" placeholder="Activation code" required />
        <button type="submit">Next</button>
      </form>
      <div class="note" id="noteArea">
        Signup steps:<br/>
        1. Fill in all information (including activation code).<br/>
        2. Click "Next".<br/>
        3. Log in to your email and <b>send an email</b>.
      </div>
      <div id="msg" style="margin-top:10px;color:green;font-weight:bold;"></div>
    </div>
  <script>
    const f = document.getElementById('signupForm');
    const msg = document.getElementById('msg');
    const note = document.getElementById('noteArea');

    // (new) v3.2 polling function
    function startPolling(email) {
      const startTime = Date.now();
      msg.style.color = '#1d4ed8';
      
      const intervalId = setInterval(async () => {
        // stop polling after 15 minutes
        if (Date.now() - startTime > 900000) { // 15 * 60 * 1000
          clearInterval(intervalId);
          msg.style.color = 'red';
          msg.textContent = 'Activation timed out (15 minutes). Please refresh and try again.';
          return;
        }
        
        try {
          // request new endpoint /signup-status
          const res = await fetch('/signup-status?email=' + encodeURIComponent(email));
          const data = await res.json();
          
          if (data.status === 'complete') {
            // --- signup complete ---
            clearInterval(intervalId);
            // show final "signup complete" page
            document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh">' +
              '<div style="text-align:center">' +
              '<h2>Signup Complete 🎉</h2>' +
              '<p>Your account <b>' + email + '</b> has been successfully activated.</p>' +
              '<p>You can now close this page and use your email as the API Key.</p></div></div>';
          } else {
            // still waiting... (optional: update message)
            msg.textContent = 'Request submitted... waiting for email verification...';
          }
        } catch (err) {
          // ignore fetch errors (e.g. network blips), polling will retry
          console.error('Polling error:', err);
        }
      }, 5000); // poll every 5 seconds
    }

    // v3.2 submit handler
    f.addEventListener('submit', async (e)=> {
      e.preventDefault();
      msg.style.color='green'; msg.textContent='Submitting request...';
      
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value.trim();
      const captcha = document.getElementById('captcha').value.trim();
      const activation = document.getElementById('activation').value.trim(); // (new) get activation code
      
      try {
        const res = await fetch('/signup', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          // (new) send activationCode to backend
          body: JSON.stringify({ email, password, captcha, activationCode: activation }) 
        });
        
        const j = await res.json();
        
        if (res.ok) {
          // signup request accepted, hide form and show next steps
          f.style.display = 'none'; 
          msg.innerHTML = '✅ Request submitted! Please activate now:';
          note.innerHTML = 'Please log in to your email <b>' + email + '</b><br/><br/>' +
            'and send a new email to:<br/>' +
            '<b>To:</b> <code>signup@jyacs.dpdns.org</code><br/>' +
            '<b>Subject:</b> <code>Verification</code><br/><br/>' +
            'After sending the email your account will be activated within a minute. This request is valid for 15 minutes.';
          
          // --- (new) v3.2 start polling ---
          startPolling(email);

        } else {
          // failure (e.g., invalid activation code, email exists)
          msg.style.color='red';
          msg.textContent = j.error || 'Signup failed';
        }
      } catch (err) {
        msg.style.color='red';
        msg.textContent='Network error';
      }
    });
  </script>
  </body></html>`;
  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// --- MODIFIED: Handle Signup (v3.2) ---
// (added activation code validation)
async function handleSignup(request, env) {
  try {
    const body = await request.json().catch(() => null);
    // (new) check activationCode
    if (!body || !body.email || !body.password || !body.captcha || !body.activationCode) {
      return jsonResponse({ error: 'missing email, password, captcha, or activation code' }, 400);
    }
    
    const email = String(body.email).trim().toLowerCase();
    const password = String(body.password);
    const captcha = String(body.captcha);
    const activationCode = String(body.activationCode).trim(); // (new)

    // --- (new) v3.2 activation code validation ---
    // (This logic comes from your v2 implementation)
    const activationKey = `activation:${activationCode}`;
    const activationRaw = await env.USER_KEYS_KV.get(activationKey);
    if (!activationRaw) {
      return jsonResponse({ error: 'invalid activation code' }, 403);
    }
    // (activation code valid)
    // --- end ---

    // (v3.1) validate email and password
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonResponse({ error: 'Invalid email format' }, 400);
    }
    if (password.length < 8) {
      return jsonResponse({ error: 'Password must be at least 8 characters' }, 400);
    }
    if (captcha.length < 4) {
      return jsonResponse({ error: 'Invalid captcha' }, 400);
    }

    // (v3.1) check if user exists
    const userKey = `userkey:${email}`;
    const exists = await env.USER_KEYS_KV.get(userKey);
    if (exists) {
      return jsonResponse({ error: 'This email is already registered' }, 409);
    }

    // (v3.1) check pending
    const pendingKey = `pending:${email}`;
    const pendingExists = await env.USER_KEYS_KV.get(pendingKey);
    if (pendingExists) {
      return jsonResponse({ error: 'There is a pending activation request for this email; check your mail or try again after 15 minutes' }, 409);
    }

    // (v3.1) IP limit
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || '0.0.0.0';
    const yyyyMm = new Date().toISOString().slice(0, 7);
    const ipKey = `signup_ip:${ip}:${yyyyMm}`;
    const rawCount = await env.USER_KEYS_KV.get(ipKey);
    const count = rawCount ? parseInt(rawCount, 10) : 0;
    const LIMIT_PER_IP_PER_MONTH = parseInt(env.LIMIT_PER_IP_PER_MONTH || '5', 10); 
    if (count >= LIMIT_PER_IP_PER_MONTH) {
      return jsonResponse({ error: 'too many signups from this IP this month' }, 429);
    }
    const ttl = secondsUntilMonthEnd();
    await env.USER_KEYS_KV.put(ipKey, String(count + 1), { expirationTtl: ttl });

    // (v3.1) hash password
    const passHash = await hashPassword(password);
    
    // (v3.1) store pending record (15 minute TTL)
    await env.USER_KEYS_KV.put(pendingKey, passHash, { expirationTtl: 900 });

    // (v3.1) return success
    return jsonResponse({ ok: true, message: 'Pending activation. Please send verification email.' }, 200);
    
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- NEW: Signup Status Checker (v3.2) ---
// (used by frontend polling)
async function handleSignupStatus(request, env) {
  const url = new URL(request.url);
  const email = url.searchParams.get('email');
  
  if (!email) {
    return jsonResponse({ error: 'missing email' }, 400);
  }
  
  // check whether the final user key has been created by the jyacssignup worker
  const userKey = `userkey:${email.toLowerCase()}`;
  const meta = await env.USER_KEYS_KV.get(userKey);
  
  if (meta) {
    // mail worker has processed it successfully
    return jsonResponse({ status: 'complete' });
  } else {
    // still waiting for email
    return jsonResponse({ status: 'pending' });
  }
}

// --- NEW: Password Hashing Helper (v3.1) ---
async function hashPassword(password) {
  const utf8 = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((bytes) => bytes.toString(16).padStart(2, '0'))
    .join('');
  return hashHex;
}

// --- Proxy Request (v2 - unchanged) ---
async function handleProxy(request, env) {
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization'
      }
    });
  }

  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Bearer ')) return jsonResponse({ error: 'missing Authorization header' }, 401);
  
  const username = auth.slice(7).trim(); 
  if (!username) return jsonResponse({ error: 'missing api key (email)' }, 401);

  const kvKey = `userkey:${username}`;
  const metaRaw = await env.USER_KEYS_KV.get(kvKey);
  if (!metaRaw) return jsonResponse({ error: 'invalid API key' }, 403);

  let meta;
  try {
    meta = JSON.parse(metaRaw);
  } catch {
    meta = {};
  }
  if (meta.status === 'banned') {
    return jsonResponse({ error: 'account banned' }, 403);
  }
  
  const yyyyMm = new Date().toISOString().slice(0, 7);
  const quotaKey = `quota:${username}:${yyyyMm}`;
  const rawUsed = await env.USER_KEYS_KV.get(quotaKey);
  const used = rawUsed ? parseInt(rawUsed, 10) : 0;
  const QUOTA_PER_USER_PER_MONTH = parseInt(env.QUOTA_PER_USER_PER_MONTH || '999', 10);
  if (used >= QUOTA_PER_USER_PER_MONTH) {
    return jsonResponse({ error: 'monthly quota exceeded for this username' }, 429);
  }

  const ttl = secondsUntilMonthEnd();
  await env.USER_KEYS_KV.put(quotaKey, String(used + 1), { expirationTtl: ttl });

  // Check load balancing switch status
  const loadBalancingEnabled = await env.USER_KEYS_KV.get('config:load_balancing_enabled');
  const isLoadBalancingOn = loadBalancingEnabled === 'true';

  let apiConfig;
  let bodyToForward;
  const newHeaders = new Headers(request.headers);

  if (request.method === 'POST') {
    try {
      const clonedRequest = request.clone();
      const originalBody = await clonedRequest.json();

      const MODEL_NAME_1 = env.REQUIRED_MODEL_NAME || 'example-model';
      const MODEL_NAME_2 = env.REQUIRED_MODEL_NAME_2 || 'example-model2';

      if (isLoadBalancingOn) {
        // Load balancing mode: auto-select API, accept either model name
        apiConfig = await selectUpstreamAPI(env);
        
        if (!originalBody.model || (originalBody.model !== MODEL_NAME_1 && originalBody.model !== MODEL_NAME_2)) {
          return jsonResponse({ error: `Invalid model ID. You must use "${MODEL_NAME_1}" or "${MODEL_NAME_2}".` }, 400);
        }
      } else {
        // Manual mode: select API based on requested model name
        if (!originalBody.model) {
          return jsonResponse({ error: 'Missing model ID.' }, 400);
        }

        if (originalBody.model === MODEL_NAME_1) {
          // Use API1
          apiConfig = {
            baseUrl: env.UPSTREAM_BASE_URL,
            apiKey: env.REAL_API_KEY,
            modelId: env.UPSTREAM_MODEL_ID,
            name: 'API1'
          };
        } else if (originalBody.model === MODEL_NAME_2) {
          // Use API2
          if (!env.UPSTREAM_BASE_URL_2 || !env.REAL_API_KEY_2) {
            return jsonResponse({ error: `Model "${MODEL_NAME_2}" is not available (API2 not configured).` }, 400);
          }
          apiConfig = {
            baseUrl: env.UPSTREAM_BASE_URL_2,
            apiKey: env.REAL_API_KEY_2,
            modelId: env.UPSTREAM_MODEL_ID_2 || env.UPSTREAM_MODEL_ID,
            name: 'API2'
          };
        } else {
          return jsonResponse({ error: `Invalid model ID. You must use "${MODEL_NAME_1}" or "${MODEL_NAME_2}".` }, 400);
        }
      }
      
      let messages = originalBody.messages || [];
      messages = messages.filter(m => m.role !== 'system');
      const query = messages.filter(m => m.role === 'user').pop()?.content || '';

      let skillContent = '';
      if (env.UPSTREAM_EMBEDDING_BASE_URL && env.REAL_EMBEDDING_API_KEY && env.EMBEDDING_MODEL_ID) {
        const embeddingConfig = await selectUpstreamEmbedding(env);
        const { results } = await env.KNOWLEDGE_D1.prepare('SELECT text FROM knowledge').all();
        if (results && results.length > 0) {
          const allKnowledgeText = results.map(r => r.text).join('\n\n---\n\n');
          skillContent = await getKnowledgeRetrieval(env, query, allKnowledgeText, embeddingConfig);
        }
      }
// This enforces system prompts. It's mainly used for role-play and to provide mandatory prompts to prevent abuse or inappropriate output.
      const systemPrompt = `
You are an AI assistant. Use the following SKILL information to help answer the user's question.
`;

      messages.unshift({ role: 'system', content: systemPrompt });
      const upstreamModelId = apiConfig.modelId;
      if (!upstreamModelId) {
        console.error(`Model ID not configured for ${apiConfig.name}`);
        return jsonResponse({ error: 'Model ID not configured by administrator.' }, 500);
      }
      const modifiedBody = { ...originalBody, messages, model: upstreamModelId };
      bodyToForward = JSON.stringify(modifiedBody);
      newHeaders.set('Content-Type', 'application/json; charset=utf-8');
    } catch (err) {
      return jsonResponse({ error: 'Failed to parse request body as JSON or process RAG' }, 400);
    }
  } else {
    bodyToForward = request.body;
  }

  const incoming = new URL(request.url);
  const upstreamUrl = new URL(incoming.pathname + incoming.search, apiConfig.baseUrl).toString();
  const headersForUpstream = new Headers();
  for (const [k, v] of newHeaders.entries()) {
    const lk = k.toLowerCase();
    if (['authorization', 'cf-connecting-ip', 'x-forwarded-for', 'x-real-ip'].includes(lk)) continue;
    if (['content-type', 'accept', 'user-agent', 'referer', 'x-request-id'].includes(lk)) headersForUpstream.set(k, v);
  }
  if (apiConfig.apiKey) headersForUpstream.set('Authorization', `Bearer ${apiConfig.apiKey}`);
  const isBodylessMethod = ['GET', 'HEAD', 'OPTIONS'].includes(request.method);
  try {
    const upstreamResp = await fetch(upstreamUrl, {
      method: request.method,
      headers: headersForUpstream,
      body: isBodylessMethod ? undefined : bodyToForward,
      redirect: 'manual'
    });
    const respHeaders = new Headers(upstreamResp.headers);
    respHeaders.delete('server');
    const buf = await upstreamResp.arrayBuffer();
    return new Response(buf, { status: upstreamResp.status, statusText: upstreamResp.statusText, headers: respHeaders });
  } catch (err) {
    return jsonResponse({ error: 'upstream_fetch_failed', detail: String(err) }, 502);
  }
}

// --- Load Balancing Logic (v2 - unchanged) ---
async function selectUpstreamAPI(env) {
  const now = Date.now();
  const today = new Date().toISOString().slice(0, 10); 
  const api1 = {
    baseUrl: env.UPSTREAM_BASE_URL,
    apiKey: env.REAL_API_KEY,
    modelId: env.UPSTREAM_MODEL_ID,
    name: 'API1'
  };
  const api2 = {
    baseUrl: env.UPSTREAM_BASE_URL_2,
    apiKey: env.REAL_API_KEY_2,
    modelId: env.UPSTREAM_MODEL_ID_2 || env.UPSTREAM_MODEL_ID,
    name: 'API2'
  };
  if (!api2.baseUrl || !api2.apiKey) {
    return api1;
  }
  const dailyCountKey = `api1_daily_count:${today}`;
  const rawCount = await env.USER_KEYS_KV.get(dailyCountKey);
  const dailyCount = rawCount ? parseInt(rawCount, 10) : 0;
  const DAILY_LIMIT = parseInt(env.DAILY_LIMIT || '2500', 10);
  if (dailyCount >= DAILY_LIMIT) {
    return api2;
  }
  const lastRequestKey = 'last_request_info';
  const lastRequestRaw = await env.USER_KEYS_KV.get(lastRequestKey);
  let selectedAPI = api1;
  let shouldAlternate = false;
  if (lastRequestRaw) {
    try {
      const lastRequest = JSON.parse(lastRequestRaw);
      const timeSinceLastRequest = now - lastRequest.timestamp;
      if (timeSinceLastRequest < 2000) {
        shouldAlternate = true;
        selectedAPI = lastRequest.api === 'API1' ? api2 : api1;
      }
    } catch (err) {}
  }
  const newRequestInfo = {
    timestamp: now,
    api: selectedAPI.name
  };
  await env.USER_KEYS_KV.put(lastRequestKey, JSON.stringify(newRequestInfo), { expirationTtl: 60 });
  if (selectedAPI.name === 'API1') {
    const ttlUntilMidnight = secondsUntilMidnight();
    await env.USER_KEYS_KV.put(dailyCountKey, String(dailyCount + 1), { expirationTtl: ttlUntilMidnight });
  }
  return selectedAPI;
}
// We do not recommend using this feature because it is unstable.
// --- Load Balancing for Embedding API (v2 - unchanged) ---
async function selectUpstreamEmbedding(env) {
  const now = Date.now();
  const today = new Date().toISOString().slice(0, 10);
  const embedding1 = {
    baseUrl: env.UPSTREAM_EMBEDDING_BASE_URL,
    apiKey: env.REAL_EMBEDDING_API_KEY,
    modelId: env.EMBEDDING_MODEL_ID,
    name: 'EMBEDDING1'
  };
  const embedding2 = {
    baseUrl: env.UPSTREAM_EMBEDDING_BASE_URL_2,
    apiKey: env.REAL_EMBEDDING_API_KEY_2,
    modelId: env.EMBEDDING_MODEL_ID_2 || env.EMBEDDING_MODEL_ID,
    name: 'EMBEDDING2'
  };
  if (!embedding2.baseUrl || !embedding2.apiKey) {
    return embedding1;
  }
  const dailyCountKey = `embedding1_daily_count:${today}`;
  const rawCount = await env.USER_KEYS_KV.get(dailyCountKey);
  const dailyCount = rawCount ? parseInt(rawCount, 10) : 0;
  const DAILY_LIMIT = parseInt(env.DAILY_LIMIT || '2500', 10); 
  if (dailyCount >= DAILY_LIMIT) {
    return embedding2;
  }
  const lastRequestKey = 'last_embedding_request_info';
  const lastRequestRaw = await env.USER_KEYS_KV.get(lastRequestKey);
  let selected = embedding1;
  if (lastRequestRaw) {
    try {
      const lastRequest = JSON.parse(lastRequestRaw);
      const timeSince = now - lastRequest.timestamp;
      if (timeSince < 2000) {
        selected = lastRequest.api === 'EMBEDDING1' ? embedding2 : embedding1;
      }
    } catch {}
  }
  const newInfo = { timestamp: now, api: selected.name };
  await env.USER_KEYS_KV.put(lastRequestKey, JSON.stringify(newInfo), { expirationTtl: 60 });
  if (selected.name === 'EMBEDDING1') {
    const ttl = secondsUntilMidnight();
    await env.USER_KEYS_KV.put(dailyCountKey, String(dailyCount + 1), { expirationTtl: ttl });
  }
  return selected;
}

// --- Get Knowledge Retrieval (v2 - unchanged) ---
async function getKnowledgeRetrieval(env, query, knowledgeText, config) {
  const { baseUrl, apiKey, modelId } = config;
  if (!baseUrl || !apiKey || !modelId) {
    console.error('Embedding/Retrieval API not configured');
    return '';
  }
  const url = new URL('/v1/chat/completions', baseUrl).toString();
  const PROMPT_KEY = 'config:retrieval_prompt';
  const DEFAULT_PROMPT = "You are a retrieval assistant. Based on the provided CONTEXT, find the most relevant information to answer the user's QUERY. Extract only the relevant text snippets. If no context is relevant, return an empty string.";
  const systemPrompt = (await env.USER_KEYS_KV.get(PROMPT_KEY)) || DEFAULT_PROMPT;
  const messages = [
    { role: 'system', content: systemPrompt },
    { 
      role: 'user', 
      content: `CONTEXT:\n${knowledgeText}\n\nQUERY:\n${query}`
    }
  ];
  const body = JSON.stringify({
    model: modelId,
    messages: messages,
    max_tokens: 400,
    temperature: 0.2
  });

  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body
    });
    if (!resp.ok) throw new Error(`Retrieval API error: ${resp.status}`);
    const data = await resp.json();
    return data.choices[0].message.content || '';
  } catch (err) {
    console.error(err);
    return ''; 
  }
}

// --- Helper Functions (v2 - unchanged) ---
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' }
  });
}

function secondsUntilMonthEnd() {
  const now = new Date();
  const year = now.getUTCFullYear();
  const month = now.getUTCMonth();
  const nextMonth = new Date(Date.UTC(year, month + 1, 1, 0, 0, 0));
  const seconds = Math.ceil((nextMonth.getTime() - now.getTime()) / 1000) + 5;
  return seconds;
}

function secondsUntilMidnight() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setUTCHours(24, 0, 0, 0);
  const seconds = Math.ceil((tomorrow.getTime() - now.getTime()) / 1000) + 5;
  return seconds;
}
// Admin login control page
// --- Admin Login Page (v2 - unchanged) ---
function serveAdminLogin() {
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Login</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f7f7fb}
    .box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,0.08);width:360px}
    h2{text-align:center;margin-bottom:24px;color:#1d1d1f}
    input{width:100%;padding:12px;margin:8px 0;border:1px solid #ddd;border-radius:8px;font-size:14px}
    button{width:100%;padding:12px;border:0;border-radius:8px;background:#2563eb;color:#fff;font-weight:600;cursor:pointer;margin-top:8px;font-size:14px}
    button:hover{background:#1d4ed8}
  </style>
</head>
<body>
  <div class="box">
    <h2>🔐 Admin Login</h2>
    <form id="loginForm" method="POST" action="/admin">
      <input type="text" id="username" name="username" placeholder="Username" required autocomplete="username" />
      <input type="password" id="password" name="password" placeholder="Password" required autocomplete="current-password" />
      <button type="submit">Login</button>
    </form>
  </div>
  </body>
</html>`;
  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// --- MODIFIED: Admin Panel (v3.1) ---
// (HTML and JS updated for v3)
async function handleAdmin(request, env) {
  const url = new URL(request.url);
  let username = '';
  let password = '';

  if (request.method === 'POST') {
    try {
      const formData = await request.formData();
      username = formData.get('username') || '';
      password = formData.get('password') || '';
    } catch (e) {
      return new Response('Invalid login request', { status: 400, headers: { 'content-type': 'text/html; charset=utf-8' } });
    }
  } else if (request.method === 'GET') {
     return new Response(null, { status: 302, headers: { 'Location': '/admin/login' } });
  } else {
    return new Response('Method not allowed', { status: 405 });
  }

  const adminUsername = env.ADMIN_USERNAME || 'Panghu1102';
  const adminPassword = env.ADMIN_PASSWORD;

  if (!adminPassword) {
    return new Response('Error: ADMIN_PASSWORD environment variable not set.', {
      status: 500,
      headers: { 'content-type': 'text/html; charset=utf-8' }
    });
  }

  if (username !== adminUsername || password !== adminPassword) {
    const errorHtml = `<!doctype html><html><head><meta charset="utf-8"/><title>Authentication Failed</title>
      <style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f7f7fb}
      .box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,0.08);text-align:center;max-width:400px}
      h2{color:#dc2626;margin-bottom:16px}p{color:#666;margin-bottom:20px}
      a{display:inline-block;padding:10px 20px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px}
      </style></head><body><div class="box"><h2>❌ Authentication Failed</h2><p>Incorrect username or password</p>
      <a href="/admin/login">Back to login</a></div></body></html>`;
    return new Response(errorHtml, { status: 401, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  // Admin Panel HTML (v3.1 - header updated)
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Admin Panel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto; background: #f5f5f7; padding: 20px; }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 { color: #1d1d1f; margin-bottom: 24px; font-size: 32px; }
    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .stat-card { background: #fff; padding: 20px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    .stat-card h3 { font-size: 14px; color: #86868b; margin-bottom: 8px; font-weight: 500; }
    .stat-card .value { font-size: 32px; font-weight: 600; color: #1d1d1f; }
    .table-container { background: #fff; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); overflow: hidden; margin-bottom: 40px; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #f5f5f7; padding: 12px 16px; text-align: left; font-weight: 600; font-size: 13px; color: #1d1d1f; border-bottom: 1px solid #d2d2d7; }
    td { padding: 12px 16px; border-bottom: 1px solid #f5f5f7; font-size: 14px; color: #1d1d1f; word-break: break-all; }
    tr:hover { background: #fafafa; }
    .loading { text-align: center; padding: 40px; color: #86868b; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: 500; }
    .badge.active { background: #d1f4e0; color: #0d7a3f; }
    .badge.warning { background: #fff3cd; color: #856404; }
    .badge.danger { background: #f8d7da; color: #721c24; }
    .badge.banned { background: #fee2e2; color: #991b1b; }
    .refresh-btn { background: #2563eb; color: #fff; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-weight: 600; margin-bottom: 16px; }
    .refresh-btn:hover { background: #1d4ed8; }
    .action-btn { padding: 4px 8px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; margin: 0 2px; }
    .btn-ban { background: #fbbf24; color: #000; }
    .btn-unban { background: #10b981; color: #fff; }
    .btn-delete { background: #ef4444; color: #fff; }
    .btn-quota { background: #3b82f6; color: #fff; }
    .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center; }
    .modal.show { display: flex; }
    .modal-content { background: #fff; padding: 24px; border-radius: 12px; max-width: 500px; width: 90%; }
    .modal-content h3 { margin-bottom: 16px; }
    .modal-content input, .modal-content textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 6px; margin-top: 8px; }
    .modal-buttons { display: flex; gap: 8px; margin-top: 16px; }
    .modal-buttons button { flex: 1; padding: 10px; border-radius: 8px; cursor: pointer; }
    .btn-cancel { border: 1px solid #ddd; background: #fff; }
    .btn-confirm { border: 0; background: #2563eb; color: #fff; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛠️ Admin Panel</h1>
    
    <div class="stats">
      <div class="stat-card">
        <h3>Total Users</h3>
        <div class="value" id="totalUsers">-</div>
      </div>
      <div class="stat-card">
        <h3>Total Calls This Month</h3>
        <div class="value" id="totalCalls">-</div>
      </div>
      <div class="stat-card">
        <h3>Remaining Quota This Month</h3>
        <div class="value" id="remainingQuota">-</div>
      </div>
      <div class="stat-card">
        <h3>Quota Usage Rate</h3>
        <div class="value" id="usageRate">-</div>
      </div>
      <div class="stat-card">
        <h3>API1 Calls Today</h3>
        <div class="value" id="api1DailyCount">-</div>
      </div>
      <div class="stat-card">
        <h3>API1 Remaining Today</h3>
        <div class="value" id="api1Remaining">-</div>
      </div>
    </div>

    <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
    <button class="refresh-btn" onclick="testConnection()" style="background:#10b981;margin-left:8px">🔌 Test API Connectivity</button>

    <h1 style="margin-top:40px">User Management</h1>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Username (Email)</th>
            <th>Registered At</th>
            <th>Registration IP</th>
            <th>Activation Method</th>
            <th>Used This Month</th>
            <th>Remaining This Month</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="userTable">
          <tr><td colspan="8" class="loading">Loading...</td></tr>
        </tbody>
      </table>
    </div>

    <h1 style="margin-top:40px">Advanced Features</h1>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Feature</th>
            <th>Status</th>
            <th>Description</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Load Balancing</strong></td>
            <td><span id="loadBalancingStatus" class="badge">Loading...</span></td>
            <td>When enabled, auto-switch between API1 and API2; when disabled, select API based on client's model name</td>
            <td>
              <button class="action-btn btn-unban" id="toggleLoadBalancing" onclick="toggleLoadBalancing()">Toggle</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h1>Knowledge Management</h1>
    <button class="refresh-btn" onclick="addKnowledge()" style="background:#10b981">➕ Add Knowledge</button>
    <button class="refresh-btn" onclick="editRetrievalPrompt()" style="background:#3b82f6; margin-left: 8px;">✏️ Edit Retrieval Prompt</button>
    <button class="refresh-btn" onclick="loadKnowledge()" style="margin-left: 8px;">🔄 Refresh Knowledge</button>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Name</th>
            <th>Content (Preview)</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="knowledgeTable">
          <tr><td colspan="4" class="loading">Loading...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div id="modal" class="modal">
    <div class="modal-content">
      <h3 id="modalTitle"></h3>
      <div id="modalContent"></div>
      <div class="modal-buttons">
        <button class="btn-cancel" onclick="closeModal()">Cancel</button>
        <button class="btn-confirm" id="modalConfirm">Confirm</button>
      </div>
    </div>
  </div>

  <script>
    // credentials injected by server (v2 unchanged)
    const username = ${JSON.stringify(username)};
    const password = ${JSON.stringify(password)};
    
    // JS (v3.1 - loadData rendering updated)
    async function loadData() {
      try {
        const res = await fetch('/admin/api/users?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
        if (!res.ok) {
          if (res.status === 401) window.location.href = '/admin/login'; 
          document.getElementById('userTable').innerHTML = '<tr><td colspan="8" class="loading" style="color:red">Load failed: ' + res.status + '</td></tr>';
          return;
        }
        
        const data = await res.json();
        
        document.getElementById('totalUsers').textContent = data.totalUsers;
        document.getElementById('totalCalls').textContent = data.totalCalls;
        document.getElementById('remainingQuota').textContent = data.remainingQuota;
        document.getElementById('usageRate').textContent = data.usageRate;
        document.getElementById('api1DailyCount').textContent = data.api1DailyCount || 0;
        document.getElementById('api1Remaining').textContent = data.api1Remaining || 2500;
        
        const tbody = document.getElementById('userTable');
        if (data.users.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" class="loading">No users</td></tr>';
          return;
        }
        
        // v3.1 rendering
        tbody.innerHTML = data.users.map(u => {
          let statusClass, statusText;
          if (u.status === 'banned') {
            statusClass = 'banned';
            statusText = 'Banned';
          } else if (u.remaining > 100) {
            statusClass = 'active';
            statusText = 'Active';
          } else if (u.remaining > 0) {
            statusClass = 'warning';
            statusText = 'Active';
          } else {
            statusClass = 'danger';
            statusText = 'Depleted';
          }
          
          const isBanned = u.status === 'banned';
          const actions = isBanned 
            ? '<button class="action-btn btn-unban" onclick="unbanUser(\\''+u.username+'\\')">Unban</button>' // u.username is email
            : '<button class="action-btn btn-ban" onclick="banUser(\\''+u.username+'\\')">Ban</button>';
          
          // u.username is now email
          // u.activationCode is 'email-verification' or 'legacy-user' or an old activation code
          return '<tr>' +
            '<td><strong>'+u.username+'</strong></td>' + 
            '<td>'+u.createdAt+'</td>' +
            '<td>'+(u.registrationIP || '-')+'</td>' +
            '<td>'+u.activationCode+'</td>' + 
            '<td>'+u.used+'</td>' +
            '<td>'+u.remaining+'</td>' +
            '<td><span class="badge '+statusClass+'">'+statusText+'</span></td>' +
            '<td>'+actions+
            '<button class="action-btn btn-quota" onclick="addQuota(\\''+u.username+'\\')">Add Quota</button>' +
            '<button class="action-btn btn-delete" onclick="deleteUser(\\''+u.username+'\\')">Delete</button></td>' +
          '</tr>';
        }).join('');
      } catch (err) {
        document.getElementById('userTable').innerHTML = '<tr><td colspan="8" class="loading" style="color:red">Error: ' + err.message + '</td></tr>';
      }
    }

    // (v2 unchanged)
    async function loadKnowledge() {
      try {
        const res = await fetch('/admin/api/knowledge?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
        if (!res.ok) {
          if (res.status === 401) window.location.href = '/admin/login';
          document.getElementById('knowledgeTable').innerHTML = '<tr><td colspan="4" class="loading" style="color:red">Load failed: ' + res.status + '</td></tr>';
          return;
        }
        
        const data = await res.json();
        const tbody = document.getElementById('knowledgeTable');
        if (data.knowledge.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" class="loading">No knowledge</td></tr>';
          return;
        }
        
        tbody.innerHTML = data.knowledge.map(k => {
          const preview = k.text.substring(0, 100) + (k.text.length > 100 ? '...' : '');
          return '<tr>' +
            '<td>'+k.id+'</td>' +
            '<td>'+ (k.name || '-') +'</td>' +
            '<td>'+preview+'</td>' +
            '<td><button class="action-btn btn-delete" onclick="deleteKnowledge(\\''+k.id+'\\')">Delete</button></td>' +
          '</tr>';
        }).join('');
      } catch (err) {
        document.getElementById('knowledgeTable').innerHTML = '<tr><td colspan="4" class="loading" style="color:red">Error: ' + err.message + '</td></tr>';
      }
    }
    
    // (v2 unchanged)
    async function performAction(action, target, extraData = {}) {
      try {
        const res = await fetch('/admin/api/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username, 
            password, 
            action,
            target,
            ...extraData
          })
        });
        const result = await res.json();
        if (res.ok) {
          alert(result.message || 'Operation successful');
          if (action.includes('Knowledge') || action.includes('Prompt')) {
             if (action.includes('Knowledge')) loadKnowledge();
          } else {
             loadData();
          }
        } else {
          alert('Operation failed: ' + (result.error || 'Unknown error'));
        }
      } catch (err) {
        alert('Operation failed: ' + err.message);
      }
    }
    
    // (v2 unchanged)
    function banUser(targetUsername) {
      if (confirm('Are you sure you want to ban user ' + targetUsername + ' ?')) {
        performAction('ban', targetUsername);
      }
    }
    
    // (v2 unchanged)
    function unbanUser(targetUsername) {
      if (confirm('Are you sure you want to unban user ' + targetUsername + ' ?')) {
        performAction('unban', targetUsername);
      }
    }
    
    // (v2 unchanged)
    function deleteUser(targetUsername) {
      if (confirm('Are you sure you want to delete user ' + targetUsername + ' ? This action is irreversible!')) {
        performAction('delete', targetUsername);
      }
    }
    
    // (v2 unchanged)
    function addQuota(targetUsername) {
      document.getElementById('modalTitle').textContent = 'Increase Quota';
      document.getElementById('modalContent').innerHTML = 
        '<p>Increase monthly quota for user <strong>' + targetUsername + '</strong></p>' +
        '<input type="number" id="quotaAmount" placeholder="Enter quota amount" min="1" value="100" />';
      document.getElementById('modal').classList.add('show');
      
      document.getElementById('modalConfirm').onclick = function() {
        const amount = parseInt(document.getElementById('quotaAmount').value);
        if (amount && amount > 0) {
          performAction('addQuota', targetUsername, { amount });
          closeModal();
        } else {
          alert('Please enter a valid quota amount');
        }
      };
    }

    // (v2 unchanged)
    function addKnowledge() {
      document.getElementById('modalTitle').textContent = 'Add Knowledge';
      document.getElementById('modalContent').innerHTML = 
        '<p>Knowledge name (optional)</p>' +
        '<input type="text" id="knowledgeName" placeholder="Enter knowledge name" />' +
        '<p>Upload a file (TXT, MD, JSON, etc.) or input text</p>' +
        '<input type="file" id="knowledgeFile" accept=".txt,.md,.json,.csv" />' +
        '<textarea id="knowledgeText" placeholder="Or paste knowledge text directly" rows="5"></textarea>';
      document.getElementById('modal').classList.add('show');
      
      document.getElementById('modalConfirm').onclick = async function() {
        const name = document.getElementById('knowledgeName').value.trim();
        const file = document.getElementById('knowledgeFile').files[0];
        const text = document.getElementById('knowledgeText').value.trim();
        
        if (!file && !text) {
          alert('Please upload a file or input text');
          return;
        }

        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password); 
        if (name) formData.append('name', name);
        if (file) formData.append('file', file);
        if (text) formData.append('text', text);

        try {
          const res = await fetch('/admin/api/add-knowledge', {
            method: 'POST',
            body: formData
          });
          const result = await res.json();
          if (res.ok) {
            alert(result.message || 'Added successfully');
            loadKnowledge();
            closeModal();
          } else {
            alert('Add failed: ' + (result.error || 'Unknown error'));
          }
        } catch (err) {
          alert('Add failed: ' + err.message);
        }
      };
    }

    // (v2 unchanged)
    function editRetrievalPrompt() {
      document.getElementById('modalTitle').textContent = 'Edit Retrieval Prompt';
      document.getElementById('modalContent').innerHTML = '<p>Loading current prompt...</p>';
      document.getElementById('modalConfirm').disabled = true;
      document.getElementById('modal').classList.add('show');
      loadAndShowPromptEditor();
    }
    
    // (v2 unchanged)
    async function loadAndShowPromptEditor() {
      let currentPrompt = '';
      try {
        const res = await fetch('/admin/api/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username,
            password,
            action: 'getRetrievalPrompt'
          })
        });
        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.error || 'Failed to load prompt');
        }
        const data = await res.json();
        currentPrompt = data.prompt;
      } catch (err) {
        document.getElementById('modalContent').innerHTML = '<p style="color:red">Load failed: ' + err.message + '</p>';
        return;
      }

      document.getElementById('modalContent').innerHTML = 
        '<p>Edit the "retrieval assistant" (Embedding API) system prompt.</p>' +
        '<p style="font-size:12px; color:#666;">This prompt is used by the getKnowledgeRetrieval function.</p>' +
        '<textarea id="promptText" rows="10" style="width:100%; font-family: monospace; font-size: 13px; margin-top: 8px;"></textarea>';
      document.getElementById('promptText').value = currentPrompt;
      document.getElementById('modalConfirm').disabled = false;

      document.getElementById('modalConfirm').onclick = async function() {
        const newPrompt = document.getElementById('promptText').value.trim();
        if (!newPrompt) {
          alert('Prompt cannot be empty');
          return;
        }
        document.getElementById('modalConfirm').disabled = true;
        document.getElementById('modalConfirm').textContent = 'Saving...';
        try {
          await performAction('updateRetrievalPrompt', null, { prompt: newPrompt });
          closeModal();
        } catch (err) {
        } finally {
          document.getElementById('modalConfirm').disabled = false;
          document.getElementById('modalConfirm').textContent = 'Confirm';
        }
      };
    }

    // (v2 unchanged)
    function deleteKnowledge(id) {
      if (confirm('Are you sure you want to delete knowledge ID ' + id + ' ?')) {
        performAction('deleteKnowledge', id);
      }
    }
    
    // (v2 unchanged)
    function closeModal() {
      document.getElementById('modal').classList.remove('show');
    }
    
    // (v2 unchanged)
    async function testConnection() {
      if (!confirm('Are you sure you want to test API connectivity? This will send test requests to both APIs.')) {
        return;
      }
      const btn = event.target;
      btn.disabled = true;
      btn.textContent = '🔄 Testing...';
      try {
        const res = await fetch('/admin/api/test-connection', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const result = await res.json();
        if (res.ok) {
          let message = '=== API Connectivity Test Results ===\\n\\n';
          if (result.api1) {
            message += 'API1 (' + (result.api1.baseUrl || 'N/A') + '):\\n';
            message += 'Status: ' + (result.api1.success ? '✅ Success' : '❌ Failure') + '\\n';
            message += 'Response time: ' + result.api1.responseTime + 'ms\\n';
            if (result.api1.error) message += 'Error: ' + result.api1.error + '\\n';
            message += '\\n';
          }
          if (result.api2) {
            message += 'API2 (' + (result.api2.baseUrl || 'N/A') + '):\\n';
            message += 'Status: ' + (result.api2.success ? '✅ Success' : '❌ Failure') + '\\n';
            message += 'Response time: ' + result.api2.responseTime + 'ms\\n';
            if (result.api2.error) message += 'Error: ' + result.api2.error + '\\n';
          } else {
            message += 'API2: Not configured\\n';
          }
          if (result.embedding1) {
            message += '\\nEmbedding1 (' + (result.embedding1.baseUrl || 'N/A') + '):\\n';
            message += 'Status: ' + (result.embedding1.success ? '✅ Success' : '❌ Failure') + '\\n';
            message += 'Response time: ' + result.embedding1.responseTime + 'ms\\n';
            message += 'Test endpoint: /v1/chat/completions\\n'
            if (result.embedding1.error) message += 'Error: ' + result.embedding1.error + '\\n';
            message += '\\n';
          }
          if (result.embedding2) {
            message += 'Embedding2 (' + (result.embedding2.baseUrl || 'N/A') + '):\\n';
            message += 'Status: ' + (result.embedding2.success ? '✅ Success' : '❌ Failure') + '\\n';
            message += 'Response time: ' + result.embedding2.responseTime + 'ms\\n';
            message += 'Test endpoint: /v1/chat/completions\\n'
            if (result.embedding2.error) message += 'Error: ' + result.embedding2.error + '\\n';
          } else {
            message += 'Embedding2: Not configured\\n';
          }
          alert(message);
        } else {
          alert('Test failed: ' + (result.error || 'Unknown error'));
        }
      } catch (err) {
        alert('Test failed: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = '🔌 Test API Connectivity';
      }
    }
    
    // Load balancing toggle functions
    async function loadLoadBalancingStatus() {
      try {
        const res = await fetch('/admin/api/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username,
            password,
            action: 'getLoadBalancingStatus'
          })
        });
        
        if (res.ok) {
          const data = await res.json();
          const isEnabled = data.enabled;
          const statusSpan = document.getElementById('loadBalancingStatus');
          const toggleBtn = document.getElementById('toggleLoadBalancing');
          
          if (isEnabled) {
            statusSpan.className = 'badge active';
            statusSpan.textContent = 'Enabled';
            toggleBtn.textContent = 'Disable';
            toggleBtn.className = 'action-btn btn-ban';
          } else {
            statusSpan.className = 'badge danger';
            statusSpan.textContent = 'Disabled';
            toggleBtn.textContent = 'Enable';
            toggleBtn.className = 'action-btn btn-unban';
          }
        }
      } catch (err) {
        console.error('Failed to load load balancing status:', err);
      }
    }
    
    async function toggleLoadBalancing() {
      if (!confirm('Are you sure you want to toggle load balancing?')) {
        return;
      }
      
      try {
        const res = await fetch('/admin/api/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username,
            password,
            action: 'toggleLoadBalancing'
          })
        });
        
        const result = await res.json();
        if (res.ok) {
          alert(result.message || 'Operation successful');
          loadLoadBalancingStatus();
        } else {
          alert('Operation failed: ' + (result.error || 'Unknown error'));
        }
      } catch (err) {
        alert('Operation failed: ' + err.message);
      }
    }
    
    loadData();
    loadKnowledge();
    loadLoadBalancingStatus();
  </script>
</body>
</html>`;

  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// --- MODIFIED: Admin API (v3.1) ---
// (updated to support email as username)
async function handleAdminAPI(request, env) {
  const url = new URL(request.url);
  const username = url.searchParams.get('username') || '';
  const password = url.searchParams.get('password') || '';

  const adminUsername = env.ADMIN_USERNAME || 'Panghu1102';
  if (!env.ADMIN_PASSWORD || username !== adminUsername || password !== env.ADMIN_PASSWORD) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  try {
    const yyyyMm = new Date().toISOString().slice(0, 7);
    const QUOTA_PER_USER_PER_MONTH = parseInt(env.QUOTA_PER_USER_PER_MONTH || '999', 10);

    const userList = await env.USER_KEYS_KV.list({ prefix: 'userkey:' });

    const users = [];
    let totalCalls = 0;

    for (const key of userList.keys) {
      const emailAsUsername = key.name.replace('userkey:', ''); 
      const metaRaw = await env.USER_KEYS_KV.get(key.name);

      if (!metaRaw) continue;

      let meta;
      try {
        meta = JSON.parse(metaRaw);
      } catch {
        meta = {};
      }

      const quotaKey = `quota:${emailAsUsername}:${yyyyMm}`;
      const rawUsed = await env.USER_KEYS_KV.get(quotaKey);
      const used = rawUsed ? parseInt(rawUsed, 10) : 0;
      const remaining = Math.max(0, QUOTA_PER_USER_PER_MONTH - used);

      totalCalls += used;

      const registrationIP = meta.registrationIP || '-';
      
      users.push({
        username: emailAsUsername, 
        createdAt: meta.createdAt ? new Date(meta.createdAt).toLocaleString('en-US') : '-',
        registrationIP,
        activationCode: meta.activatedWith || 'legacy-user', // fill with 'email-verification' or old activation code
        used,
        remaining,
        status: meta.status || 'active'
      });
    }

    users.sort((a, b) => {
      const timeA = a.createdAt === '-' ? 0 : new Date(a.createdAt).getTime();
      const timeB = b.createdAt === '-' ? 0 : new Date(b.createdAt).getTime();
      return timeB - timeA;
    });

    const totalUsers = users.length;
    const totalPossibleQuota = totalUsers * QUOTA_PER_USER_PER_MONTH;
    const remainingQuota = totalPossibleQuota - totalCalls;
    const usageRate = totalPossibleQuota > 0 ? ((totalCalls / totalPossibleQuota) * 100).toFixed(1) + '%' : '0%';

    const today = new Date().toISOString().slice(0, 10);
    const dailyCountKey = `api1_daily_count:${today}`;
    const rawDailyCount = await env.USER_KEYS_KV.get(dailyCountKey);
    const api1DailyCount = rawDailyCount ? parseInt(rawDailyCount, 10) : 0;
    const DAILY_LIMIT = parseInt(env.DAILY_LIMIT || '2500', 10);
    const api1Remaining = Math.max(0, DAILY_LIMIT - api1DailyCount);

    return jsonResponse({
      totalUsers,
      totalCalls,
      remainingQuota,
      usageRate,
      api1DailyCount,
      api1Remaining,
      users
    });
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- Admin Knowledge API (v2 - unchanged) ---
async function handleAdminKnowledgeAPI(request, env) {
  const url = new URL(request.url);
  const username = url.searchParams.get('username') || '';
  const password = url.searchParams.get('password') || '';

  const adminUsername = env.ADMIN_USERNAME || 'Panghu1102';
  if (!env.ADMIN_PASSWORD || username !== adminUsername || password !== env.ADMIN_PASSWORD) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  try {
    const stmt = env.KNOWLEDGE_D1.prepare('SELECT id, name, text FROM knowledge ORDER BY CAST(id AS INTEGER)');
    const { results } = await stmt.all();
    const knowledge = results.map(row => ({
      id: row.id,
      name: row.name || null,
      text: row.text
    }));
    return jsonResponse({ knowledge });
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- Add Knowledge (v2 - unchanged) ---
async function handleAddKnowledge(request, env) {
  try {
    const formData = await request.formData();
    const username = formData.get('username');
    const password = formData.get('password');
    const name = formData.get('name') || null;
    const file = formData.get('file');
    let text = formData.get('text') || '';

    const adminUsername = env.ADMIN_USERNAME || 'Panghu1102';
    if (!env.ADMIN_PASSWORD || username !== adminUsername || password !== env.ADMIN_PASSWORD) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    if (!file && !text) {
      return jsonResponse({ error: 'missing file or text' }, 400);
    }

    if (file) {
      text = await file.text();
      if (!['text/plain', 'text/markdown', 'application/json', 'text/csv'].includes(file.type)) {
        return jsonResponse({ error: 'unsupported file type' }, 400);
      }
    }

    if (!text.trim()) {
      return jsonResponse({ error: 'empty content' }, 400);
    }

    const id = Date.now().toString();
    
    const stmt = env.KNOWLEDGE_D1.prepare(
      'INSERT INTO knowledge (id, name, text) VALUES (?, ?, ?)'
    ).bind(id, name, text); 
    
    await stmt.run();

    return jsonResponse({ message: `Knowledge added, ID: ${id}` });
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- Admin Action (v2 - unchanged) ---
async function handleAdminAction(request, env) {
  try {
    const body = await request.json().catch(() => null);
    if (!body) {
      return jsonResponse({ error: 'invalid request body' }, 400);
    }

    const { username, password, action, target, amount, prompt } = body; 

    const adminUsername = env.ADMIN_USERNAME || 'Panghu1102';
    if (!env.ADMIN_PASSWORD || username !== adminUsername || password !== env.ADMIN_PASSWORD) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    switch (action) {
      case 'ban':
        if (!target) return jsonResponse({ error: 'missing target' }, 400);
        const userKeyBan = `userkey:${target}`;
        const metaRawBan = await env.USER_KEYS_KV.get(userKeyBan);
        if (!metaRawBan) return jsonResponse({ error: 'user not found' }, 404);
        let metaBan = JSON.parse(metaRawBan);
        metaBan.status = 'banned';
        await env.USER_KEYS_KV.put(userKeyBan, JSON.stringify(metaBan));
        return jsonResponse({ message: `User ${target} has been banned` });

      case 'unban':
        if (!target) return jsonResponse({ error: 'missing target' }, 400);
        const userKeyUnban = `userkey:${target}`;
        const metaRawUnban = await env.USER_KEYS_KV.get(userKeyUnban);
        if (!metaRawUnban) return jsonResponse({ error: 'user not found' }, 404);
        let metaUnban = JSON.parse(metaRawUnban);
        metaUnban.status = 'active';
        await env.USER_KEYS_KV.put(userKeyUnban, JSON.stringify(metaUnban));
        return jsonResponse({ message: `User ${target} has been unbanned` });

      case 'delete':
        if (!target) return jsonResponse({ error: 'missing target' }, 400);
        const userKeyDel = `userkey:${target}`;
        await env.USER_KEYS_KV.delete(userKeyDel);
        const yyyyMmDel = new Date().toISOString().slice(0, 7);
        const quotaKeyDel = `quota:${target}:${yyyyMmDel}`;
        await env.USER_KEYS_KV.delete(quotaKeyDel);
        return jsonResponse({ message: `User ${target} has been deleted` });

      case 'addQuota':
        if (!target || !amount || amount <= 0) return jsonResponse({ error: 'invalid target or amount' }, 400);
        const yyyyMmAdd = new Date().toISOString().slice(0, 7);
        const quotaKeyAdd = `quota:${target}:${yyyyMmAdd}`;
        const rawUsedAdd = await env.USER_KEYS_KV.get(quotaKeyAdd);
        const usedAdd = rawUsedAdd ? parseInt(rawUsedAdd, 10) : 0;
        const newUsedAdd = Math.max(0, usedAdd - amount);
        const ttlAdd = secondsUntilMonthEnd();
        await env.USER_KEYS_KV.put(quotaKeyAdd, String(newUsedAdd), { expirationTtl: ttlAdd });
        return jsonResponse({ message: `Increased ${amount} quota for user ${target}` });

      case 'deleteKnowledge':
        if (!target) return jsonResponse({ error: 'missing target id' }, 400);
        const stmt = env.KNOWLEDGE_D1.prepare('DELETE FROM knowledge WHERE id = ?').bind(target);
        await stmt.run();
        return jsonResponse({ message: `Knowledge ID ${target} has been deleted` });

      case 'getRetrievalPrompt':
        const PROMPT_KEY = 'config:retrieval_prompt';
        const DEFAULT_PROMPT = "You are a retrieval assistant. Based on the provided CONTEXT, find the most relevant information to answer the user's QUERY. Extract only the relevant text snippets. If no context is relevant, return an empty string.";
        const currentPrompt = await env.USER_KEYS_KV.get(PROMPT_KEY);
        return jsonResponse({ prompt: currentPrompt || DEFAULT_PROMPT });

      case 'updateRetrievalPrompt':
        if (typeof prompt !== 'string' || !prompt.trim()) {
           return jsonResponse({ error: 'prompt is missing or empty' }, 400);
        }
        await env.USER_KEYS_KV.put('config:retrieval_prompt', prompt.trim());
        return jsonResponse({ message: 'Retrieval prompt updated' });

      case 'getLoadBalancingStatus':
        const loadBalancingEnabled = await env.USER_KEYS_KV.get('config:load_balancing_enabled');
        return jsonResponse({ enabled: loadBalancingEnabled === 'true' });

      case 'toggleLoadBalancing':
        const currentStatus = await env.USER_KEYS_KV.get('config:load_balancing_enabled');
        const newStatus = currentStatus === 'true' ? 'false' : 'true';
        await env.USER_KEYS_KV.put('config:load_balancing_enabled', newStatus);
        return jsonResponse({ 
          message: newStatus === 'true' ? 'Load balancing enabled' : 'Load balancing disabled',
          enabled: newStatus === 'true'
        });

      default:
        return jsonResponse({ error: 'unknown action' }, 400);
    }
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- Test API Connection (v2 - unchanged) ---
async function handleTestConnection(request, env) {
  try {
    const body = await request.json().catch(() => null);
    if (!body) {
      return jsonResponse({ error: 'invalid request body' }, 400);
    }

    const { username, password } = body;

    const adminUsername = env.ADMIN_USERNAME || 'Panghu1102';
    if (!env.ADMIN_PASSWORD || username !== adminUsername || password !== env.ADMIN_PASSWORD) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const results = {};

    if (env.UPSTREAM_BASE_URL && env.REAL_API_KEY && env.UPSTREAM_MODEL_ID) {
      const startTime1 = Date.now();
      try {
        const testBody = {
          model: env.UPSTREAM_MODEL_ID,
          messages: [{ role: 'user', content: 'Hi' }],
          max_tokens: 5
        };
        const response1 = await fetch(env.UPSTREAM_BASE_URL + '/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.REAL_API_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(testBody)
        });
        const responseTime1 = Date.now() - startTime1;
        results.api1 = {
          success: response1.ok,
          status: response1.status,
          responseTime: responseTime1,
          baseUrl: env.UPSTREAM_BASE_URL,
          modelId: env.UPSTREAM_MODEL_ID
        };
        if (!response1.ok) {
          const errorText = await response1.text();
          results.api1.error = `HTTP ${response1.status}: ${errorText.substring(0, 200)}`;
        }
      } catch (err) {
        results.api1 = {
          success: false,
          responseTime: Date.now() - startTime1,
          baseUrl: env.UPSTREAM_BASE_URL,
          modelId: env.UPSTREAM_MODEL_ID,
          error: String(err)
        };
      }
    } else {
      results.api1 = {
        success: false,
        error: 'API1 not fully configured (requires UPSTREAM_BASE_URL, REAL_API_KEY, UPSTREAM_MODEL_ID)'
      };
    }

    if (env.UPSTREAM_BASE_URL_2 && env.REAL_API_KEY_2) {
      const modelId2 = env.UPSTREAM_MODEL_ID_2 || env.UPSTREAM_MODEL_ID;
      const startTime2 = Date.now();
      try {
        const testBody = {
          model: modelId2,
          messages: [{ role: 'user', content: 'Hi' }],
          max_tokens: 5
        };
        const response2 = await fetch(env.UPSTREAM_BASE_URL_2 + '/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.REAL_API_KEY_2}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(testBody)
        });
        const responseTime2 = Date.now() - startTime2;
        results.api2 = {
          success: response2.ok,
          status: response2.status,
          responseTime: responseTime2,
          baseUrl: env.UPSTREAM_BASE_URL_2,
          modelId: modelId2
        };
        if (!response2.ok) {
          const errorText = await response2.text();
          results.api2.error = `HTTP ${response2.status}: ${errorText.substring(0, 200)}`;
        }
      } catch (err) {
        results.api2 = {
          success: false,
          responseTime: Date.now() - startTime2,
          baseUrl: env.UPSTREAM_BASE_URL_2,
          modelId: modelId2,
          error: String(err)
        };
      }
    } else {
      results.api2 = null; 
    }

    if (env.UPSTREAM_EMBEDDING_BASE_URL && env.REAL_EMBEDDING_API_KEY && env.EMBEDDING_MODEL_ID) {
      const startTimeE1 = Date.now();
      try {
        const testBody = {
          model: env.EMBEDDING_MODEL_ID,
          messages: [{ role: 'user', content: 'Hi' }],
          max_tokens: 5
        };
        const responseE1 = await fetch(env.UPSTREAM_EMBEDDING_BASE_URL + '/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.REAL_EMBEDDING_API_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(testBody)
        });
        const responseTimeE1 = Date.now() - startTimeE1;
        results.embedding1 = {
          success: responseE1.ok,
          status: responseE1.status,
          responseTime: responseTimeE1,
          baseUrl: env.UPSTREAM_EMBEDDING_BASE_URL,
          modelId: env.EMBEDDING_MODEL_ID
        };
        if (!responseE1.ok) {
          const errorText = await responseE1.text();
          results.embedding1.error = `HTTP ${responseE1.status}: ${errorText.substring(0, 200)}`;
        }
      } catch (err) {
        results.embedding1 = {
          success: false,
          responseTime: Date.now() - startTimeE1,
          baseUrl: env.UPSTREAM_EMBEDDING_BASE_URL,
          modelId: env.EMBEDDING_MODEL_ID,
          error: String(err)
        };
      }
    } else {
      results.embedding1 = {
        success: false,
        error: 'Embedding1 not fully configured'
      };
    }

    if (env.UPSTREAM_EMBEDDING_BASE_URL_2 && env.REAL_EMBEDDING_API_KEY_2) {
      const modelIdE2 = env.EMBEDDING_MODEL_ID_2 || env.EMBEDDING_MODEL_ID;
      const startTimeE2 = Date.now();
      try {
        const testBody = {
          model: modelIdE2,
          messages: [{ role: 'user', content: 'Hi' }],
          max_tokens: 5
        };
        const responseE2 = await fetch(env.UPSTREAM_EMBEDDING_BASE_URL_2 + '/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.REAL_EMBEDDING_API_KEY_2}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(testBody)
        });
        const responseTimeE2 = Date.now() - startTimeE2;
        results.embedding2 = {
          success: responseE2.ok,
          status: responseE2.status,
          responseTime: responseTimeE2,
          baseUrl: env.UPSTREAM_EMBEDDING_BASE_URL_2,
          modelId: modelIdE2
        };
        if (!responseE2.ok) {
          const errorText = await responseE2.text();
          results.embedding2.error = `HTTP ${responseE2.status}: ${errorText.substring(0, 200)}`;
        }
      } catch (err) {
        results.embedding2 = {
          success: false,
          responseTime: Date.now() - startTimeE2,
          baseUrl: env.UPSTREAM_EMBEDDING_BASE_URL_2,
          modelId: modelIdE2,
          error: String(err)
        };
      }
    } else {
      results.embedding2 = null;
    }

    return jsonResponse(results);
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}
