// 一个基于CloudFlare Worker，可以实现AI网关，用户注册，用户管理，强制替换提示词及更改请求体，BM25等功能的js！仅需3分钟即可完成部署
// Github仓库：https://github.com/Panghu1102/cfRelay   麻烦star啦！
// 开发者：Panghu1102
// 当前版本：1.0.0   内部版本：v3.2.1
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    // 注册声明：需要搭配jyacssignup邮件Worker使用，本文件在相同目录下
    // --- v3.2 注册路由 ---
    if (request.method === 'GET' && (path === '/' || path === '/index.html')) {
      return serveSignupPage(); // 已替换为 v3.2 页面 (带激活码)
    }
    if (request.method === 'POST' && path === '/signup') {
      return handleSignup(request, env); // 已替换为 v3.2 逻辑 (带激活码检查)
    }
    // (新) v3.2 轮询路由
    if (request.method === 'GET' && path === '/signup-status') {
      return handleSignupStatus(request, env);
    }
    // --- 结束 ---

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

    // 其他路径代理 (v2 不变)
    return handleProxy(request, env);
  }
};

// --- MODIFIED: HTML Signup Page (v3.2) ---
// 表单更新为 email, password, captcha, 和 activation
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
      <h3>注册</h3>
      <form id="signupForm">
        <input id="email" name="email" type="email" placeholder="邮箱账号 (将作为你的API Key)" required />
        <input id="password" name="password" type="password" placeholder="设置密码 (最少8位)" required minlength="8" />
        <input id="captcha" name="captcha" placeholder="验证码 (输入任意4位字符)" required minlength="4" />
        <input id="activation" name="activation" placeholder="激活码" required />
        <button type="submit">下一步</button>
      </form>
      <div class="note" id="noteArea">
        注册流程：<br/>
        1. 填写所有信息 (包括激活码)。<br/>
        2. 点击“下一步”。<br/>
        3. 登录您的邮箱，<b>发送一封邮件</b>。
      </div>
      <div id="msg" style="margin-top:10px;color:green;font-weight:bold;"></div>
    </div>
  <script>
    const f = document.getElementById('signupForm');
    const msg = document.getElementById('msg');
    const note = document.getElementById('noteArea');

    // (新) v3.2 轮询函数
    function startPolling(email) {
      const startTime = Date.now();
      msg.style.color = '#1d4ed8';
      
      const intervalId = setInterval(async () => {
        // 15 分钟后停止轮询
        if (Date.now() - startTime > 900000) { // 15 * 60 * 1000
          clearInterval(intervalId);
          msg.style.color = 'red';
          msg.textContent = '激活超时 (15分钟)。请刷新页面重试。';
          return;
        }
        
        try {
          // 向新端点 /signup-status 发送请求
          const res = await fetch('/signup-status?email=' + encodeURIComponent(email));
          const data = await res.json();
          
          if (data.status === 'complete') {
            // --- 注册成功 ---
            clearInterval(intervalId);
            // 显示最终的 "注册完成" 页面
            document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh">' +
              '<div style="text-align:center">' +
              '<h2>注册完成 🎉</h2>' +
              '<p>您的账户 <b>' + email + '</b> 已成功激活。</p>' +
              '<p>现在可以关闭此页, 使用您的邮箱作为 API Key。</p></div></div>';
          } else {
            // 仍在等待... (可选: 更新消息)
            msg.textContent = '请求已提交... 正在等待邮件验证...';
          }
        } catch (err) {
          // 忽略 fetch 错误 (例如网络波动)，轮询将自动重试
          console.error('Polling error:', err);
        }
      }, 5000); // 每 5 秒轮询一次
    }

    // v3.2 提交事件处理器
    f.addEventListener('submit', async (e)=> {
      e.preventDefault();
      msg.style.color='green'; msg.textContent='正在提交请求...';
      
      const email = document.getElementById('email').value.trim();
      const password = document.getElementById('password').value.trim();
      const captcha = document.getElementById('captcha').value.trim();
      const activation = document.getElementById('activation').value.trim(); // (新) 获取激活码
      
      try {
        const res = await fetch('/signup', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          // (新) 将 activationCode 发送到后端
          body: JSON.stringify({ email, password, captcha, activationCode: activation }) 
        });
        
        const j = await res.json();
        
        if (res.ok) {
          // 注册请求成功，隐藏表单并显示下一步指示
          f.style.display = 'none'; 
          msg.innerHTML = '✅ 请求已提交！请立即激活：';
          note.innerHTML = '请登录您的邮箱 <b>' + email + '</b><br/><br/>' +
            '并发送一封新邮件：<br/>' +
            '<b>收件人:</b> <code>signup@jyacs.dpdns.org</code><br/>' +
            '<b>主题:</b> <code>验证</code><br/><br/>' +
            '发送邮件后，您的账户将在一分钟内激活。此请求 15 分钟内有效。';
          
          // --- (新) v3.2 开始轮询 ---
          startPolling(email);

        } else {
          // 失败 (例如: 激活码错误, 邮箱已存在)
          msg.style.color='red';
          msg.textContent = j.error || '注册失败';
        }
      } catch (err) {
        msg.style.color='red';
        msg.textContent='网络错误';
      }
    });
  </script>
  </body></html>`;
  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// --- MODIFIED: Handle Signup (v3.2) ---
// (增加了激活码验证)
async function handleSignup(request, env) {
  try {
    const body = await request.json().catch(() => null);
    // (新) 检查 activationCode
    if (!body || !body.email || !body.password || !body.captcha || !body.activationCode) {
      return jsonResponse({ error: '缺少 邮箱、密码、验证码或激活码' }, 400);
    }

    const email = String(body.email).trim().toLowerCase();
    const password = String(body.password);
    const captcha = String(body.captcha);
    const activationCode = String(body.activationCode).trim(); // (新)

    // --- (新) v3.2 激活码验证 ---
    // (此逻辑来自您的 v2 版本)
    const activationKey = `activation:${activationCode}`;
    const activationRaw = await env.USER_KEYS_KV.get(activationKey);
    if (!activationRaw) {
      return jsonResponse({ error: '无效的激活码' }, 403);
    }
    // (激活码验证通过)
    // --- 结束 ---

    // (v3.1) 验证邮箱和密码
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return jsonResponse({ error: '无效的邮箱格式' }, 400);
    }
    if (password.length < 8) {
      return jsonResponse({ error: '密码必须至少8位' }, 400);
    }
    if (captcha.length < 4) {
      return jsonResponse({ error: '无效的验证码' }, 400);
    }

    // (v3.1) 检查用户是否存在
    const userKey = `userkey:${email}`;
    const exists = await env.USER_KEYS_KV.get(userKey);
    if (exists) {
      return jsonResponse({ error: '此邮箱已被注册' }, 409);
    }

    // (v3.1) 检查待处理
    const pendingKey = `pending:${email}`;
    const pendingExists = await env.USER_KEYS_KV.get(pendingKey);
    if (pendingExists) {
      return jsonResponse({ error: '此邮箱已有待处理的激活请求，请检查您的邮件或 15 分钟后再试' }, 409);
    }

    // (v3.1) IP 限制
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

    // (v3.1) 哈希密码
    const passHash = await hashPassword(password);

    // (v3.1) 存储待处理记录 (15 分钟 TTL)
    await env.USER_KEYS_KV.put(pendingKey, passHash, { expirationTtl: 900 });

    // (v3.1) 返回成功
    return jsonResponse({ ok: true, message: 'Pending activation. Please send verification email.' }, 200);

  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- NEW: Signup Status Checker (v3.2) ---
// (用于前端轮询)
async function handleSignupStatus(request, env) {
  const url = new URL(request.url);
  const email = url.searchParams.get('email');

  if (!email) {
    return jsonResponse({ error: 'missing email' }, 400);
  }

  // 检查最终的用户 key 是否已由 jyacssignup worker 创建
  const userKey = `userkey:${email.toLowerCase()}`;
  const meta = await env.USER_KEYS_KV.get(userKey);

  if (meta) {
    // 邮件 Worker 已成功处理
    return jsonResponse({ status: 'complete' });
  } else {
    // 仍在等待邮件
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

// --- Proxy Request (v2 - 不变) ---
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

  // 检查负载均衡开关状态
  const loadBalancingEnabled = await env.USER_KEYS_KV.get('config:load_balancing_enabled');
  const isLoadBalancingOn = loadBalancingEnabled === 'true';

  let apiConfig = {
    baseUrl: env.UPSTREAM_BASE_URL,
    apiKey: env.REAL_API_KEY,
    modelId: env.UPSTREAM_MODEL_ID,
    name: 'API1'
  };
  let bodyToForward;
  const newHeaders = new Headers(request.headers);

  if (!apiConfig.baseUrl) {
    return jsonResponse({ error: 'Upstream API base URL is not configured by administrator.' }, 500);
  }

  if (request.method === 'POST') {
    try {
      const clonedRequest = request.clone();
      const originalBody = await clonedRequest.json();

      const MODEL_NAME_1 = env.REQUIRED_MODEL_NAME || 'example-model';
      const MODEL_NAME_2 = env.REQUIRED_MODEL_NAME_2 || 'example-model2';

      if (isLoadBalancingOn) {
        // 负载均衡模式：自动选择 API，接受任一模型名称
        apiConfig = await selectUpstreamAPI(env);
        
        if (!originalBody.model || (originalBody.model !== MODEL_NAME_1 && originalBody.model !== MODEL_NAME_2)) {
          return jsonResponse({ error: `Invalid model ID. You must use "${MODEL_NAME_1}" or "${MODEL_NAME_2}".` }, 400);
        }
      } else {
        // 手动模式：根据请求的模型名称选择对应的 API
        if (!originalBody.model) {
          return jsonResponse({ error: 'Missing model ID.' }, 400);
        }

        if (originalBody.model === MODEL_NAME_1) {
          // 使用 API1
          apiConfig = {
            baseUrl: env.UPSTREAM_BASE_URL,
            apiKey: env.REAL_API_KEY,
            modelId: env.UPSTREAM_MODEL_ID,
            name: 'API1'
          };
        } else if (originalBody.model === MODEL_NAME_2) {
          // 使用 API2
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
      // 这里用来强制system prompts。主要适用于角色扮演以及需要强制提示词来防止滥用和输出不当内容的场景。
      const systemPrompt = `
You are an AI assistant. Use the following SKILL information to help answer the user's question.
${skillContent ? `\nSKILL:\n${skillContent}` : ''}
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

// --- Load Balancing Logic (v2 - 不变) ---
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
    } catch (err) { }
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
// 我们不推荐使用本功能，因为并不稳定。
// --- Load Balancing for Embedding API (v2 - 不变) ---
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
    } catch { }
  }
  const newInfo = { timestamp: now, api: selected.name };
  await env.USER_KEYS_KV.put(lastRequestKey, JSON.stringify(newInfo), { expirationTtl: 60 });
  if (selected.name === 'EMBEDDING1') {
    const ttl = secondsUntilMidnight();
    await env.USER_KEYS_KV.put(dailyCountKey, String(dailyCount + 1), { expirationTtl: ttl });
  }
  return selected;
}

// --- Get Knowledge Retrieval (v2 - 不变) ---
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

// --- Helper Functions (v2 - 不变) ---
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
// 管理员登陆控制页面
// --- Admin Login Page (v2 - 不变) ---
function serveAdminLogin() {
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>管理员登录</title>
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
    <h2>🔐 管理员登录</h2>
    <form id="loginForm" method="POST" action="/admin">
      <input type="text" id="username" name="username" placeholder="用户名" required autocomplete="username" />
      <input type="password" id="password" name="password" placeholder="密码" required autocomplete="current-password" />
      <button type="submit">登录</button>
    </form>
  </div>
  </body>
</html>`;
  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
}

// --- MODIFIED: Admin Panel (v3.1) ---
// (HTML 和 JS 已更新以适应 v3)
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
    return new Response('错误：未设置 ADMIN_PASSWORD 环境变量。', {
      status: 500,
      headers: { 'content-type': 'text/html; charset=utf-8' }
    });
  }

  if (username !== adminUsername || password !== adminPassword) {
    const errorHtml = `<!doctype html><html><head><meta charset="utf-8"/><title>认证失败</title>
      <style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f7f7fb}
      .box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 6px 20px rgba(0,0,0,0.08);text-align:center;max-width:400px}
      h2{color:#dc2626;margin-bottom:16px}p{color:#666;margin-bottom:20px}
      a{display:inline-block;padding:10px 20px;background:#2563eb;color:#fff;text-decoration:none;border-radius:8px}
      </style></head><body><div class="box"><h2>❌ 认证失败</h2><p>用户名或密码错误</p>
      <a href="/admin/login">返回登录</a></div></body></html>`;
    return new Response(errorHtml, { status: 401, headers: { 'content-type': 'text/html; charset=utf-8' } });
  }

  // Admin Panel HTML (v3.1 - 更新了表头)
  const html = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>管理面板</title>
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
    <h1>🛠️ 管理面板</h1>
    
    <div class="stats">
      <div class="stat-card">
        <h3>总用户数</h3>
        <div class="value" id="totalUsers">-</div>
      </div>
      <div class="stat-card">
        <h3>本月总调用</h3>
        <div class="value" id="totalCalls">-</div>
      </div>
      <div class="stat-card">
        <h3>本月剩余配额</h3>
        <div class="value" id="remainingQuota">-</div>
      </div>
      <div class="stat-card">
        <h3>配额使用率</h3>
        <div class="value" id="usageRate">-</div>
      </div>
      <div class="stat-card">
        <h3>API1 今日调用</h3>
        <div class="value" id="api1DailyCount">-</div>
      </div>
      <div class="stat-card">
        <h3>API1 今日剩余</h3>
        <div class="value" id="api1Remaining">-</div>
      </div>
    </div>

    <button class="refresh-btn" onclick="loadData()">🔄 刷新数据</button>
    <button class="refresh-btn" onclick="testConnection()" style="background:#10b981;margin-left:8px">🔌 测试 API 连通性</button>

    <h1 style="margin-top:40px">用户管理</h1>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>用户名 (邮箱)</th>
            <th>注册时间</th>
            <th>注册 IP</th>
            <th>激活方式</th>
            <th>本月已用</th>
            <th>本月剩余</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="userTable">
          <tr><td colspan="8" class="loading">加载中...</td></tr>
        </tbody>
      </table>
    </div>

    <h1 style="margin-top:40px">高级功能</h1>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>功能</th>
            <th>状态</th>
            <th>说明</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>负载均衡</strong></td>
            <td><span id="loadBalancingStatus" class="badge">加载中...</span></td>
            <td>开启后自动在 API1 和 API2 间切换；关闭后根据客户端请求的模型名称选择对应 API</td>
            <td>
              <button class="action-btn btn-unban" id="toggleLoadBalancing" onclick="toggleLoadBalancing()">切换</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <h1>知识库管理</h1>
    <button class="refresh-btn" onclick="addKnowledge()" style="background:#10b981">➕ 添加知识</button>
    <button class="refresh-btn" onclick="editRetrievalPrompt()" style="background:#3b82f6; margin-left: 8px;">✏️ 修改检索提示词</button>
    <button class="refresh-btn" onclick="loadKnowledge()" style="margin-left: 8px;">🔄 刷新知识库</button>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>名称</th>
            <th>内容 (预览)</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="knowledgeTable">
          <tr><td colspan="4" class="loading">加载中...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div id="modal" class="modal">
    <div class="modal-content">
      <h3 id="modalTitle"></h3>
      <div id="modalContent"></div>
      <div class="modal-buttons">
        <button class="btn-cancel" onclick="closeModal()">取消</button>
        <button class="btn-confirm" id="modalConfirm">确认</button>
      </div>
    </div>
  </div>

  <script>
    // 凭证由服务器注入 (v2 不变)
    const username = ${JSON.stringify(username)};
    const password = ${JSON.stringify(password)};
    
    // JS (v3.1 - loadData 渲染逻辑已更新)
    async function loadData() {
      try {
        const res = await fetch('/admin/api/users?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
        if (!res.ok) {
          if (res.status === 401) window.location.href = '/admin/login'; 
          document.getElementById('userTable').innerHTML = '<tr><td colspan="8" class="loading" style="color:red">加载失败: ' + res.status + '</td></tr>';
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
          tbody.innerHTML = '<tr><td colspan="8" class="loading">暂无用户</td></tr>';
          return;
        }
        
        // v3.1 渲染逻辑
        tbody.innerHTML = data.users.map(u => {
          let statusClass, statusText;
          if (u.status === 'banned') {
            statusClass = 'banned';
            statusText = '已封禁';
          } else if (u.remaining > 100) {
            statusClass = 'active';
            statusText = '正常';
          } else if (u.remaining > 0) {
            statusClass = 'warning';
            statusText = '正常';
          } else {
            statusClass = 'danger';
            statusText = '已耗尽';
          }
          
          const isBanned = u.status === 'banned';
          const actions = isBanned 
            ? '<button class="action-btn btn-unban" onclick="unbanUser(\\''+u.username+'\\')">解封</button>' // u.username 是邮箱
            : '<button class="action-btn btn-ban" onclick="banUser(\\''+u.username+'\\')">封禁</button>';
          
          // u.username 现在是邮箱
          // u.activationCode 现在是 'email-verification' 或 'legacy-user' 或旧激活码
          return '<tr>' +
            '<td><strong>'+u.username+'</strong></td>' + 
            '<td>'+u.createdAt+'</td>' +
            '<td>'+(u.registrationIP || '-')+'</td>' +
            '<td>'+u.activationCode+'</td>' + 
            '<td>'+u.used+'</td>' +
            '<td>'+u.remaining+'</td>' +
            '<td><span class="badge '+statusClass+'">'+statusText+'</span></td>' +
            '<td>'+actions+
            '<button class="action-btn btn-quota" onclick="addQuota(\\''+u.username+'\\')">加额度</button>' +
            '<button class="action-btn btn-delete" onclick="deleteUser(\\''+u.username+'\\')">删除</button></td>' +
          '</tr>';
        }).join('');
      } catch (err) {
        document.getElementById('userTable').innerHTML = '<tr><td colspan="8" class="loading" style="color:red">错误: ' + err.message + '</td></tr>';
      }
    }

    // (v2 - 不变)
    async function loadKnowledge() {
      try {
        const res = await fetch('/admin/api/knowledge?username=' + encodeURIComponent(username) + '&password=' + encodeURIComponent(password));
        if (!res.ok) {
          if (res.status === 401) window.location.href = '/admin/login';
          document.getElementById('knowledgeTable').innerHTML = '<tr><td colspan="4" class="loading" style="color:red">加载失败: ' + res.status + '</td></tr>';
          return;
        }
        
        const data = await res.json();
        const tbody = document.getElementById('knowledgeTable');
        if (data.knowledge.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" class="loading">暂无知识</td></tr>';
          return;
        }
        
        tbody.innerHTML = data.knowledge.map(k => {
          const preview = k.text.substring(0, 100) + (k.text.length > 100 ? '...' : '');
          return '<tr>' +
            '<td>'+k.id+'</td>' +
            '<td>'+ (k.name || '-') +'</td>' +
            '<td>'+preview+'</td>' +
            '<td><button class="action-btn btn-delete" onclick="deleteKnowledge(\\''+k.id+'\\')">删除</button></td>' +
          '</tr>';
        }).join('');
      } catch (err) {
        document.getElementById('knowledgeTable').innerHTML = '<tr><td colspan="4" class="loading" style="color:red">错误: ' + err.message + '</td></tr>';
      }
    }
    
    // (v2 - 不变)
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
          alert(result.message || '操作成功');
          if (action.includes('Knowledge') || action.includes('Prompt')) {
             if (action.includes('Knowledge')) loadKnowledge();
          } else {
             loadData();
          }
        } else {
          alert('操作失败: ' + (result.error || '未知错误'));
        }
      } catch (err) {
        alert('操作失败: ' + err.message);
      }
    }
    
    // (v2 - 不变)
    function banUser(targetUsername) {
      if (confirm('确定要封禁用户 ' + targetUsername + ' 吗？')) {
        performAction('ban', targetUsername);
      }
    }
    
    // (v2 - 不变)
    function unbanUser(targetUsername) {
      if (confirm('确定要解封用户 ' + targetUsername + ' 吗？')) {
        performAction('unban', targetUsername);
      }
    }
    
    // (v2 - 不变)
    function deleteUser(targetUsername) {
      if (confirm('确定要删除用户 ' + targetUsername + ' 吗？此操作不可恢复！')) {
        performAction('delete', targetUsername);
      }
    }
    
    // (v2 - 不变)
    function addQuota(targetUsername) {
      document.getElementById('modalTitle').textContent = '增加额度';
      document.getElementById('modalContent').innerHTML = 
        '<p>为用户 <strong>' + targetUsername + '</strong> 增加本月额度</p>' +
        '<input type="number" id="quotaAmount" placeholder="输入额度数量" min="1" value="100" />';
      document.getElementById('modal').classList.add('show');
      
      document.getElementById('modalConfirm').onclick = function() {
        const amount = parseInt(document.getElementById('quotaAmount').value);
        if (amount && amount > 0) {
          performAction('addQuota', targetUsername, { amount });
          closeModal();
        } else {
          alert('请输入有效的额度数量');
        }
      };
    }

    // (v2 - 不变)
    function addKnowledge() {
      document.getElementById('modalTitle').textContent = '添加知识';
      document.getElementById('modalContent').innerHTML = 
        '<p>知识名称（可选）</p>' +
        '<input type="text" id="knowledgeName" placeholder="输入知识名称" />' +
        '<p>上传文件（TXT, MD, JSON 等文本文件）或输入文本</p>' +
        '<input type="file" id="knowledgeFile" accept=".txt,.md,.json,.csv" />' +
        '<textarea id="knowledgeText" placeholder="或直接输入知识文本" rows="5"></textarea>';
      document.getElementById('modal').classList.add('show');
      
      document.getElementById('modalConfirm').onclick = async function() {
        const name = document.getElementById('knowledgeName').value.trim();
        const file = document.getElementById('knowledgeFile').files[0];
        const text = document.getElementById('knowledgeText').value.trim();
        
        if (!file && !text) {
          alert('请上传文件或输入文本');
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
            alert(result.message || '添加成功');
            loadKnowledge();
            closeModal();
          } else {
            alert('添加失败: ' + (result.error || '未知错误'));
          }
        } catch (err) {
          alert('添加失败: ' + err.message);
        }
      };
    }

    // (v2 - 不变)
    function editRetrievalPrompt() {
      document.getElementById('modalTitle').textContent = '修改检索提示词';
      document.getElementById('modalContent').innerHTML = '<p>正在加载当前提示词...</p>';
      document.getElementById('modalConfirm').disabled = true;
      document.getElementById('modal').classList.add('show');
      loadAndShowPromptEditor();
    }
    
    // (v2 - 不变)
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
          throw new Error(errData.error || '无法加载提示词');
        }
        const data = await res.json();
        currentPrompt = data.prompt;
      } catch (err) {
        document.getElementById('modalContent').innerHTML = '<p style="color:red">加载失败: ' + err.message + '</p>';
        return;
      }

      document.getElementById('modalContent').innerHTML = 
        '<p>修改 "检索助手" (Embedding API) 的系统提示词。</p>' +
        '<p style="font-size:12px; color:#666;">此提示词用于 getKnowledgeRetrieval 函数。</p>' +
        '<textarea id="promptText" rows="10" style="width:100%; font-family: monospace; font-size: 13px; margin-top: 8px;"></textarea>';
      document.getElementById('promptText').value = currentPrompt;
      document.getElementById('modalConfirm').disabled = false;

      document.getElementById('modalConfirm').onclick = async function() {
        const newPrompt = document.getElementById('promptText').value.trim();
        if (!newPrompt) {
          alert('提示词不能为空');
          return;
        }
        document.getElementById('modalConfirm').disabled = true;
        document.getElementById('modalConfirm').textContent = '保存中...';
        try {
          await performAction('updateRetrievalPrompt', null, { prompt: newPrompt });
          closeModal();
        } catch (err) {
        } finally {
          document.getElementById('modalConfirm').disabled = false;
          document.getElementById('modalConfirm').textContent = '确认';
        }
      };
    }

    // (v2 - 不变)
    function deleteKnowledge(id) {
      if (confirm('确定要删除知识 ID ' + id + ' 吗？')) {
        performAction('deleteKnowledge', id);
      }
    }
    
    // (v2 - 不变)
    function closeModal() {
      document.getElementById('modal').classList.remove('show');
    }
    
    // (v2 - 不变)
    async function testConnection() {
      if (!confirm('确定要测试 API 连通性吗？这将向两个 API 发送测试请求。')) {
        return;
      }
      const btn = event.target;
      btn.disabled = true;
      btn.textContent = '🔄 测试中...';
      try {
        const res = await fetch('/admin/api/test-connection', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const result = await res.json();
        if (res.ok) {
          let message = '=== API 连通性测试结果 ===\\n\\n';
          if (result.api1) {
            message += 'API1 (' + (result.api1.baseUrl || 'N/A') + '):\\n';
            message += '状态: ' + (result.api1.success ? '✅ 成功' : '❌ 失败') + '\\n';
            message += '响应时间: ' + result.api1.responseTime + 'ms\\n';
            if (result.api1.error) message += '错误: ' + result.api1.error + '\\n';
            message += '\\n';
          }
          if (result.api2) {
            message += 'API2 (' + (result.api2.baseUrl || 'N/A') + '):\\n';
            message += '状态: ' + (result.api2.success ? '✅ 成功' : '❌ 失败') + '\\n';
            message += '响应时间: ' + result.api2.responseTime + 'ms\\n';
            if (result.api2.error) message += '错误: ' + result.api2.error + '\\n';
          } else {
            message += 'API2: 未配置\\n';
          }
          if (result.embedding1) {
            message += '\\nEmbedding1 (' + (result.embedding1.baseUrl || 'N/A') + '):\\n';
            message += '状态: ' + (result.embedding1.success ? '✅ 成功' : '❌ 失败') + '\\n';
            message += '响应时间: ' + result.embedding1.responseTime + 'ms\\n';
            message += '测试端点: /v1/chat/completions\\n'
            if (result.embedding1.error) message += '错误: ' + result.embedding1.error + '\\n';
            message += '\\n';
          }
          if (result.embedding2) {
            message += 'Embedding2 (' + (result.embedding2.baseUrl || 'N/A') + '):\\n';
            message += '状态: ' + (result.embedding2.success ? '✅ 成功' : '❌ 失败') + '\\n';
            message += '响应时间: ' + result.embedding2.responseTime + 'ms\\n';
            message += '测试端点: /v1/chat/completions\\n'
            if (result.embedding2.error) message += '错误: ' + result.embedding2.error + '\\n';
          } else {
            message += 'Embedding2: 未配置\\n';
          }
          alert(message);
        } else {
          alert('测试失败: ' + (result.error || '未知错误'));
        }
      } catch (err) {
        alert('测试失败: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = '🔌 测试 API 连通性';
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
            statusSpan.textContent = '已开启';
            toggleBtn.textContent = '关闭';
            toggleBtn.className = 'action-btn btn-ban';
          } else {
            statusSpan.className = 'badge danger';
            statusSpan.textContent = '已关闭';
            toggleBtn.textContent = '开启';
            toggleBtn.className = 'action-btn btn-unban';
          }
        }
      } catch (err) {
        console.error('Failed to load load balancing status:', err);
      }
    }
    
    async function toggleLoadBalancing() {
      if (!confirm('确定要切换负载均衡状态吗？')) {
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
          alert(result.message || '操作成功');
          loadLoadBalancingStatus();
        } else {
          alert('操作失败: ' + (result.error || '未知错误'));
        }
      } catch (err) {
        alert('操作失败: ' + err.message);
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
// (更新以支持邮箱作为用户名)
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
        createdAt: meta.createdAt ? new Date(meta.createdAt).toLocaleString('zh-CN') : '-',
        registrationIP,
        activationCode: meta.activatedWith || 'legacy-user', // 填充 'email-verification' 或旧的激活码
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

// --- Admin Knowledge API (v2 - 不变) ---
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

// --- Add Knowledge (v2 - 不变) ---
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

    return jsonResponse({ message: `知识已添加，ID: ${id}` });
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- Admin Action (v2 - 不变) ---
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
        return jsonResponse({ message: `用户 ${target} 已被封禁` });

      case 'unban':
        if (!target) return jsonResponse({ error: 'missing target' }, 400);
        const userKeyUnban = `userkey:${target}`;
        const metaRawUnban = await env.USER_KEYS_KV.get(userKeyUnban);
        if (!metaRawUnban) return jsonResponse({ error: 'user not found' }, 404);
        let metaUnban = JSON.parse(metaRawUnban);
        metaUnban.status = 'active';
        await env.USER_KEYS_KV.put(userKeyUnban, JSON.stringify(metaUnban));
        return jsonResponse({ message: `用户 ${target} 已解封` });

      case 'delete':
        if (!target) return jsonResponse({ error: 'missing target' }, 400);
        const userKeyDel = `userkey:${target}`;
        await env.USER_KEYS_KV.delete(userKeyDel);
        const yyyyMmDel = new Date().toISOString().slice(0, 7);
        const quotaKeyDel = `quota:${target}:${yyyyMmDel}`;
        await env.USER_KEYS_KV.delete(quotaKeyDel);
        return jsonResponse({ message: `用户 ${target} 已删除` });

      case 'addQuota':
        if (!target || !amount || amount <= 0) return jsonResponse({ error: 'invalid target or amount' }, 400);
        const yyyyMmAdd = new Date().toISOString().slice(0, 7);
        const quotaKeyAdd = `quota:${target}:${yyyyMmAdd}`;
        const rawUsedAdd = await env.USER_KEYS_KV.get(quotaKeyAdd);
        const usedAdd = rawUsedAdd ? parseInt(rawUsedAdd, 10) : 0;
        const newUsedAdd = Math.max(0, usedAdd - amount);
        const ttlAdd = secondsUntilMonthEnd();
        await env.USER_KEYS_KV.put(quotaKeyAdd, String(newUsedAdd), { expirationTtl: ttlAdd });
        return jsonResponse({ message: `已为用户 ${target} 增加 ${amount} 额度` });

      case 'deleteKnowledge':
        if (!target) return jsonResponse({ error: 'missing target id' }, 400);
        const stmt = env.KNOWLEDGE_D1.prepare('DELETE FROM knowledge WHERE id = ?').bind(target);
        await stmt.run();
        return jsonResponse({ message: `知识 ID ${target} 已删除` });

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
        return jsonResponse({ message: '检索提示词已更新' });

      case 'getLoadBalancingStatus':
        const loadBalancingEnabled = await env.USER_KEYS_KV.get('config:load_balancing_enabled');
        return jsonResponse({ enabled: loadBalancingEnabled === 'true' });

      case 'toggleLoadBalancing':
        const currentStatus = await env.USER_KEYS_KV.get('config:load_balancing_enabled');
        const newStatus = currentStatus === 'true' ? 'false' : 'true';
        await env.USER_KEYS_KV.put('config:load_balancing_enabled', newStatus);
        return jsonResponse({ 
          message: newStatus === 'true' ? '负载均衡已开启' : '负载均衡已关闭',
          enabled: newStatus === 'true'
        });

      default:
        return jsonResponse({ error: 'unknown action' }, 400);
    }
  } catch (err) {
    return jsonResponse({ error: 'internal_error', detail: String(err) }, 500);
  }
}

// --- Test API Connection (v2 - 不变) ---
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
        error: 'API1 未完整配置（需要 UPSTREAM_BASE_URL, REAL_API_KEY, UPSTREAM_MODEL_ID）'
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
        error: 'Embedding1 未完整配置'
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