/**
 * Hard Fact Music — backend auth logic.
 * Handles /api/register, /api/login, /api/me, /api/logout.
 * Everything else falls through to the static site (env.ASSETS).
 *
 * Storage: Cloudflare KV binding "USERS".
 *   key "user:<email>"    -> { email, name, passwordHash, salt, createdAt }
 *   key "session:<token>" -> "<email>"  (expires automatically after 30 days)
 *
 * Passwords are never stored in plain text — only a PBKDF2 hash + random salt.
 */

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const encoder = new TextEncoder();

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/register' && request.method === 'POST') {
      return handleRegister(request, env);
    }
    if (url.pathname === '/api/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }
    if (url.pathname === '/api/logout' && request.method === 'POST') {
      return handleLogout(request, env);
    }
    if (url.pathname === '/api/me' && request.method === 'GET') {
      return handleMe(request, env);
    }

    // Anything else — serve the static site as before.
    const assetResponse = await env.ASSETS.fetch(request);

    // Never let the HTML page itself get stuck in a stale cache (browser or edge) —
    // this is what caused the phone to keep showing an old, already-fixed build.
    // Heavier files (audio/video/images) keep their normal caching untouched.
    if (url.pathname === '/' || url.pathname.endsWith('.html')) {
      const headers = new Headers(assetResponse.headers);
      headers.set('Cache-Control', 'no-cache, must-revalidate');
      return new Response(assetResponse.body, {
        status: assetResponse.status,
        statusText: assetResponse.statusText,
        headers,
      });
    }

    return assetResponse;
  },
};

async function handleRegister(request, env) {
  try {
    const body = await request.json();
    const email = normalizeEmail(body.email);
    const password = body.password || '';
    const name = (body.name || '').trim().slice(0, 80);

    if (!email || !isValidEmail(email)) {
      return json({ error: 'Некоректний email.' }, 400);
    }
    if (password.length < 6) {
      return json({ error: 'Пароль мінімум 6 символів.' }, 400);
    }

    const key = 'user:' + email;
    const existing = await env.USERS.get(key);
    if (existing) {
      return json({ error: 'Цей email вже зареєстрований.' }, 409);
    }

    const salt = randomToken(16);
    const passwordHash = await hashPassword(password, salt);
    const user = { email, name, passwordHash, salt, createdAt: Date.now() };
    await env.USERS.put(key, JSON.stringify(user));

    const token = await createSession(env, email);
    return withSessionCookie(json({ ok: true, email, name }), token);
  } catch (e) {
    return json({ error: 'Помилка сервера. Спробуйте ще раз.' }, 500);
  }
}

async function handleLogin(request, env) {
  try {
    const body = await request.json();
    const email = normalizeEmail(body.email);
    const password = body.password || '';

    const raw = await env.USERS.get('user:' + email);
    if (!raw) {
      return json({ error: 'Невірний email або пароль.' }, 401);
    }
    const user = JSON.parse(raw);
    const hash = await hashPassword(password, user.salt);
    if (hash !== user.passwordHash) {
      return json({ error: 'Невірний email або пароль.' }, 401);
    }

    const token = await createSession(env, user.email);
    return withSessionCookie(json({ ok: true, email: user.email, name: user.name }), token);
  } catch (e) {
    return json({ error: 'Помилка сервера. Спробуйте ще раз.' }, 500);
  }
}

async function handleMe(request, env) {
  const token = getCookie(request, 'session');
  if (!token) return json({ authenticated: false });

  const email = await env.USERS.get('session:' + token);
  if (!email) return json({ authenticated: false });

  const raw = await env.USERS.get('user:' + email);
  if (!raw) return json({ authenticated: false });

  const user = JSON.parse(raw);
  return json({ authenticated: true, email: user.email, name: user.name });
}

async function handleLogout(request, env) {
  const token = getCookie(request, 'session');
  if (token) {
    await env.USERS.delete('session:' + token);
  }
  const res = json({ ok: true });
  res.headers.append(
    'Set-Cookie',
    'session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0'
  );
  return res;
}

/* ---------- helpers ---------- */

async function createSession(env, email) {
  const token = randomToken(32);
  await env.USERS.put('session:' + token, email, { expirationTtl: SESSION_TTL_SECONDS });
  return token;
}

function withSessionCookie(response, token) {
  response.headers.append(
    'Set-Cookie',
    `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL_SECONDS}`
  );
  return response;
}

async function hashPassword(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: encoder.encode(salt), iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return bufferToBase64(bits);
}

function randomToken(byteLength) {
  const arr = new Uint8Array(byteLength);
  crypto.getRandomValues(arr);
  return bufferToBase64(arr.buffer).replace(/[+/=]/g, '');
}

function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function normalizeEmail(email) {
  return (email || '').toString().trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[1]) : null;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
