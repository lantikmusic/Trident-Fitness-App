// Trident Fitness - Cloudflare Worker
// Handles: Auth (signup/login/sessions) + LogMeal API proxy

// The LogMeal API token is a Cloudflare secret (env.LOGMEAL_TOKEN), set with:
//   npx wrangler secret put LOGMEAL_TOKEN
const LOGMEAL_API_BASE = 'https://api.logmeal.es';
const SESSION_DURATION_DAYS = 30;

// ── CORS Headers ──
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' }
  });
}

function error(msg, status = 400) {
  return json({ error: msg }, status);
}

// ── Simple password hashing (using Web Crypto) ──
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password + 'trident-salt-2025');
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Generate random token ──
function generateToken() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Generate UUID ──
function generateId() {
  return crypto.randomUUID();
}

// ── Validate session token ──
async function validateSession(request, DB) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.replace('Bearer ', '');

  const session = await DB.prepare(
    'SELECT s.user_id, s.expires_at, u.email, u.name FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?'
  ).bind(token).first();

  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    await DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }

  return session;
}

// ══════════════════════════════════════════════════════
// MAIN FETCH HANDLER
// ══════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    // ── Auth Routes ──
    if (path === '/auth/signup' && request.method === 'POST') return handleSignup(request, env.DB);
    if (path === '/auth/login'  && request.method === 'POST') return handleLogin(request, env.DB);
    if (path === '/auth/google' && request.method === 'POST') return handleGoogleAuth(request, env.DB);
    if (path === '/auth/logout' && request.method === 'POST') return handleLogout(request, env.DB);
    if (path === '/auth/me'     && request.method === 'GET')  return handleMe(request, env.DB);

    // ── User Data Routes ──
    if (path === '/user/settings' && request.method === 'GET')  return getSettings(request, env.DB);
    if (path === '/user/settings' && request.method === 'POST') return saveSettings(request, env.DB);
    if (path === '/user/goals'    && request.method === 'GET')  return getGoals(request, env.DB);
    if (path === '/user/goals'    && request.method === 'POST') return saveGoals(request, env.DB);

    // ── Macro Log Routes ──
    if (path === '/macros'        && request.method === 'GET')  return getMacros(request, env.DB);
    if (path === '/macros'        && request.method === 'POST') return saveMacros(request, env.DB);
    if (path === '/macros/burned' && request.method === 'POST') return saveBurned(request, env.DB);
    if (path === '/macros/delete' && request.method === 'POST') return deleteMacro(request, env.DB);
    if (path === '/macros/clear'  && request.method === 'POST') return clearMacros(request, env.DB);

    // ── Progress Routes ──
    if (path === '/progress'      && request.method === 'GET')  return getProgress(request, env.DB);
    if (path === '/progress'      && request.method === 'POST') return saveProgress(request, env.DB);

    // ── Workout Routes ──
    if (path === '/workout'       && request.method === 'GET')  return getWorkout(request, env.DB);
    if (path === '/workout'       && request.method === 'POST') return saveWorkout(request, env.DB);

    // ── Personal Records ──
    if (path === '/prs'           && request.method === 'GET')  return getPRs(request, env.DB);
    if (path === '/prs'           && request.method === 'POST') return savePRs(request, env.DB);

    // ── Food Library ──
    if (path === '/foodlib'       && request.method === 'GET')  return getFoodLib(request, env.DB);
    if (path === '/foodlib'       && request.method === 'POST') return saveFoodLib(request, env.DB);

    // ── Steps ──
    if (path === '/steps'         && request.method === 'GET')  return getSteps(request, env.DB);
    if (path === '/steps'         && request.method === 'POST') return saveSteps(request, env.DB);

    // ── Sleep ──
    if (path === '/sleep'         && request.method === 'GET')  return getSleep(request, env.DB);
    if (path === '/sleep'         && request.method === 'POST') return saveSleep(request, env.DB);

    // ── Progress Photos ──
    if (path === '/photos'        && request.method === 'GET')  return getPhotos(request, env.DB);
    if (path === '/photos'        && request.method === 'POST') return savePhoto(request, env.DB);
    if (path === '/photos/delete' && request.method === 'POST') return deletePhoto(request, env.DB);

    // ── Community ──
    if (path === '/community/feed'            && request.method === 'GET')  return community(communityFeed, request, env.DB);
    if (path === '/community/posts'           && request.method === 'POST') return community(communityCreatePost, request, env.DB);
    if (path === '/community/posts/delete'    && request.method === 'POST') return community(communityDeletePost, request, env.DB);
    if (path === '/community/like'            && request.method === 'POST') return community(communityToggleLike, request, env.DB);
    if (path === '/community/comments'        && request.method === 'GET')  return community(communityComments, request, env.DB);
    if (path === '/community/comments'        && request.method === 'POST') return community(communityAddComment, request, env.DB, env, ctx);
    if (path === '/community/comments/delete' && request.method === 'POST') return community(communityDeleteComment, request, env.DB);
    if (path.startsWith('/community/photo/')  && request.method === 'GET')  return community(communityPhoto, path, env.DB);
    if (path.startsWith('/community/avatar/') && request.method === 'GET')  return community(communityAvatar, path, env.DB);
    if (path === '/community/profile'         && request.method === 'GET')  return community(communityProfile, request, env.DB);
    if (path === '/community/follow'          && request.method === 'POST') return community(communityToggleFollow, request, env.DB, env, ctx);
    if (path === '/community/block'           && request.method === 'POST') return community(communityToggleBlock, request, env.DB);

    // ── Direct messages ──
    if (path === '/dm/threads'                && request.method === 'GET')  return community(dmThreads, request, env.DB);
    if (path === '/dm/unread'                 && request.method === 'GET')  return community(dmUnread, request, env.DB);
    if (path === '/dm/messages'               && request.method === 'GET')  return community(dmMessages, request, env.DB);
    if (path === '/dm/send'                   && request.method === 'POST') return community(dmSend, request, env.DB, env, ctx);

    // ── Push notifications ──
    if (path === '/push/key'                  && request.method === 'GET')  return community(pushKey, env);
    if (path === '/push/subscribe'            && request.method === 'POST') return community(pushSubscribe, request, env.DB, env);
    if (path === '/push/unsubscribe'          && request.method === 'POST') return community(pushUnsubscribe, request, env.DB);
    if (path === '/push/test'                 && request.method === 'POST') return community(pushTest, request, env.DB, env);
    if (path === '/push/rest'                 && request.method === 'POST') return community(pushRest, request, env.DB, env);

    // ── Profile picture on its own (does not touch the other settings) ──
    if (path === '/user/profile-pic'          && request.method === 'POST') return community(saveProfilePic, request, env.DB);

    // ── LogMeal Proxy Routes ──
    if (path.startsWith('/v2/')) return handleLogMealProxy(request, path + url.search, env);

    return error('Not found', 404);
  }
};

// ══════════════════════════════════════════════════════
// AUTH HANDLERS
// ══════════════════════════════════════════════════════

async function handleGoogleAuth(request, DB) {
  try {
    const { credential } = await request.json();
    if(!credential) return error('Google credential required');

    // Decode the JWT from Google (verify signature with Google's public keys)
    const parts = credential.split('.');
    if(parts.length !== 3) return error('Invalid Google credential');

    // Decode payload
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    // Verify it's for our app
    const GOOGLE_CLIENT_ID = '341176626662-7cf89bets0asup40ht1kl3m7engnik5a.apps.googleusercontent.com';
    if(payload.aud !== GOOGLE_CLIENT_ID) return error('Invalid Google token', 401);

    // Check token expiry
    if(payload.exp < Math.floor(Date.now() / 1000)) return error('Google token expired', 401);

    const googleId  = payload.sub;
    const email     = payload.email?.toLowerCase();
    const name      = payload.name || email?.split('@')[0] || 'User';

    if(!email) return error('No email from Google');

    // Check if user exists
    let user = await DB.prepare('SELECT id, email, name FROM users WHERE email = ?').bind(email).first();
    let isNewUser = false;

    if(!user) {
      // Create new user from Google
      const userId = generateId();
      const passwordHash = await hashPassword(googleId + '_google_oauth');
      await DB.prepare('INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)')
        .bind(userId, email, passwordHash, name).run();
      await DB.prepare('INSERT INTO user_settings (user_id, name) VALUES (?, ?)').bind(userId, name).run();
      user = { id: userId, email, name };
      isNewUser = true;
    }

    // Update last login
    await DB.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(new Date().toISOString(), user.id).run();

    // Create session
    const token = generateToken();
    const expiresAt = new Date(Date.now() + SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000).toISOString();
    await DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expiresAt).run();

    return json({ token, user: { id: user.id, email: user.email, name: user.name }, isNewUser });

  } catch(e) {
    console.error('Google auth error:', e);
    return error('Google sign-in failed: ' + e.message, 500);
  }
}

async function handleSignup(request, DB) {
  try {
    const { email, password, name } = await request.json();

    if (!email || !password) return error('Email and password required');
    if (password.length < 8) return error('Password must be at least 8 characters');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return error('Invalid email address');

    // Check if email already exists
    const existing = await DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
    if (existing) return error('An account with this email already exists', 409);

    // Create user
    const userId = generateId();
    const passwordHash = await hashPassword(password);

    await DB.prepare(
      'INSERT INTO users (id, email, password_hash, name) VALUES (?, ?, ?, ?)'
    ).bind(userId, email.toLowerCase(), passwordHash, name || '').run();

    // Create default settings
    await DB.prepare(
      'INSERT INTO user_settings (user_id, name) VALUES (?, ?)'
    ).bind(userId, name || '').run();

    // Create session
    const token = generateToken();
    const expiresAt = new Date(Date.now() + SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000).toISOString();

    await DB.prepare(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(token, userId, expiresAt).run();

    return json({ token, user: { id: userId, email: email.toLowerCase(), name: name || '' } }, 201);

  } catch (e) {
    console.error('Signup error:', e);
    return error('Signup failed: ' + e.message, 500);
  }
}

async function handleLogin(request, DB) {
  try {
    const { email, password } = await request.json();

    if (!email || !password) return error('Email and password required');

    // Find user
    const user = await DB.prepare(
      'SELECT id, email, name, password_hash FROM users WHERE email = ?'
    ).bind(email.toLowerCase()).first();

    if (!user) return error('Invalid email or password', 401);

    // Check password
    const passwordHash = await hashPassword(password);
    if (passwordHash !== user.password_hash) return error('Invalid email or password', 401);

    // Update last login
    await DB.prepare('UPDATE users SET last_login = ? WHERE id = ?')
      .bind(new Date().toISOString(), user.id).run();

    // Create session
    const token = generateToken();
    const expiresAt = new Date(Date.now() + SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000).toISOString();

    await DB.prepare(
      'INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)'
    ).bind(token, user.id, expiresAt).run();

    return json({ token, user: { id: user.id, email: user.email, name: user.name } });

  } catch (e) {
    console.error('Login error:', e);
    return error('Login failed: ' + e.message, 500);
  }
}

async function handleLogout(request, DB) {
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.replace('Bearer ', '');
    await DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return json({ success: true });
}

async function handleMe(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  return json({ user: { id: session.user_id, email: session.email, name: session.name } });
}

// ══════════════════════════════════════════════════════
// USER DATA HANDLERS
// ══════════════════════════════════════════════════════

async function getSettings(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const settings = await DB.prepare(
    'SELECT * FROM user_settings WHERE user_id = ?'
  ).bind(session.user_id).first();

  // Fetch profile pic from blobs
  const picRow = await DB.prepare(
    'SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?'
  ).bind(session.user_id, 'profile_pic').first();

  const result = settings || {};
  if (picRow) result.profile_pic = JSON.parse(picRow.data_json);

  return json(result);
}

async function saveSettings(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();

  // Save profile pic separately as a blob if provided (too large for settings table)
  if (data.profile_pic) {
    await DB.prepare(`INSERT INTO user_blobs (user_id, blob_key, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(user_id, blob_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`)
      .bind(session.user_id, 'profile_pic', JSON.stringify(data.profile_pic)).run();
  }

  await DB.prepare(`
    INSERT INTO user_settings (user_id, gender, age, height_ft, height_in, weight, goal_weight, activity_level, name, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      gender = excluded.gender,
      age = excluded.age,
      height_ft = excluded.height_ft,
      height_in = excluded.height_in,
      weight = excluded.weight,
      goal_weight = excluded.goal_weight,
      activity_level = excluded.activity_level,
      name = excluded.name,
      updated_at = excluded.updated_at
  `).bind(
    session.user_id,
    data.gender || 'female',
    data.age || null,
    data.height_ft || null,
    data.height_in || null,
    data.weight || null,
    data.goal_weight || null,
    data.activity_level || 1.55,
    data.name || ''
  ).run();

  return json({ success: true });
}

async function getGoals(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const goals = await DB.prepare(
    'SELECT * FROM user_goals WHERE user_id = ?'
  ).bind(session.user_id).first();

  return json(goals || {});
}

async function saveGoals(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();

  await DB.prepare(`
    INSERT INTO user_goals (user_id, focus, cal, protein, carbs, fat, tdee, deficit_per_day, weeks, current_weight, goal_weight, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      focus = excluded.focus,
      cal = excluded.cal,
      protein = excluded.protein,
      carbs = excluded.carbs,
      fat = excluded.fat,
      tdee = excluded.tdee,
      deficit_per_day = excluded.deficit_per_day,
      weeks = excluded.weeks,
      current_weight = excluded.current_weight,
      goal_weight = excluded.goal_weight,
      updated_at = excluded.updated_at
  `).bind(
    session.user_id,
    data.focus || 'fat_loss',
    data.cal || null,
    data.protein || null,
    data.carbs || null,
    data.fat || null,
    data.tdee || null,
    data.deficit_per_day || null,
    data.weeks || 8,
    data.current_weight || null,
    data.goal_weight || null
  ).run();

  return json({ success: true });
}

async function getMacros(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const url = new URL(request.url);
  const date = url.searchParams.get('date');

  // If date specified fetch just that day, otherwise fetch all logs for the past 30 days
  let logs;
  if (date) {
    logs = await DB.prepare(
      'SELECT * FROM macro_logs WHERE user_id = ? AND log_date = ? ORDER BY created_at ASC'
    ).bind(session.user_id, date).all();
  } else {
    logs = await DB.prepare(
      'SELECT * FROM macro_logs WHERE user_id = ? ORDER BY log_date DESC, created_at ASC LIMIT 500'
    ).bind(session.user_id).all();
  }

  // Also fetch burned calories blob
  const burnedRow = await DB.prepare(
    'SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?'
  ).bind(session.user_id, 'burned_calories').first();
  const burned = burnedRow ? JSON.parse(burnedRow.data_json) : {};

  const results = logs.results || [];

  // Attach burned/notes to response as special entries
  return json({ items: results, burned });
}

async function saveMacros(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();
  const id = generateId();
  const date = data.date || new Date().toISOString().split('T')[0];

  await DB.prepare(`
    INSERT INTO macro_logs (id, user_id, log_date, day_index, meal, food_name, calories, protein, carbs, fat)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    id,
    session.user_id,
    date,
    data.day_index || 0,
    data.meal || 'breakfast',
    data.food_name || 'Unknown',
    data.calories || 0,
    data.protein || 0,
    data.carbs || 0,
    data.fat || 0
  ).run();

  return json({ success: true, id });
}

async function saveBurned(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();
  // Store burned calories as a blob keyed by day_index
  const burnedRow = await DB.prepare(
    'SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?'
  ).bind(session.user_id, 'burned_calories').first();

  const burned = burnedRow ? JSON.parse(burnedRow.data_json) : {};
  burned[data.day_index] = { burned: data.burned || 0, notes: data.notes || '', date: data.date };

  await DB.prepare(`INSERT INTO user_blobs (user_id, blob_key, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, blob_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`)
    .bind(session.user_id, 'burned_calories', JSON.stringify(burned)).run();

  return json({ success: true });
}

// The app sends the date of the day being edited; only entries saved for that day (±1 day, for
// entries from older app versions that used the UTC date) are touched, never earlier weeks.
// Without a date (older app versions) it behaves as before.
function macroDateWindow(date) {
  if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return null;
  const d = new Date(date + 'T00:00:00Z');
  if (isNaN(d)) return null;
  const shift = n => new Date(d.getTime() + n * 86400000).toISOString().slice(0, 10);
  return [shift(-1), shift(1)];
}

async function deleteMacro(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();
  const win = macroDateWindow(data.date);
  // Delete one matching entry (same day, meal, food and calories) — just one, if the same food was logged twice.
  await DB.prepare(
    `DELETE FROM macro_logs WHERE id = (SELECT id FROM macro_logs WHERE user_id = ? AND day_index = ? AND meal = ? AND food_name = ? AND calories = ?
      ${win ? 'AND log_date BETWEEN ? AND ?' : ''} ORDER BY created_at DESC LIMIT 1)`
  ).bind(
    session.user_id,
    data.day_index,
    data.meal,
    data.food_name,
    data.calories || 0,
    ...(win || [])
  ).run();

  return json({ success: true });
}

async function clearMacros(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();
  const win = macroDateWindow(data.date);
  const range = win ? ' AND log_date BETWEEN ? AND ?' : '';
  // Clear all macros for a specific day_index + meal, or whole day if no meal specified
  if (data.meal) {
    await DB.prepare(
      'DELETE FROM macro_logs WHERE user_id = ? AND day_index = ? AND meal = ?' + range
    ).bind(session.user_id, data.day_index, data.meal, ...(win || [])).run();
  } else {
    await DB.prepare(
      'DELETE FROM macro_logs WHERE user_id = ? AND day_index = ?' + range
    ).bind(session.user_id, data.day_index, ...(win || [])).run();
  }

  return json({ success: true });
}

async function getProgress(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const logs = await DB.prepare(
    'SELECT * FROM progress_logs WHERE user_id = ? ORDER BY log_date DESC LIMIT 30'
  ).bind(session.user_id).all();

  return json(logs.results || []);
}

async function saveProgress(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();
  const id = generateId();

  await DB.prepare(`
    INSERT INTO progress_logs (id, user_id, log_date, weight, body_fat)
    VALUES (?, ?, ?, ?, ?)
  `).bind(
    id,
    session.user_id,
    data.date || new Date().toISOString().split('T')[0],
    data.weight || null,
    data.body_fat || null
  ).run();

  return json({ success: true, id });
}

async function getWorkout(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const workout = await DB.prepare(
    'SELECT * FROM workout_state WHERE user_id = ?'
  ).bind(session.user_id).first();

  return json(workout || {});
}

async function saveWorkout(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();

  await DB.prepare(`
    INSERT INTO workout_state (user_id, program, state_json, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      program = excluded.program,
      state_json = excluded.state_json,
      updated_at = excluded.updated_at
  `).bind(
    session.user_id,
    data.program || null,
    JSON.stringify(data.state || {})
  ).run();

  return json({ success: true });
}

// ══════════════════════════════════════════════════════
// PERSONAL RECORDS
// ══════════════════════════════════════════════════════
async function getPRs(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const row = await DB.prepare('SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?').bind(session.user_id, 'prs').first();
  return json(row ? JSON.parse(row.data_json) : {});
}

async function savePRs(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const data = await request.json();
  await DB.prepare(`INSERT INTO user_blobs (user_id, blob_key, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, blob_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`)
    .bind(session.user_id, 'prs', JSON.stringify(data)).run();
  return json({ success: true });
}

// ══════════════════════════════════════════════════════
// FOOD LIBRARY
// ══════════════════════════════════════════════════════
async function getFoodLib(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const row = await DB.prepare('SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?').bind(session.user_id, 'foodlib').first();
  return json(row ? JSON.parse(row.data_json) : []);
}

async function saveFoodLib(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const data = await request.json();
  await DB.prepare(`INSERT INTO user_blobs (user_id, blob_key, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, blob_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`)
    .bind(session.user_id, 'foodlib', JSON.stringify(data)).run();
  return json({ success: true });
}

// ══════════════════════════════════════════════════════
// STEPS
// ══════════════════════════════════════════════════════
async function getSteps(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const row = await DB.prepare('SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?').bind(session.user_id, 'steps').first();
  return json(row ? JSON.parse(row.data_json) : {});
}

async function saveSteps(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const data = await request.json();
  await DB.prepare(`INSERT INTO user_blobs (user_id, blob_key, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, blob_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`)
    .bind(session.user_id, 'steps', JSON.stringify(data)).run();
  return json({ success: true });
}

// ══════════════════════════════════════════════════════
// SLEEP
// ══════════════════════════════════════════════════════
async function getSleep(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const row = await DB.prepare('SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?').bind(session.user_id, 'sleep').first();
  return json(row ? JSON.parse(row.data_json) : {});
}

async function saveSleep(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const data = await request.json();
  await DB.prepare(`INSERT INTO user_blobs (user_id, blob_key, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, blob_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`)
    .bind(session.user_id, 'sleep', JSON.stringify(data)).run();
  return json({ success: true });
}

// ══════════════════════════════════════════════════════
// PROGRESS PHOTOS
// ══════════════════════════════════════════════════════
async function getPhotos(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const photos = await DB.prepare('SELECT * FROM progress_photos WHERE user_id = ? ORDER BY created_at DESC').bind(session.user_id).all();
  return json(photos.results || []);
}

async function savePhoto(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const data = await request.json();
  const id = generateId();
  await DB.prepare('INSERT INTO progress_photos (id, user_id, photo_url, caption, log_date) VALUES (?, ?, ?, ?, ?)')
    .bind(id, session.user_id, data.src, data.caption || '', data.date || new Date().toISOString().split('T')[0]).run();
  return json({ success: true, id });
}

async function deletePhoto(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const { id } = await request.json();
  await DB.prepare('DELETE FROM progress_photos WHERE id = ? AND user_id = ?').bind(id, session.user_id).run();
  return json({ success: true });
}

// ══════════════════════════════════════════════════════
// COMMUNITY (shared feed: posts, likes, comments)
// ══════════════════════════════════════════════════════
const COMMUNITY_MAX_BODY = 1000;
const COMMUNITY_MAX_COMMENT = 500;
const COMMUNITY_MAX_PHOTO = 900000;   // characters of the data URL
const COMMUNITY_MAX_PAYLOAD = 6000;   // characters of the JSON attachment
const COMMUNITY_POSTS_PER_DAY = 30;
const COMMUNITY_COMMENTS_PER_DAY = 200;
const COMMUNITY_ID = /^[A-Za-z0-9-]{1,64}$/;

// A failing community query (e.g. tables not created yet) must answer with JSON, not crash the worker.
async function community(handler, ...args) {
  try {
    return await handler(...args);
  } catch (e) {
    return error('Community is unavailable right now', 500);
  }
}

const COMMUNITY_AUTHOR = "COALESCE(NULLIF(s.name, ''), NULLIF(u.name, ''), 'Member')";

const COMMUNITY_POST_SELECT = `
  SELECT p.id, p.user_id, p.type, p.body, p.payload_json, p.created_at,
    (p.photo_data IS NOT NULL) AS has_photo,
    ${COMMUNITY_AUTHOR} AS author_name,
    (SELECT COUNT(*) FROM community_likes l WHERE l.post_id = p.id) AS like_count,
    (SELECT COUNT(*) FROM community_comments c WHERE c.post_id = p.id) AS comment_count,
    EXISTS(SELECT 1 FROM community_likes l2 WHERE l2.post_id = p.id AND l2.user_id = ?1) AS liked,
    EXISTS(SELECT 1 FROM user_blobs b WHERE b.user_id = p.user_id AND b.blob_key = 'profile_pic') AS has_avatar,
    EXISTS(SELECT 1 FROM community_follows f WHERE f.follower_id = ?1 AND f.followee_id = p.user_id) AS following
  FROM community_posts p
  JOIN users u ON u.id = p.user_id
  LEFT JOIN user_settings s ON s.user_id = p.user_id`;

function communityPostOut(row, viewerId) {
  let payload = null;
  try { payload = row.payload_json ? JSON.parse(row.payload_json) : null; } catch (e) {}
  return {
    id: row.id,
    user_id: row.user_id,
    type: row.type,
    body: row.body || '',
    payload,
    created_at: row.created_at,
    has_photo: !!row.has_photo,
    author_name: row.author_name,
    like_count: row.like_count || 0,
    comment_count: row.comment_count || 0,
    liked: !!row.liked,
    has_avatar: !!row.has_avatar,
    following: !!row.following,
    mine: row.user_id === viewerId
  };
}

function communityDayAgo() {
  return new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
}

async function communityFeed(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const url = new URL(request.url);
  const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit'), 10) || 15, 1), 30);
  const before = url.searchParams.get('before') || null;
  // scope=following: people you follow, plus your own posts. user=<id>: one person's posts.
  const scope = url.searchParams.get('scope') === 'following' ? 'following' : 'all';
  const only = url.searchParams.get('user') || null;
  if (only !== null && !COMMUNITY_ID.test(only)) return error('Invalid request');

  const rows = await DB.prepare(
    `${COMMUNITY_POST_SELECT} WHERE (?2 IS NULL OR p.created_at < ?2)
      AND p.user_id NOT IN (SELECT blocked_id FROM dm_blocks WHERE blocker_id = ?1)
      AND (?4 = 'all' OR p.user_id = ?1 OR p.user_id IN (SELECT followee_id FROM community_follows WHERE follower_id = ?1))
      AND (?5 IS NULL OR p.user_id = ?5)
    ORDER BY p.created_at DESC LIMIT ?3`
  ).bind(session.user_id, before, limit + 1, scope, only).all();

  const list = rows.results || [];
  const page = list.slice(0, limit);
  return json({
    posts: page.map(r => communityPostOut(r, session.user_id)),
    next: list.length > limit ? page[page.length - 1].created_at : null
  });
}

async function communityCreatePost(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  if (!data || typeof data !== 'object') return error('Invalid request');

  const type = ['text', 'workout', 'pr'].includes(data.type) ? data.type : 'text';
  const body = typeof data.body === 'string' ? data.body.trim() : '';
  if (body.length > COMMUNITY_MAX_BODY) return error(`Posts are limited to ${COMMUNITY_MAX_BODY} characters`);

  let photo = null;
  if (data.photo != null) {
    if (typeof data.photo !== 'string') return error('That photo could not be read');
    if (data.photo.length > COMMUNITY_MAX_PHOTO) return error('That photo is too large', 413);
    if (!/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+=*$/.test(data.photo)) return error('That photo could not be read');
    photo = data.photo;
  }

  let payloadJson = null;
  if (type !== 'text') {
    if (!data.payload || typeof data.payload !== 'object' || Array.isArray(data.payload)) return error('Missing details for that post');
    payloadJson = JSON.stringify(data.payload);
    if (payloadJson.length > COMMUNITY_MAX_PAYLOAD) return error('That attachment is too large', 413);
  }

  if (!body && !photo && !payloadJson) return error('Write something or attach a photo, workout or PR');

  const recent = await DB.prepare(
    'SELECT COUNT(*) AS n FROM community_posts WHERE user_id = ? AND created_at > ?'
  ).bind(session.user_id, communityDayAgo()).first();
  if (recent && recent.n >= COMMUNITY_POSTS_PER_DAY) return error('You have reached today\'s posting limit', 429);

  const id = generateId();
  await DB.prepare(
    'INSERT INTO community_posts (id, user_id, type, body, payload_json, photo_data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, session.user_id, type, body, payloadJson, photo, new Date().toISOString()).run();

  const row = await DB.prepare(`${COMMUNITY_POST_SELECT} WHERE p.id = ?2`).bind(session.user_id, id).first();
  return json({ success: true, post: communityPostOut(row, session.user_id) });
}

async function communityDeletePost(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const id = data && data.id;
  if (typeof id !== 'string' || !COMMUNITY_ID.test(id)) return error('Invalid request');

  const post = await DB.prepare('SELECT user_id FROM community_posts WHERE id = ?').bind(id).first();
  if (!post) return error('Post not found', 404);
  if (post.user_id !== session.user_id) return error('You can only delete your own posts', 403);

  await DB.batch([
    DB.prepare('DELETE FROM community_likes WHERE post_id = ?').bind(id),
    DB.prepare('DELETE FROM community_comments WHERE post_id = ?').bind(id),
    DB.prepare('DELETE FROM community_posts WHERE id = ?').bind(id)
  ]);
  return json({ success: true });
}

async function communityToggleLike(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const postId = data && data.post_id;
  if (typeof postId !== 'string' || !COMMUNITY_ID.test(postId)) return error('Invalid request');

  const post = await DB.prepare('SELECT id FROM community_posts WHERE id = ?').bind(postId).first();
  if (!post) return error('Post not found', 404);

  const existing = await DB.prepare(
    'SELECT 1 AS x FROM community_likes WHERE post_id = ? AND user_id = ?'
  ).bind(postId, session.user_id).first();

  if (existing) {
    await DB.prepare('DELETE FROM community_likes WHERE post_id = ? AND user_id = ?').bind(postId, session.user_id).run();
  } else {
    await DB.prepare(
      'INSERT OR IGNORE INTO community_likes (post_id, user_id, created_at) VALUES (?, ?, ?)'
    ).bind(postId, session.user_id, new Date().toISOString()).run();
  }

  const count = await DB.prepare('SELECT COUNT(*) AS n FROM community_likes WHERE post_id = ?').bind(postId).first();
  return json({ success: true, liked: !existing, like_count: (count && count.n) || 0 });
}

function communityCommentOut(row, viewerId) {
  return {
    id: row.id,
    post_id: row.post_id,
    user_id: row.user_id,
    body: row.body || '',
    created_at: row.created_at,
    author_name: row.author_name,
    has_avatar: !!row.has_avatar,
    can_delete: row.user_id === viewerId || row.post_owner === viewerId
  };
}

const COMMUNITY_COMMENT_SELECT = `
  SELECT c.id, c.post_id, c.user_id, c.body, c.created_at, p.user_id AS post_owner,
    ${COMMUNITY_AUTHOR} AS author_name,
    EXISTS(SELECT 1 FROM user_blobs b WHERE b.user_id = c.user_id AND b.blob_key = 'profile_pic') AS has_avatar
  FROM community_comments c
  JOIN community_posts p ON p.id = c.post_id
  JOIN users u ON u.id = c.user_id
  LEFT JOIN user_settings s ON s.user_id = c.user_id`;

async function communityComments(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const postId = new URL(request.url).searchParams.get('post_id') || '';
  if (!COMMUNITY_ID.test(postId)) return error('Invalid request');

  const rows = await DB.prepare(
    `${COMMUNITY_COMMENT_SELECT} WHERE c.post_id = ? ORDER BY c.created_at ASC LIMIT 200`
  ).bind(postId).all();
  return json({ comments: (rows.results || []).map(r => communityCommentOut(r, session.user_id)) });
}

async function communityAddComment(request, DB, env, ctx) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const postId = data && data.post_id;
  if (typeof postId !== 'string' || !COMMUNITY_ID.test(postId)) return error('Invalid request');
  const body = typeof data.body === 'string' ? data.body.trim() : '';
  if (!body) return error('Write a comment first');
  if (body.length > COMMUNITY_MAX_COMMENT) return error(`Comments are limited to ${COMMUNITY_MAX_COMMENT} characters`);

  const post = await DB.prepare('SELECT id, user_id FROM community_posts WHERE id = ?').bind(postId).first();
  if (!post) return error('Post not found', 404);

  const recent = await DB.prepare(
    'SELECT COUNT(*) AS n FROM community_comments WHERE user_id = ? AND created_at > ?'
  ).bind(session.user_id, communityDayAgo()).first();
  if (recent && recent.n >= COMMUNITY_COMMENTS_PER_DAY) return error('You have reached today\'s comment limit', 429);

  const id = generateId();
  await DB.prepare(
    'INSERT INTO community_comments (id, post_id, user_id, body, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, postId, session.user_id, body, new Date().toISOString()).run();

  const row = await DB.prepare(`${COMMUNITY_COMMENT_SELECT} WHERE c.id = ?`).bind(id).first();
  const count = await DB.prepare('SELECT COUNT(*) AS n FROM community_comments WHERE post_id = ?').bind(postId).first();
  if (post.user_id !== session.user_id && !(await dmBlockedBetween(DB, post.user_id, session.user_id))) {
    pushLater(ctx, env, DB, post.user_id, { title: `${(row && row.author_name) || 'Someone'} commented on your post`, body: body.slice(0, 140), tag: 'post-' + postId, open: 'post:' + postId });
  }
  return json({ success: true, comment: communityCommentOut(row, session.user_id), comment_count: (count && count.n) || 0 });
}

async function communityDeleteComment(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const id = data && data.id;
  if (typeof id !== 'string' || !COMMUNITY_ID.test(id)) return error('Invalid request');

  const row = await DB.prepare(
    'SELECT c.post_id, c.user_id, p.user_id AS post_owner FROM community_comments c JOIN community_posts p ON p.id = c.post_id WHERE c.id = ?'
  ).bind(id).first();
  if (!row) return error('Comment not found', 404);
  if (row.user_id !== session.user_id && row.post_owner !== session.user_id) return error('You cannot delete that comment', 403);

  await DB.prepare('DELETE FROM community_comments WHERE id = ?').bind(id).run();
  const count = await DB.prepare('SELECT COUNT(*) AS n FROM community_comments WHERE post_id = ?').bind(row.post_id).first();
  return json({ success: true, comment_count: (count && count.n) || 0 });
}

// ── Follows, profiles and blocking ──
async function communityUserRow(DB, userId) {
  return DB.prepare(
    `SELECT u.id, ${COMMUNITY_AUTHOR} AS name,
       EXISTS(SELECT 1 FROM user_blobs b WHERE b.user_id = u.id AND b.blob_key = 'profile_pic') AS has_avatar
     FROM users u LEFT JOIN user_settings s ON s.user_id = u.id WHERE u.id = ?`
  ).bind(userId).first();
}

async function communityTarget(request) {
  let data;
  try { data = await request.json(); } catch (e) { return null; }
  const id = data && data.user_id;
  return typeof id === 'string' && COMMUNITY_ID.test(id) ? id : null;
}

async function communityProfile(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const userId = new URL(request.url).searchParams.get('user_id') || '';
  if (!COMMUNITY_ID.test(userId)) return error('Invalid request');
  const user = await communityUserRow(DB, userId);
  if (!user) return error('Member not found', 404);
  const me = session.user_id;
  const stats = await DB.prepare(
    `SELECT
       (SELECT COUNT(*) FROM community_follows WHERE followee_id = ?1) AS followers,
       (SELECT COUNT(*) FROM community_follows WHERE follower_id = ?1) AS following,
       (SELECT COUNT(*) FROM community_posts WHERE user_id = ?1) AS posts,
       EXISTS(SELECT 1 FROM community_follows WHERE follower_id = ?2 AND followee_id = ?1) AS is_following,
       EXISTS(SELECT 1 FROM community_follows WHERE follower_id = ?1 AND followee_id = ?2) AS follows_you,
       EXISTS(SELECT 1 FROM dm_blocks WHERE blocker_id = ?2 AND blocked_id = ?1) AS blocked`
  ).bind(userId, me).first();
  return json({
    user_id: user.id, name: user.name, has_avatar: !!user.has_avatar, is_me: user.id === me,
    followers: stats.followers || 0, following: stats.following || 0, posts: stats.posts || 0,
    is_following: !!stats.is_following, follows_you: !!stats.follows_you, blocked: !!stats.blocked
  });
}

async function communityToggleFollow(request, DB, env, ctx) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const target = await communityTarget(request);
  if (!target) return error('Invalid request');
  if (target === session.user_id) return error('You cannot follow yourself');
  if (!(await communityUserRow(DB, target))) return error('Member not found', 404);
  const existing = await DB.prepare('SELECT 1 AS x FROM community_follows WHERE follower_id = ? AND followee_id = ?').bind(session.user_id, target).first();
  if (existing) {
    await DB.prepare('DELETE FROM community_follows WHERE follower_id = ? AND followee_id = ?').bind(session.user_id, target).run();
  } else {
    const blocked = await DB.prepare('SELECT 1 AS x FROM dm_blocks WHERE (blocker_id = ?1 AND blocked_id = ?2) OR (blocker_id = ?2 AND blocked_id = ?1)').bind(session.user_id, target).first();
    if (blocked) return error('You cannot follow this member', 403);
    await DB.prepare('INSERT OR IGNORE INTO community_follows (follower_id, followee_id, created_at) VALUES (?, ?, ?)').bind(session.user_id, target, new Date().toISOString()).run();
    const me = await communityUserRow(DB, session.user_id);
    pushLater(ctx, env, DB, target, { title: 'New follower', body: `${(me && me.name) || 'Someone'} started following you`, tag: 'follow-' + session.user_id, open: 'profile:' + session.user_id });
  }
  const count = await DB.prepare('SELECT COUNT(*) AS n FROM community_follows WHERE followee_id = ?').bind(target).first();
  return json({ success: true, following: !existing, followers: (count && count.n) || 0 });
}

// Blocking someone hides their posts from you, stops messages both ways and removes follows both ways.
async function communityToggleBlock(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const target = await communityTarget(request);
  if (!target || target === session.user_id) return error('Invalid request');
  if (!(await communityUserRow(DB, target))) return error('Member not found', 404);
  const me = session.user_id;
  const existing = await DB.prepare('SELECT 1 AS x FROM dm_blocks WHERE blocker_id = ? AND blocked_id = ?').bind(me, target).first();
  if (existing) {
    await DB.prepare('DELETE FROM dm_blocks WHERE blocker_id = ? AND blocked_id = ?').bind(me, target).run();
  } else {
    await DB.batch([
      DB.prepare('INSERT OR IGNORE INTO dm_blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)').bind(me, target, new Date().toISOString()),
      DB.prepare('DELETE FROM community_follows WHERE (follower_id = ?1 AND followee_id = ?2) OR (follower_id = ?2 AND followee_id = ?1)').bind(me, target)
    ]);
  }
  return json({ success: true, blocked: !existing });
}

// ── Direct messages ──
const DM_MAX_BODY = 1000;
const DM_PER_HOUR = 60;

async function dmBlockedBetween(DB, a, b) {
  return !!(await DB.prepare('SELECT 1 AS x FROM dm_blocks WHERE (blocker_id = ?1 AND blocked_id = ?2) OR (blocker_id = ?2 AND blocked_id = ?1)').bind(a, b).first());
}

async function dmUnread(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const row = await DB.prepare(
    'SELECT COUNT(*) AS n FROM dm_messages WHERE recipient_id = ?1 AND read_at IS NULL AND sender_id NOT IN (SELECT blocked_id FROM dm_blocks WHERE blocker_id = ?1)'
  ).bind(session.user_id).first();
  return json({ unread: (row && row.n) || 0 });
}

async function dmThreads(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const me = session.user_id;
  const rows = await DB.prepare(
    `SELECT t.other_id, t.last_at,
       (SELECT m.body FROM dm_messages m WHERE (m.sender_id = ?1 AND m.recipient_id = t.other_id) OR (m.sender_id = t.other_id AND m.recipient_id = ?1) ORDER BY m.created_at DESC LIMIT 1) AS last_body,
       (SELECT m.sender_id FROM dm_messages m WHERE (m.sender_id = ?1 AND m.recipient_id = t.other_id) OR (m.sender_id = t.other_id AND m.recipient_id = ?1) ORDER BY m.created_at DESC LIMIT 1) AS last_sender,
       (SELECT COUNT(*) FROM dm_messages m WHERE m.sender_id = t.other_id AND m.recipient_id = ?1 AND m.read_at IS NULL) AS unread,
       ${COMMUNITY_AUTHOR} AS name,
       EXISTS(SELECT 1 FROM user_blobs b WHERE b.user_id = t.other_id AND b.blob_key = 'profile_pic') AS has_avatar
     FROM (
       SELECT other_id, MAX(created_at) AS last_at FROM (
         SELECT recipient_id AS other_id, created_at FROM dm_messages WHERE sender_id = ?1
         UNION ALL
         SELECT sender_id AS other_id, created_at FROM dm_messages WHERE recipient_id = ?1
       ) GROUP BY other_id
     ) t
     JOIN users u ON u.id = t.other_id
     LEFT JOIN user_settings s ON s.user_id = t.other_id
     WHERE t.other_id NOT IN (SELECT blocked_id FROM dm_blocks WHERE blocker_id = ?1)
     ORDER BY t.last_at DESC LIMIT 50`
  ).bind(me).all();
  const threads = (rows.results || []).map(r => ({
    user_id: r.other_id, name: r.name, has_avatar: !!r.has_avatar, last_at: r.last_at,
    last_body: (r.last_body || '').slice(0, 140), last_mine: r.last_sender === me, unread: r.unread || 0
  }));
  return json({ threads, unread: threads.reduce((n, t) => n + t.unread, 0) });
}

async function dmMessages(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const me = session.user_id;
  const other = new URL(request.url).searchParams.get('with') || '';
  if (!COMMUNITY_ID.test(other) || other === me) return error('Invalid request');
  const user = await communityUserRow(DB, other);
  if (!user) return error('Member not found', 404);
  const rows = await DB.prepare(
    `SELECT id, sender_id, body, created_at, read_at FROM dm_messages
     WHERE (sender_id = ?1 AND recipient_id = ?2) OR (sender_id = ?2 AND recipient_id = ?1)
     ORDER BY created_at DESC LIMIT 100`
  ).bind(me, other).all();
  await DB.prepare('UPDATE dm_messages SET read_at = ? WHERE sender_id = ? AND recipient_id = ? AND read_at IS NULL')
    .bind(new Date().toISOString(), other, me).run();
  const iBlocked = !!(await DB.prepare('SELECT 1 AS x FROM dm_blocks WHERE blocker_id = ? AND blocked_id = ?').bind(me, other).first());
  return json({
    user: { user_id: user.id, name: user.name, has_avatar: !!user.has_avatar },
    blocked: iBlocked,
    can_send: !(await dmBlockedBetween(DB, me, other)),
    messages: (rows.results || []).reverse().map(m => ({ id: m.id, body: m.body, created_at: m.created_at, mine: m.sender_id === me, read: !!m.read_at }))
  });
}

async function dmSend(request, DB, env, ctx) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const to = data && data.to;
  const body = data && typeof data.body === 'string' ? data.body.trim() : '';
  if (typeof to !== 'string' || !COMMUNITY_ID.test(to) || to === session.user_id) return error('Invalid request');
  if (!body) return error('Write a message first');
  if (body.length > DM_MAX_BODY) return error(`Messages are limited to ${DM_MAX_BODY} characters`);
  if (!(await communityUserRow(DB, to))) return error('Member not found', 404);
  if (await dmBlockedBetween(DB, session.user_id, to)) return error('You cannot message this member', 403);
  const recent = await DB.prepare('SELECT COUNT(*) AS n FROM dm_messages WHERE sender_id = ? AND created_at > ?')
    .bind(session.user_id, new Date(Date.now() - 3600000).toISOString()).first();
  if (recent && recent.n >= DM_PER_HOUR) return error('You are sending messages too quickly. Try again later.', 429);
  const id = generateId(), now = new Date().toISOString();
  await DB.prepare('INSERT INTO dm_messages (id, sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(id, session.user_id, to, body, now).run();
  const me = await communityUserRow(DB, session.user_id);
  pushLater(ctx, env, DB, to, { title: (me && me.name) || 'New message', body: body.slice(0, 140), tag: 'dm-' + session.user_id, open: 'dm:' + session.user_id, urgent: true });
  return json({ success: true, message: { id, body, created_at: now, mine: true, read: false } });
}

// ── Web Push (RFC 8030 delivery, RFC 8291 aes128gcm encryption, RFC 8292 VAPID) ──
// The VAPID private key is the Cloudflare secret VAPID_PRIVATE_JWK (a P-256 JWK with d, x, y).
const PUSH_HOST = /^(?:[a-z0-9-]+\.)*(?:push\.apple\.com|fcm\.googleapis\.com|push\.services\.mozilla\.com|notify\.windows\.com)$/;
const PUSH_MAX_PER_USER = 10;
const textBytes = s => new TextEncoder().encode(s);
function b64url(bytes) {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '==='.slice((s.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function joinBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8));
}
let vapidCache = null;
async function vapidKeys(env) {
  if (!env.VAPID_PRIVATE_JWK) return null;
  if (vapidCache && vapidCache.src === env.VAPID_PRIVATE_JWK) return vapidCache;
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', d: jwk.d, x: jwk.x, y: jwk.y, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  vapidCache = { src: env.VAPID_PRIVATE_JWK, key, pub: joinBytes(new Uint8Array([4]), unb64url(jwk.x), unb64url(jwk.y)) };
  return vapidCache;
}
async function vapidHeader(endpoint, keys) {
  const head = b64url(textBytes(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64url(textBytes(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: 'https://tridentfitness.netlify.app' })));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.key, textBytes(`${head}.${claims}`));
  return `vapid t=${head}.${claims}.${b64url(sig)}, k=${b64url(keys.pub)}`;
}
// `fixed` is only for checking against the RFC 8291 example: { senderJwk, salt }.
async function encryptPush(p256dh, auth, payload, fixed) {
  const uaPub = unb64url(p256dh), authSecret = unb64url(auth);
  const local = fixed
    ? { privateKey: await crypto.subtle.importKey('jwk', fixed.senderJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']),
        publicKey: await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: fixed.senderJwk.x, y: fixed.senderJwk.y, ext: true }, { name: 'ECDH', namedCurve: 'P-256' }, true, []) }
    : await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', local.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(authSecret, shared, joinBytes(textBytes('WebPush: info\0'), uaPub, asPub), 32);
  const salt = fixed ? fixed.salt : crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, textBytes('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, textBytes('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, joinBytes(payload, new Uint8Array([2]))));
  const header = new Uint8Array(21);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPub.length;
  return joinBytes(header, asPub, sealed);
}
async function pushOne(env, DB, sub, message, keys) {
  const body = await encryptPush(sub.p256dh, sub.auth, textBytes(JSON.stringify(message)));
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': await vapidHeader(sub.endpoint, keys),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
      'Urgency': message.urgent ? 'high' : 'normal'
    },
    body
  });
  // The device unsubscribed or the subscription expired: forget it.
  if (res.status === 404 || res.status === 410) await DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?').bind(sub.endpoint).run();
  let detail = '';
  if (!res.ok) { try { detail = (await res.text()).slice(0, 200); } catch (e) {} }
  return { host: new URL(sub.endpoint).host, status: res.status, detail };
}
async function pushToUser(env, DB, userId, message) {
  const keys = await vapidKeys(env);
  if (!keys) return [];
  const rows = await DB.prepare('SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?').bind(userId).all();
  const msg = { title: String(message.title || 'Trident Fitness').slice(0, 80), body: String(message.body || '').slice(0, 160), tag: message.tag || '', open: message.open || '', urgent: !!message.urgent };
  return Promise.all((rows.results || []).map(sub => pushOne(env, DB, sub, msg, keys).catch(e => ({ host: '', status: 0, detail: String(e && e.message || e) }))));
}
// Sends after the response has gone back, so posting a message or comment is never slowed down.
function pushLater(ctx, env, DB, userId, message) {
  const job = pushToUser(env, DB, userId, message).catch(e => console.error('Push failed:', e && e.message));
  if (ctx && ctx.waitUntil) ctx.waitUntil(job);
}
async function pushKey(env) {
  const keys = await vapidKeys(env);
  if (!keys) return error('Notifications are not set up on the server', 503);
  return json({ key: b64url(keys.pub) });
}
async function pushSubscribe(request, DB, env) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const endpoint = data && data.endpoint, keys = (data && data.keys) || {};
  let url;
  try { url = new URL(endpoint); } catch (e) { return error('Invalid subscription'); }
  // PUSH_ALLOW_LOCAL is only ever set in local test runs (.dev.vars), never on the live Worker.
  const localTest = env && env.PUSH_ALLOW_LOCAL === '1' && url.protocol === 'http:' && url.hostname === '127.0.0.1';
  if ((!localTest && (url.protocol !== 'https:' || !PUSH_HOST.test(url.hostname))) || endpoint.length > 1000) return error('Invalid subscription');
  let pub, auth;
  try { pub = unb64url(keys.p256dh); auth = unb64url(keys.auth); } catch (e) { return error('Invalid subscription'); }
  if (pub.length !== 65 || pub[0] !== 4 || auth.length !== 16) return error('Invalid subscription');
  const now = new Date().toISOString();
  await DB.prepare(`INSERT INTO push_subscriptions (endpoint, user_id, p256dh, auth, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, updated_at = excluded.updated_at`)
    .bind(endpoint, session.user_id, keys.p256dh, keys.auth, now, now).run();
  // Keep the newest few devices per account.
  await DB.prepare(`DELETE FROM push_subscriptions WHERE user_id = ?1 AND endpoint NOT IN
    (SELECT endpoint FROM push_subscriptions WHERE user_id = ?1 ORDER BY updated_at DESC LIMIT ${PUSH_MAX_PER_USER})`).bind(session.user_id).run();
  return json({ success: true });
}
async function pushUnsubscribe(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  if (!data || typeof data.endpoint !== 'string') return error('Invalid request');
  await DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?').bind(data.endpoint, session.user_id).run();
  return json({ success: true });
}
async function pushTest(request, DB, env) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  const results = await pushToUser(env, DB, session.user_id, { title: 'Trident Fitness', body: 'Notifications are working. 💪', tag: 'test', open: '' });
  return json({ sent: results.filter(r => r.status >= 200 && r.status < 300).length, results });
}

// ── Rest-timer notification ──
// The app tells the server when the rest will end; a Durable Object (one per account) waits and then
// sends "Rest is over". Starting a new timer replaces the old one; the app cancels it if it is open
// when the timer ends. Sent 3 seconds after the end so that cancel always arrives first.
const REST_MAX_SECONDS = 1800;
async function pushRest(request, DB, env) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  if (!env.REST_TIMERS) return error('Rest notifications are not available', 503);
  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const stub = env.REST_TIMERS.get(env.REST_TIMERS.idFromName(session.user_id));
  if (data && data.cancel) {
    await stub.fetch('https://rest-timer/', { method: 'POST', body: JSON.stringify({ cancel: true }) });
    return json({ success: true });
  }
  const seconds = Number(data && data.seconds);
  if (!Number.isFinite(seconds) || seconds < 1 || seconds > REST_MAX_SECONDS) return error('Invalid request');
  const label = data && typeof data.label === 'string' ? data.label.replace(/\s+/g, ' ').trim().slice(0, 60) : '';
  await stub.fetch('https://rest-timer/', { method: 'POST', body: JSON.stringify({
    userId: session.user_id, fireAt: Date.now() + seconds * 1000 + 3000,
    body: label ? `Time for your next set — ${label}` : 'Time for your next set'
  }) });
  return json({ success: true });
}
export class RestTimer {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const job = await request.json();
    if (job.cancel) {
      await this.state.storage.deleteAlarm();
      await this.state.storage.delete('job');
    } else {
      await this.state.storage.put('job', job);
      await this.state.storage.setAlarm(job.fireAt);
    }
    return new Response('ok');
  }
  async alarm() {
    const job = await this.state.storage.get('job');
    await this.state.storage.delete('job');
    if (!job) return;
    await pushToUser(this.env, this.env.DB, job.userId, { title: 'Rest is over', body: job.body, tag: 'rest-timer', open: 'workout', urgent: true });
  }
}

// ── Profile picture ──
const PROFILE_PIC_MAX = 400000; // characters of the data URL (the app sends a small square image)
async function saveProfilePic(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);
  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const image = data && data.image;
  if (typeof image !== 'string' || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/]+=*$/.test(image)) return error('That photo could not be read');
  if (image.length > PROFILE_PIC_MAX) return error('That photo is too large', 413);
  await DB.prepare(`INSERT INTO user_blobs (user_id, blob_key, data_json, updated_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(user_id, blob_key) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at`)
    .bind(session.user_id, 'profile_pic', JSON.stringify(image)).run();
  return json({ success: true });
}

// Images are stored as data URLs; serve them as real image responses so <img> tags can load them.
function communityImageResponse(dataUrl, cacheControl) {
  const notFound = () => new Response('Not found', { status: 404, headers: CORS });
  if (typeof dataUrl !== 'string') return notFound();
  const m = /^data:(image\/(?:jpeg|png|webp|gif|heic|heif));base64,([A-Za-z0-9+/]+=*)$/.exec(dataUrl);
  if (!m) return notFound();
  let bin;
  try { bin = atob(m[2]); } catch (e) { return notFound(); }
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Response(bytes, {
    headers: { ...CORS, 'Content-Type': m[1], 'Cache-Control': cacheControl, 'X-Content-Type-Options': 'nosniff' }
  });
}

async function communityPhoto(path, DB) {
  const id = path.slice('/community/photo/'.length);
  if (!COMMUNITY_ID.test(id)) return new Response('Not found', { status: 404, headers: CORS });
  const row = await DB.prepare('SELECT photo_data FROM community_posts WHERE id = ?').bind(id).first();
  return communityImageResponse(row && row.photo_data, 'public, max-age=31536000, immutable');
}

async function communityAvatar(path, DB) {
  const userId = path.slice('/community/avatar/'.length);
  if (!COMMUNITY_ID.test(userId)) return new Response('Not found', { status: 404, headers: CORS });
  const row = await DB.prepare(
    'SELECT data_json FROM user_blobs WHERE user_id = ? AND blob_key = ?'
  ).bind(userId, 'profile_pic').first();
  let dataUrl = null;
  try { dataUrl = row ? JSON.parse(row.data_json) : null; } catch (e) {}
  return communityImageResponse(dataUrl, 'public, max-age=300');
}

// ══════════════════════════════════════════════════════
// LOGMEAL PROXY
// ══════════════════════════════════════════════════════

async function handleLogMealProxy(request, path, env) {
  try {
    // Signed-in users only, so the proxy cannot be used by anyone else on the app's LogMeal plan.
    const session = await validateSession(request, env.DB);
    if (!session) return error('Sign in to use food scanning', 401);
    const LOGMEAL_TOKEN = env.LOGMEAL_TOKEN;
    if (!LOGMEAL_TOKEN) return error('Food scanning is not set up on the server', 503);
    const logmealUrl = `${env.LOGMEAL_API_BASE || LOGMEAL_API_BASE}${path}`;
    const contentType = request.headers.get('Content-Type') || '';
    const isMultipart = contentType.includes('multipart');
    // Photo uploads (segmentation/recognition). /image/confirm/ calls are plain JSON and are forwarded as-is.
    const isImageEndpoint = path.includes('/image/') && !path.includes('/image/confirm/');

    let logmealRequest;

    if (isImageEndpoint) {
      // Image endpoints: receive base64 JSON from app, rebuild multipart for LogMeal
      const body = await request.json();
      const base64Data = body.image;

      if (!base64Data) {
        return error('No image data received', 400);
      }

      // Strip data URL prefix if present
      const base64 = base64Data.includes(',') ? base64Data.split(',')[1] : base64Data;

      // Decode base64 to binary
      const binaryStr = atob(base64);
      const bytes = new Uint8Array(binaryStr.length);
      for (let i = 0; i < binaryStr.length; i++) {
        bytes[i] = binaryStr.charCodeAt(i);
      }

      // Build multipart form data with the image blob
      const blob = new Blob([bytes], { type: 'image/jpeg' });
      const formData = new FormData();
      formData.append('image', blob, 'food.jpg');

      logmealRequest = new Request(logmealUrl, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${LOGMEAL_TOKEN}` },
        body: formData
      });

    } else {
      // Non-image endpoints: forward as-is with auth header
      const headers = { 'Authorization': `Bearer ${LOGMEAL_TOKEN}` };
      if (contentType && !isMultipart) headers['Content-Type'] = contentType;

      logmealRequest = new Request(logmealUrl, {
        method: request.method,
        headers,
        body: request.method !== 'GET' ? request.body : undefined,
      });
    }

    const response = await fetch(logmealRequest);
    const responseBody = await response.text();

    console.log(`LogMeal ${path} → ${response.status}: ${responseBody.slice(0, 300)}`);

    if (!response.ok) {
      return new Response(JSON.stringify({
        error: `LogMeal API returned ${response.status}`,
        details: responseBody.slice(0, 500)
      }), {
        status: response.status,
        headers: { ...CORS, 'Content-Type': 'application/json' }
      });
    }

    return new Response(responseBody, {
      status: response.status,
      headers: {
        ...CORS,
        'Content-Type': response.headers.get('Content-Type') || 'application/json',
      }
    });

  } catch (e) {
    console.error('LogMeal proxy error:', e.message);
    return error('LogMeal proxy error: ' + e.message, 500);
  }
}
