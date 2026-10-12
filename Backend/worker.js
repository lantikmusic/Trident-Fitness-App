// Trident Fitness - Cloudflare Worker
// Handles: Auth (signup/login/sessions) + LogMeal API proxy

const LOGMEAL_TOKEN = '676027383a6745629677a74d23a5328471ac49e7';
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
    if (path === '/community/comments'        && request.method === 'POST') return community(communityAddComment, request, env.DB);
    if (path === '/community/comments/delete' && request.method === 'POST') return community(communityDeleteComment, request, env.DB);
    if (path.startsWith('/community/photo/')  && request.method === 'GET')  return community(communityPhoto, path, env.DB);
    if (path.startsWith('/community/avatar/') && request.method === 'GET')  return community(communityAvatar, path, env.DB);

    // ── LogMeal Proxy Routes ──
    if (path.startsWith('/v2/')) return handleLogMealProxy(request, path);

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

async function deleteMacro(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();
  // Delete a single matching macro entry by day_index, meal, food_name, and calories
  await DB.prepare(
    'DELETE FROM macro_logs WHERE user_id = ? AND day_index = ? AND meal = ? AND food_name = ? AND calories = ?'
  ).bind(
    session.user_id,
    data.day_index,
    data.meal,
    data.food_name,
    data.calories || 0
  ).run();

  return json({ success: true });
}

async function clearMacros(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  const data = await request.json();
  // Clear all macros for a specific day_index + meal, or whole day if no meal specified
  if (data.meal) {
    await DB.prepare(
      'DELETE FROM macro_logs WHERE user_id = ? AND day_index = ? AND meal = ?'
    ).bind(session.user_id, data.day_index, data.meal).run();
  } else {
    await DB.prepare(
      'DELETE FROM macro_logs WHERE user_id = ? AND day_index = ?'
    ).bind(session.user_id, data.day_index).run();
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
    EXISTS(SELECT 1 FROM user_blobs b WHERE b.user_id = p.user_id AND b.blob_key = 'profile_pic') AS has_avatar
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

  const rows = await DB.prepare(
    `${COMMUNITY_POST_SELECT} WHERE (?2 IS NULL OR p.created_at < ?2) ORDER BY p.created_at DESC LIMIT ?3`
  ).bind(session.user_id, before, limit + 1).all();

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

async function communityAddComment(request, DB) {
  const session = await validateSession(request, DB);
  if (!session) return error('Unauthorized', 401);

  let data;
  try { data = await request.json(); } catch (e) { return error('Invalid request'); }
  const postId = data && data.post_id;
  if (typeof postId !== 'string' || !COMMUNITY_ID.test(postId)) return error('Invalid request');
  const body = typeof data.body === 'string' ? data.body.trim() : '';
  if (!body) return error('Write a comment first');
  if (body.length > COMMUNITY_MAX_COMMENT) return error(`Comments are limited to ${COMMUNITY_MAX_COMMENT} characters`);

  const post = await DB.prepare('SELECT id FROM community_posts WHERE id = ?').bind(postId).first();
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

async function handleLogMealProxy(request, path) {
  try {
    const logmealUrl = `${LOGMEAL_API_BASE}${path}`;
    const contentType = request.headers.get('Content-Type') || '';
    const isMultipart = contentType.includes('multipart');
    const isImageEndpoint = path.includes('/image/');

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
