'use strict';
// Users, password hashing, sessions and login rate limiting. No database:
// users live in <project>/data/users.json (password hashes only, never plain text).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);
const ROOT = path.resolve(__dirname, '..', '..');
const FILE = process.env.USERS_FILE || path.join(ROOT, 'data', 'users.json');
const COOKIE = 'im_sid';
const IDLE_MS = (Number(process.env.SESSION_HOURS) || 8) * 3600 * 1000; // sign out after this long idle
const ABSOLUTE_MS = 24 * 3600 * 1000; // and never keep a session longer than a day
const MIN_PW = 10;
const MAX_PW = 128;
const ROLES = ['admin', 'user'];

const fail = (message, status = 400) => Object.assign(new Error(message), { status });

/* ---------- storage ---------- */
function readAll() {
  if (!fs.existsSync(FILE)) return [];
  const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8') || '{}');
  return Array.isArray(parsed.users) ? parsed.users : [];
}
function writeAll(users) {
  fs.mkdirSync(path.dirname(FILE), { recursive: true });
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ users }, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, FILE); // atomic replace
}
const publicUser = (u) => ({
  id: u.id, name: u.name, email: u.email, role: u.role, disabled: !!u.disabled,
  createdAt: u.createdAt, updatedAt: u.updatedAt, lastLogin: u.lastLogin || null,
});

/* ---------- passwords ---------- */
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$16384$${salt.toString('base64')}$${h.toString('base64')}`;
}
async function verifyPassword(pw, stored) {
  try {
    const [alg, n, s, h] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(h, 'base64');
    const got = await scrypt(pw, Buffer.from(s, 'base64'), expected.length, { N: Number(n), r: 8, p: 1 });
    return crypto.timingSafeEqual(got, expected);
  } catch { return false; }
}
let dummyHash; // used so unknown emails take as long as wrong passwords
const getDummy = async () => (dummyHash ||= await hashPassword('not-a-real-password'));

function validatePassword(pw, email) {
  if (typeof pw !== 'string' || pw.length < MIN_PW) throw fail(`Password must be at least ${MIN_PW} characters`);
  if (pw.length > MAX_PW) throw fail(`Password must be at most ${MAX_PW} characters`);
  if (!pw.trim()) throw fail('Password cannot be blank');
  if (email && pw.toLowerCase() === String(email).toLowerCase()) throw fail('Password cannot be the same as the email address');
}

/* ---------- validation ---------- */
function cleanName(v) {
  const name = String(v ?? '').replace(/[\u0000-\u001F\u007F]/g, '').trim();
  if (!name) throw fail('Name is required');
  if (name.length > 100) throw fail('Name is too long (max 100 characters)');
  return name;
}
function cleanEmail(v) {
  const email = String(v ?? '').trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw fail('Enter a valid email address');
  return email;
}
function cleanRole(v) {
  const role = v === undefined || v === '' ? 'user' : v;
  if (!ROLES.includes(role)) throw fail('Role must be admin or user');
  return role;
}
const activeAdmins = (users) => users.filter((u) => u.role === 'admin' && !u.disabled);

/* ---------- user management ---------- */
const list = () => readAll().map(publicUser).sort((a, b) => a.name.localeCompare(b.name));
const count = () => readAll().length;

async function createUser({ name, email, password, role }) {
  const users = readAll();
  const e = cleanEmail(email);
  if (users.some((u) => u.email === e)) throw fail('A user with this email already exists', 409);
  validatePassword(password, e);
  const now = new Date().toISOString();
  const user = { id: crypto.randomUUID(), name: cleanName(name), email: e, role: cleanRole(role), disabled: false,
    passwordHash: await hashPassword(password), createdAt: now, updatedAt: now, lastLogin: null };
  users.push(user);
  writeAll(users);
  return publicUser(user);
}

function updateUser(id, patch, actingId) {
  const users = readAll();
  const u = users.find((x) => x.id === id);
  if (!u) throw fail('User not found', 404);
  const next = { ...u };
  if (patch.name !== undefined) next.name = cleanName(patch.name);
  if (patch.email !== undefined) {
    next.email = cleanEmail(patch.email);
    if (users.some((x) => x.id !== id && x.email === next.email)) throw fail('A user with this email already exists', 409);
  }
  if (patch.role !== undefined) next.role = cleanRole(patch.role);
  if (patch.disabled !== undefined) next.disabled = !!patch.disabled;
  if (id === actingId && (next.disabled || next.role !== 'admin') && u.role === 'admin') throw fail('You cannot disable or demote your own admin account');
  const after = users.map((x) => (x.id === id ? next : x));
  if (u.role === 'admin' && !u.disabled && !activeAdmins(after).length) throw fail('At least one active admin is required');
  next.updatedAt = new Date().toISOString();
  writeAll(after);
  if (next.disabled || next.role !== u.role || next.email !== u.email) revokeUser(id);
  return publicUser(next);
}

async function resetPassword(id, password) {
  const users = readAll();
  const u = users.find((x) => x.id === id);
  if (!u) throw fail('User not found', 404);
  validatePassword(password, u.email);
  u.passwordHash = await hashPassword(password);
  u.updatedAt = new Date().toISOString();
  writeAll(users);
  revokeUser(id); // the old password's sessions end immediately
  failures.clear();
  return publicUser(u);
}

async function changeOwnPassword(id, current, next) {
  const users = readAll();
  const u = users.find((x) => x.id === id);
  if (!u) throw fail('User not found', 404);
  if (!(await verifyPassword(String(current ?? ''), u.passwordHash))) throw fail('Current password is incorrect', 403);
  validatePassword(next, u.email);
  u.passwordHash = await hashPassword(next);
  u.updatedAt = new Date().toISOString();
  writeAll(users);
  revokeUser(id);
  return publicUser(u);
}

function removeUser(id, actingId) {
  const users = readAll();
  const u = users.find((x) => x.id === id);
  if (!u) throw fail('User not found', 404);
  if (id === actingId) throw fail('You cannot delete your own account');
  const after = users.filter((x) => x.id !== id);
  if (u.role === 'admin' && !u.disabled && !activeAdmins(after).length) throw fail('At least one active admin is required');
  writeAll(after);
  revokeUser(id);
}

// Used by the create-admin command: creates the account, or resets an existing one (account recovery).
async function upsertAdmin({ name, email, password }) {
  const e = cleanEmail(email);
  const users = readAll();
  const u = users.find((x) => x.email === e);
  if (!u) return { created: true, user: await createUser({ name, email: e, password, role: 'admin' }) };
  validatePassword(password, e);
  u.passwordHash = await hashPassword(password);
  u.role = 'admin'; u.disabled = false; u.updatedAt = new Date().toISOString();
  if (name) u.name = cleanName(name);
  writeAll(users);
  revokeUser(u.id);
  return { created: false, user: publicUser(u) };
}

/* ---------- login with rate limiting ---------- */
const failures = new Map(); // key -> { count, first, lockedUntil }
const WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const LIMITS = { account: 5, ip: 20 };

function locked(key) {
  const f = failures.get(key);
  return !!(f && f.lockedUntil && f.lockedUntil > Date.now());
}
function recordFailure(key, max) {
  const now = Date.now();
  let f = failures.get(key);
  if (!f || now - f.first > WINDOW_MS) f = { count: 0, first: now, lockedUntil: 0 };
  f.count += 1;
  if (f.count >= max) f.lockedUntil = now + LOCK_MS;
  failures.set(key, f);
}

async function login(email, password, ip) {
  const e = String(email ?? '').trim().toLowerCase();
  const accountKey = `a|${e}|${ip}`;
  const ipKey = `i|${ip}`;
  if (locked(accountKey) || locked(ipKey)) throw fail('Too many failed sign-in attempts. Try again in 15 minutes.', 429);
  const users = readAll();
  const u = users.find((x) => x.email === e);
  const ok = await verifyPassword(String(password ?? ''), u ? u.passwordHash : await getDummy());
  if (!u || !ok || u.disabled) {
    recordFailure(accountKey, LIMITS.account);
    recordFailure(ipKey, LIMITS.ip);
    console.warn(`[auth] failed sign-in for "${e.slice(0, 80)}" from ${ip}`);
    throw fail('Invalid email or password', 401); // same message for every failure so emails can't be probed
  }
  failures.delete(accountKey);
  u.lastLogin = new Date().toISOString();
  writeAll(users);
  return publicUser(u);
}

/* ---------- sessions (in memory: a server restart signs everyone out) ---------- */
const sessions = new Map(); // sha256(token) -> { userId, created, last }
const sid = (t) => crypto.createHash('sha256').update(t).digest('hex');

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  sessions.set(sid(token), { userId, created: now, last: now });
  return token;
}
function getSession(token) {
  const s = sessions.get(sid(token));
  if (!s) return null;
  const now = Date.now();
  if (now - s.last > IDLE_MS || now - s.created > ABSOLUTE_MS) { sessions.delete(sid(token)); return null; }
  s.last = now;
  return s;
}
const destroySession = (token) => sessions.delete(sid(token));
function revokeUser(userId) {
  for (const [k, s] of sessions) if (s.userId === userId) sessions.delete(k);
}
setInterval(() => {
  const now = Date.now();
  for (const [k, s] of sessions) if (now - s.last > IDLE_MS || now - s.created > ABSOLUTE_MS) sessions.delete(k);
  for (const [k, f] of failures) if (now - f.first > WINDOW_MS && (!f.lockedUntil || f.lockedUntil < now)) failures.delete(k);
}, 10 * 60 * 1000).unref();

/* ---------- express middleware ---------- */
function cookieValue(header, name) {
  for (const part of String(header || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}
function attach(req, res, next) {
  const token = cookieValue(req.headers.cookie, COOKIE);
  const s = token && getSession(token);
  if (s) {
    const u = readAll().find((x) => x.id === s.userId);
    if (u && !u.disabled) { req.user = publicUser(u); req.sessionToken = token; }
  }
  next();
}
const requireAuth = (req, res, next) => (req.user ? next() : res.status(401).json({ error: 'Please sign in' }));
const requireAdmin = (req, res, next) => (req.user?.role === 'admin' ? next() : res.status(403).json({ error: 'Admin access required' }));

// Cross-site request guard for anything that changes data (on top of SameSite=Strict cookies).
function sameOrigin(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origin = req.headers.origin;
  if (origin) {
    let host;
    try { host = new URL(origin).host; } catch { host = null; }
    if (host !== req.headers.host) return res.status(403).json({ error: 'Cross-site request blocked' });
  }
  next();
}
const cookieOptions = (req) => ({ httpOnly: true, sameSite: 'strict', path: '/', secure: req.secure || process.env.COOKIE_SECURE === '1' });
const setSessionCookie = (req, res, token) => res.cookie(COOKIE, token, cookieOptions(req));
const clearSessionCookie = (req, res) => res.clearCookie(COOKIE, cookieOptions(req));

module.exports = {
  MIN_PW, list, count, createUser, updateUser, resetPassword, changeOwnPassword, removeUser, upsertAdmin,
  login, createSession, getSession, destroySession, revokeUser, hashPassword, verifyPassword, validatePassword,
  attach, requireAuth, requireAdmin, sameOrigin, setSessionCookie, clearSessionCookie, cookieValue, COOKIE,
};
