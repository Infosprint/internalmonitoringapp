'use strict';
// Offline tests for sign-in and user management, including a real HTTP run against the Express app.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'im-auth-'));
process.env.USERS_FILE = path.join(dir, 'users.json');
const auth = require('./auth');

const rejects = async (p, re, msg) => { try { await p; } catch (e) { assert(re.test(e.message), `${msg}: got "${e.message}"`); return e; } assert.fail(`${msg}: expected an error`); };

(async () => {
  /* hashing */
  const h = await auth.hashPassword('correct horse battery');
  assert(!h.includes('correct horse'), 'hash must not contain the password');
  assert(await auth.verifyPassword('correct horse battery', h));
  assert(!(await auth.verifyPassword('wrong password!!', h)));
  assert(!(await auth.verifyPassword('x', 'garbage')));

  /* create + validation */
  const admin = await auth.createUser({ name: 'Admin One', email: 'Admin@Infosprint.com ', password: 'Sup3rSecret!!', role: 'admin' });
  assert.strictEqual(admin.email, 'admin@infosprint.com', 'email lower-cased and trimmed');
  assert(!('passwordHash' in admin), 'public user has no hash');
  assert(!fs.readFileSync(process.env.USERS_FILE, 'utf8').includes('Sup3rSecret'), 'plain password is never stored');
  await rejects(auth.createUser({ name: 'X', email: 'admin@infosprint.com', password: 'Sup3rSecret!!' }), /already exists/, 'duplicate email');
  await rejects(auth.createUser({ name: 'X', email: 'bad', password: 'Sup3rSecret!!' }), /valid email/, 'bad email');
  await rejects(auth.createUser({ name: 'X', email: 'x@y.io', password: 'short' }), /at least 10/, 'short password');
  await rejects(auth.createUser({ name: '  ', email: 'x@y.io', password: 'Sup3rSecret!!' }), /Name is required/, 'empty name');
  await rejects(auth.createUser({ name: 'X', email: 'x@y.io', password: 'Sup3rSecret!!', role: 'root' }), /Role/, 'bad role');
  const emp = await auth.createUser({ name: 'Emp Two', email: 'emp@infosprint.com', password: 'EmployeePass1' });
  assert.strictEqual(emp.role, 'user');

  /* login */
  const ok = await auth.login('EMP@infosprint.com', 'EmployeePass1', '1.1.1.1');
  assert.strictEqual(ok.email, 'emp@infosprint.com');
  const e1 = await rejects(auth.login('emp@infosprint.com', 'nope-nope-nope', '1.1.1.1'), /Invalid email or password/, 'wrong password');
  const e2 = await rejects(auth.login('ghost@infosprint.com', 'nope-nope-nope', '1.1.1.1'), /Invalid email or password/, 'unknown email');
  assert.strictEqual(e1.message, e2.message, 'same message for unknown email and wrong password');

  /* rate limiting: 5 failures lock that account+ip, other ip still works */
  for (let i = 0; i < 5; i++) await rejects(auth.login('emp@infosprint.com', 'bad-bad-bad-1', '2.2.2.2'), /Invalid/, 'fail');
  const locked2 = await rejects(auth.login('emp@infosprint.com', 'EmployeePass1', '2.2.2.2'), /Too many/, 'correct password refused while locked');
  assert.strictEqual(locked2.status, 429);
  await auth.login('emp@infosprint.com', 'EmployeePass1', '3.3.3.3');

  /* sessions */
  const tok = auth.createSession(emp.id);
  assert(auth.getSession(tok));
  assert(!auth.getSession('made-up-token'));
  await auth.resetPassword(emp.id, 'BrandNewPass99');
  assert(!auth.getSession(tok), 'reset ends existing sessions');
  await rejects(auth.login('emp@infosprint.com', 'EmployeePass1', '4.4.4.4'), /Invalid/, 'old password no longer works');
  await auth.login('emp@infosprint.com', 'BrandNewPass99', '4.4.4.4');
  await rejects(auth.changeOwnPassword(emp.id, 'wrong-current', 'AnotherPass123'), /incorrect/, 'wrong current password');
  await auth.changeOwnPassword(emp.id, 'BrandNewPass99', 'AnotherPass123');

  const tok2 = auth.createSession(emp.id);
  auth.updateUser(emp.id, { disabled: true }, admin.id);
  assert(!auth.getSession(tok2), 'disable ends sessions');
  await rejects(auth.login('emp@infosprint.com', 'AnotherPass123', '5.5.5.5'), /Invalid/, 'disabled user cannot sign in');
  auth.updateUser(emp.id, { disabled: false, name: 'Emp Renamed', email: 'emp2@infosprint.com' }, admin.id);
  assert(auth.list().some((u) => u.email === 'emp2@infosprint.com' && u.name === 'Emp Renamed'));

  /* admin safety rules */
  assert.throws(() => auth.updateUser(admin.id, { disabled: true }, admin.id), /own admin/);
  assert.throws(() => auth.updateUser(admin.id, { role: 'user' }, admin.id), /own admin/);
  assert.throws(() => auth.removeUser(admin.id, admin.id), /own account/);
  const admin2 = await auth.createUser({ name: 'Admin Two', email: 'a2@infosprint.com', password: 'AdminTwoPass1', role: 'admin' });
  auth.updateUser(admin2.id, { disabled: true }, admin.id); // fine: admin one stays active
  assert.throws(() => auth.removeUser(admin.id, 'someone-else'), /At least one active admin/);
  auth.removeUser(admin2.id, admin.id);

  /* create-admin recovery */
  const r = await auth.upsertAdmin({ name: 'Admin One', email: 'admin@infosprint.com', password: 'RecoveredPass1' });
  assert.strictEqual(r.created, false);
  await auth.login('admin@infosprint.com', 'RecoveredPass1', '6.6.6.6');

  /* ---------- HTTP end to end ---------- */
  const port = 4900 + Math.floor(Math.random() * 90);
  const child = spawn(process.execPath, [path.join(__dirname, 'index.js')], { env: { ...process.env, PORT: String(port) }, stdio: 'ignore' });
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 40; i++) { try { await fetch(base + '/api/auth/me'); break; } catch { await new Promise((r) => setTimeout(r, 150)); } }
  try {
    const call = async (method, url, body, cookie, extra = {}) => {
      const res = await fetch(base + url, { method, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...extra }, body: body ? JSON.stringify(body) : undefined });
      return { res, data: await res.json().catch(() => null) };
    };
    for (const u of ['/api/clients', '/api/reports', '/api/users', '/api/auth/me', '/api/reports/a/b.html', '/api/reports/a/b.docx']) {
      assert.strictEqual((await call('GET', u)).res.status, 401, `${u} requires sign-in`);
    }
    assert.strictEqual((await call('POST', '/api/scan/all')).res.status, 401, 'scan requires sign-in');
    assert.strictEqual((await call('POST', '/api/auth/login', { email: 'admin@infosprint.com', password: 'wrong-wrong-1' })).res.status, 401);

    const login = await call('POST', '/api/auth/login', { email: 'admin@infosprint.com', password: 'RecoveredPass1' });
    assert.strictEqual(login.res.status, 200);
    const setCookie = login.res.headers.get('set-cookie');
    assert(/HttpOnly/i.test(setCookie) && /SameSite=Strict/i.test(setCookie), 'cookie is HttpOnly + SameSite=Strict');
    assert(!/Secure/i.test(setCookie), 'no Secure flag over plain http');
    const cookie = setCookie.split(';')[0];
    assert.strictEqual((await call('GET', '/api/auth/me', null, cookie)).data.email, 'admin@infosprint.com');
    assert.strictEqual((await call('GET', '/api/clients', null, cookie)).res.status, 200);

    const secure = await call('POST', '/api/auth/login', { email: 'admin@infosprint.com', password: 'RecoveredPass1' }, null, { 'X-Forwarded-Proto': 'https' });
    assert.strictEqual(secure.res.status, 200); // header ignored unless it comes from the local proxy; still must work

    // cross-site writes are refused even with a valid cookie
    assert.strictEqual((await call('POST', '/api/users', { name: 'E', email: 'e@x.io', password: 'LongEnough123' }, cookie, { Origin: 'https://evil.example' })).res.status, 403);

    // admin API: add employee, then the employee signs in but cannot reach admin routes
    const add = await call('POST', '/api/users', { name: 'New Hire', email: 'hire@infosprint.com', password: 'HirePassword1' }, cookie);
    assert.strictEqual(add.res.status, 201);
    assert(!JSON.stringify(add.data).includes('passwordHash'), 'API never returns hashes');
    const emp = await call('POST', '/api/auth/login', { email: 'hire@infosprint.com', password: 'HirePassword1' });
    const empCookie = emp.res.headers.get('set-cookie').split(';')[0];
    assert.strictEqual((await call('GET', '/api/clients', null, empCookie)).res.status, 200, 'employee can use the console');
    assert.strictEqual((await call('GET', '/api/users', null, empCookie)).res.status, 403, 'employee cannot list users');
    assert.strictEqual((await call('POST', '/api/users', { name: 'x', email: 'x@y.io', password: 'LongEnough123' }, empCookie)).res.status, 403);
    assert.strictEqual((await call('POST', `/api/users/${add.data.id}/reset-password`, { password: 'LongEnough123' }, empCookie)).res.status, 403);

    // admin resets the employee's password: their session dies, new password works
    const reset = await call('POST', `/api/users/${add.data.id}/reset-password`, { password: 'ResetPassword77' }, cookie);
    assert.strictEqual(reset.res.status, 200);
    assert.strictEqual((await call('GET', '/api/auth/me', null, empCookie)).res.status, 401, 'old session ended');
    assert.strictEqual((await call('POST', '/api/auth/login', { email: 'hire@infosprint.com', password: 'ResetPassword77' })).res.status, 200);

    // logout
    assert.strictEqual((await call('POST', '/api/auth/logout', null, cookie)).res.status, 204);
    assert.strictEqual((await call('GET', '/api/auth/me', null, cookie)).res.status, 401, 'logged out');
  } finally { child.kill(); }

  fs.rmSync(dir, { recursive: true, force: true });
  console.log('authtest passed');
})().catch((e) => { console.error(e); process.exit(1); });
