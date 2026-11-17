import React, { useCallback, useEffect, useState } from 'react';
import { api } from './api.js';
import { AmcOverview, LogsPage } from './Amc.jsx';

const EMPTY = { clientName: '', accountId: '', roleArn: '', externalId: '' };

/* ---------- tiny hash router + Back button ---------- */
let navCount = 0; // number of in-app navigations, so Back never leaves the console
const go = (path) => { window.location.hash = `#${path}`; };

function useRoute() {
  const read = () => (window.location.hash || '#/').replace(/^#/, '') || '/';
  const [route, setRoute] = useState(read);
  useEffect(() => {
    const onChange = () => { navCount += 1; setRoute(read()); window.scrollTo(0, 0); };
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);
  return route;
}

function BackButton({ fallback = '/' }) {
  const back = () => (navCount > 0 ? window.history.back() : go(fallback));
  return <button className="back" onClick={back}>← Back</button>;
}

function Sev({ s }) {
  if (!s) return <span className="muted">—</span>;
  const sf = s.securityFindings;
  return (
    <span>
      <b className="hi">{s.findings.high}</b> high · <b className="med">{s.findings.medium}</b> med
      {sf && <> · <b>{sf.total}</b> unique findings (<span className="hi">{sf.critical + sf.high} crit/high</span>)</>}
      {s.network && <> · <b>{s.network.issues}</b> network/logging issues</>}
    </span>
  );
}

const fmt = (d) => new Date(d).toLocaleString();

/* ---------- page 1: clients ---------- */
const PARTNER_TABS = [['general', 'General'], ['amc', 'AMC partner'], ['billing', 'Billing partner']];

function Dashboard({ clients, job, busy, scan, remove, refresh, setError }) {
  const [tab, setTab] = useState(() => window.sessionStorage?.getItem('partnerTab') || 'general');
  const pick = (t) => { setTab(t); try { window.sessionStorage.setItem('partnerTab', t); } catch { /* ignore */ } };
  const itemFor = (id) => job?.items.find((i) => i.clientId === id);
  const typeOf = (c) => c.partnerType || 'general';
  const shown = tab === 'general' ? clients : clients.filter((c) => typeOf(c) === tab);
  const count = (t) => (t === 'general' ? clients.length : clients.filter((c) => typeOf(c) === t).length);
  async function setPartner(c, type) {
    try { await api.setPartner(c.id, type); await refresh(); } catch (e) { setError(e.message); }
  }
  return (
    <>
      <header>
        <div>
          <h1>Infosprint Monitoring</h1>
          <p className="muted">Click a client to see its reports. Data is stored in <code>data/clients.json</code>.</p>
        </div>
        <div className="row-actions">
          <button onClick={() => go('/clients/new')}>+ Add client</button>
          <button className="primary" disabled={busy || !clients.length} onClick={() => scan(null)}>
            {busy ? 'Scanning…' : `Scan all (${clients.length})`}
          </button>
        </div>
      </header>

      <div className="stats">
        <div className="stat"><div className="n">{clients.length}</div><div className="l">Accounts</div></div>
        <div className="stat green"><div className="n">{count('amc')}</div><div className="l">AMC partners</div></div>
        <div className="stat amber"><div className="n">{count('billing')}</div><div className="l">Billing partners</div></div>
        <div className="stat red"><div className="n">{clients.reduce((n, c) => n + (c.lastScan?.summary?.securityFindings ? c.lastScan.summary.securityFindings.critical + c.lastScan.summary.securityFindings.high : 0), 0)}</div><div className="l">Critical / high findings</div></div>
      </div>

      <section className="card">
        <div className="tabs">{PARTNER_TABS.map(([t, n]) => <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => pick(t)}>{n}<span className="count">{count(t)}</span></button>)}</div>
        {tab === 'general' && <p className="muted">All onboarded accounts. Move an account to AMC partner (adds server metrics, health and log fetching to the scan) or Billing partner (standard scan).</p>}
        {tab === 'amc' && <p className="muted">AMC partners get the standard scan plus server inventory, 8-day CPU/RAM, storage, load balancer health and a Logs page.</p>}
        {tab === 'billing' && <p className="muted">Billing partners get the standard scan.</p>}
        {!shown.length ? <div className="empty">{tab === 'general' ? 'No clients yet. Click “Add client”.' : 'No accounts in this tab yet. Move one from the General tab.'}</div> : (
          <table>
            <thead><tr><th>Client</th><th>Account</th><th>Partner</th><th>Last scan</th><th>Status</th><th /></tr></thead>
            <tbody>
              {shown.map((c) => {
                const it = itemFor(c.id);
                const ls = c.lastScan;
                return (
                  <tr key={c.id} className="clickable" onClick={() => go(`/client/${c.id}`)}>
                    <td><a className="client-link" href={`#/client/${c.id}`} onClick={(e) => e.stopPropagation()}><b>{c.clientName}</b></a></td>
                    <td>{c.accountId}</td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <select value={typeOf(c)} aria-label={`Partner type of ${c.clientName}`} onChange={(e) => setPartner(c, e.target.value)}>
                        <option value="general">General</option><option value="amc">AMC partner</option><option value="billing">Billing partner</option>
                      </select>
                    </td>
                    <td>{ls ? fmt(ls.at) : <span className="muted">never</span>}</td>
                    <td>
                      {it && it.status !== 'done' && it.status !== 'failed' ? <span className="pill run">{it.status}: {it.message}</span>
                        : ls?.status === 'FAILED' ? <span className="pill bad" title={ls.error}>failed: {ls.error}</span>
                        : ls ? <Sev s={ls.summary} /> : null}
                    </td>
                    <td className="row-actions" onClick={(e) => e.stopPropagation()}>
                      <button className="primary" disabled={busy} onClick={() => scan(c.id)}>Scan</button>
                      <button onClick={() => go(`/client/${c.id}`)}>Reports</button>
                      {typeOf(c) === 'amc' && <button onClick={() => go(`/client/${c.id}/logs`)}>Logs</button>}
                      <button onClick={() => go(`/clients/${c.id}/edit`)}>Edit</button>
                      <button className="danger" onClick={() => remove(c)}>Delete</button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}

/* ---------- page 2: one client and its reports ---------- */
function ClientPage({ id, clients, reports, job, busy, scan }) {
  const c = clients.find((x) => x.id === id);
  if (!c) return (<><div className="topbar"><BackButton /><h1>Client not found</h1></div><p className="muted">This client no longer exists.</p></>);
  const mine = reports.filter((r) => r.accountId === c.accountId);
  const it = job?.items.find((i) => i.clientId === c.id);
  const running = it && it.status !== 'done' && it.status !== 'failed';
  const ls = c.lastScan;

  return (
    <>
      <div className="topbar">
        <BackButton fallback="/" />
        <div className="grow">
          <h1>{c.clientName}</h1>
          <p className="muted">Account {c.accountId} · {({ amc: 'AMC partner', billing: 'Billing partner' })[c.partnerType] || 'General'} · <span title={c.roleArn}>{c.roleArn.split('/').slice(1).join('/')}</span></p>
        </div>
        <div className="row-actions">
          {c.partnerType === 'amc' && <button onClick={() => go(`/client/${c.id}/logs`)}>Logs</button>}
          <button onClick={() => go(`/clients/${c.id}/edit`)}>Edit client</button>
          <button className="primary" disabled={busy} onClick={() => scan(c.id)}>{running ? 'Scanning…' : 'Run scan'}</button>
        </div>
      </div>

      {running && <div className="notice">Scan {it.status}: {it.message}</div>}
      {!running && ls?.status === 'FAILED' && <div className="error">Last scan failed: {ls.error}</div>}

      {c.partnerType === 'amc' && <AmcOverview clientId={c.id} />}

      <section className="card">
        <h2>Reports ({mine.length})</h2>
        {!mine.length ? <p className="muted">No reports for this client yet. Click “Run scan”.</p> : (
          <table>
            <thead><tr><th>Generated</th><th>Instances</th><th>Recommendations · findings</th><th /></tr></thead>
            <tbody>
              {mine.map((r) => (
                <tr key={`${r.folder}/${r.file}`}>
                  <td>{fmt(r.generatedAt)}</td>
                  <td>{r.summary.totalInstances}</td>
                  <td><Sev s={r.summary} /></td>
                  <td className="row-actions">
                    <button className="primary" onClick={() => go(`/client/${c.id}/report/${r.folder}/${r.file}`)}>View</button>
                    <a className="btn word" href={`/api/reports/${r.folder}/${r.file}.docx`} download>Download Word</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}

/* ---------- page 3: one report ---------- */
function ReportViewPage({ clientId, folder, file, reports, clients }) {
  const r = reports.find((x) => x.folder === folder && x.file === file);
  const c = clients.find((x) => x.id === clientId);
  const base = `/api/reports/${folder}/${file}`;
  return (
    <>
      <div className="topbar">
        <BackButton fallback={`/client/${clientId}`} />
        <div className="grow">
          <h1>{r ? r.clientName : c?.clientName || 'Report'}</h1>
          {r && <p className="muted">Account {r.accountId} · {fmt(r.generatedAt)}</p>}
        </div>
        <div className="row-actions">
          <a className="btn word" href={`${base}.docx`} download>Download Word</a>
          <a className="btn" href={`${base}.html`} target="_blank" rel="noreferrer">Open HTML</a>
          <a className="btn" href={`${base}.json`}>JSON</a>
        </div>
      </div>
      <iframe className="report-frame" title="Report" src={`${base}.html`} />
    </>
  );
}

/* ---------- add / edit client ---------- */
function ClientFormPage({ id, clients, refresh }) {
  const existing = id === 'new' ? null : clients.find((c) => c.id === id);
  const [form, setForm] = useState(existing
    ? { clientName: existing.clientName, accountId: existing.accountId, roleArn: existing.roleArn, externalId: existing.externalId || '' }
    : EMPTY);
  const [error, setError] = useState('');
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  if (id !== 'new' && !existing) {
    return (<><div className="topbar"><BackButton /><h1>Client not found</h1></div><p className="muted">This client no longer exists.</p></>);
  }

  async function submit(e) {
    e.preventDefault();
    setError('');
    try {
      if (existing) await api.updateClient(existing.id, form);
      else await api.addClient(form);
      await refresh();
      go('/');
    } catch (err) { setError(err.message); }
  }

  const cancel = () => (navCount > 0 ? window.history.back() : go('/'));

  return (
    <>
      <div className="topbar"><BackButton /><h1>{existing ? 'Edit client' : 'Add client'}</h1></div>
      {error && <div className="error" onClick={() => setError('')}>{error}</div>}
      <section className="card">
        <form onSubmit={submit} className="grid" autoComplete="off">
          <label>Client name<input name="client-name" autoComplete="off" value={form.clientName} onChange={set('clientName')} placeholder="Acme Corp" required /></label>
          <label>AWS account ID<input name="account-id" autoComplete="off" value={form.accountId} onChange={set('accountId')} placeholder="123456789012" pattern="\d{12}" title="12 digits" required /></label>
          <label>IAM role (name or ARN)<input name="iam-role" autoComplete="off" value={form.roleArn} onChange={set('roleArn')} placeholder="InfosprintReadOnly or arn:aws:iam::123456789012:role/…" required /></label>
          <label>External ID (optional)<input name="external-id" autoComplete="off" data-lpignore="true" value={form.externalId} onChange={set('externalId')} placeholder="only if the role trust policy requires one" /></label>
          <div className="actions">
            <button className="primary" type="submit">{existing ? 'Save changes' : 'Add client'}</button>
            <button type="button" onClick={cancel}>Cancel</button>
          </div>
        </form>
      </section>
    </>
  );
}

/* ---------- password helpers ---------- */
function genPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  const a = new Uint32Array(16);
  window.crypto.getRandomValues(a);
  return Array.from(a, (x) => chars[x % chars.length]).join('');
}

function PasswordField({ label, value, onChange, generate, autoComplete = 'new-password', placeholder = 'At least 10 characters' }) {
  const [show, setShow] = useState(false);
  return (
    <label>{label}
      <div className="pw">
        <input type={show ? 'text' : 'password'} autoComplete={autoComplete} value={value} placeholder={placeholder}
          onChange={(e) => onChange(e.target.value)} minLength={10} maxLength={128} required />
        <button type="button" onClick={() => setShow(!show)}>{show ? 'Hide' : 'Show'}</button>
        {generate && <button type="button" onClick={() => { onChange(genPassword()); setShow(true); }}>Generate</button>}
      </div>
    </label>
  );
}

/* ---------- sign in ---------- */
function LoginPage({ onSignedIn, notice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try { onSignedIn(await api.login(email, password)); } catch (err) { setError(err.message); setBusy(false); }
  }

  return (
    <div className="login-shell">
      <div className="hero">
        <a className="brand" style={{ fontSize: 18 }}><i>◈</i>Infosprint Monitoring</a>
        <h2>Know the health of every client AWS account.</h2>
        <p>Security services, backups, network exposure, server health and logs in one console.</p>
        <ul>
          <li><i>🛡</i>GuardDuty, Inspector and Security Hub coverage</li>
          <li><i>📈</i>CPU, RAM and storage for AMC partners</li>
          <li><i>📥</i>One-click log export for audits</li>
        </ul>
      </div>
      <div className="login">
      <section className="card">
        <h1>Welcome back</h1>
        <p className="muted">Sign in with your work email and password.</p>
        {notice && <div className="notice">{notice}</div>}
        {error && <div className="error" onClick={() => setError('')}>{error}</div>}
        <form onSubmit={submit} className="stack">
          <label>Email<input type="email" name="email" autoComplete="username" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} required /></label>
          <label>Password<input type="password" name="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required /></label>
          <button className="primary" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        </form>
        <p className="muted small">Forgot your password? Ask an administrator to reset it.</p>
      </section>
      </div>
    </div>
  );
}

/* ---------- change my password ---------- */
function AccountPage() {
  const [form, setForm] = useState({ current: '', next: '', again: '' });
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const set = (k) => (v) => setForm({ ...form, [k]: v });

  async function submit(e) {
    e.preventDefault();
    setError(''); setDone(false);
    if (form.next !== form.again) { setError('The new passwords do not match'); return; }
    try { await api.changePassword(form.current, form.next); setForm({ current: '', next: '', again: '' }); setDone(true); } catch (err) { setError(err.message); }
  }

  return (
    <>
      <div className="topbar"><BackButton /><h1>Change password</h1></div>
      {error && <div className="error" onClick={() => setError('')}>{error}</div>}
      {done && <div className="notice">Password changed. Your other signed-in sessions were ended.</div>}
      <section className="card narrow">
        <form onSubmit={submit} className="stack" autoComplete="off">
          <PasswordField label="Current password" value={form.current} onChange={set('current')} autoComplete="current-password" placeholder="" />
          <PasswordField label="New password" value={form.next} onChange={set('next')} />
          <PasswordField label="Repeat new password" value={form.again} onChange={set('again')} />
          <div className="actions"><button className="primary" type="submit">Change password</button></div>
        </form>
      </section>
    </>
  );
}

/* ---------- admin: users ---------- */
function UsersPage({ me }) {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [form, setForm] = useState({ name: '', email: '', password: '', role: 'user' });
  const [editing, setEditing] = useState(null);   // { id, name, email, role }
  const [temp, setTemp] = useState(null);       // { name, password } shown once after a reset

  const load = useCallback(async () => { setUsers(await api.users()); }, []);
  useEffect(() => { load().catch((e) => setError(e.message)); }, [load]);

  async function run(fn, okMessage) {
    setError(''); setNotice('');
    try { await fn(); await load(); if (okMessage) setNotice(okMessage); return true; } catch (err) { setError(err.message); return false; }
  }

  async function add(e) {
    e.preventDefault();
    const pw = form.password;
    if (await run(() => api.addUser(form), `Added ${form.name}. Share the password with them securely: ${pw}`)) setForm({ name: '', email: '', password: '', role: 'user' });
  }
  async function saveEdit(e) {
    e.preventDefault();
    if (await run(() => api.updateUser(editing.id, { name: editing.name, email: editing.email, role: editing.role }), 'User updated.')) setEditing(null);
  }
  async function reset(u) {
    if (!window.confirm(`Reset the password for ${u.name} (${u.email})? They will be signed out and need the new password.`)) return;
    setError(''); setNotice(''); setTemp(null);
    try { const r = await api.resetPassword(u.id); setTemp({ name: u.name, password: r.temporaryPassword }); await load(); } catch (err) { setError(err.message); }
  }
  const copyTemp = () => navigator.clipboard?.writeText(temp.password).then(() => setNotice('Password copied.')).catch(() => {});
  const toggle = (u) => run(() => api.updateUser(u.id, { disabled: !u.disabled }), `${u.name} ${u.disabled ? 'enabled' : 'disabled'}.`);
  const remove = (u) => { if (window.confirm(`Delete ${u.name} (${u.email})? This cannot be undone.`)) run(() => api.deleteUser(u.id), `${u.name} deleted.`); };
  const setF = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  return (
    <>
      <div className="topbar"><BackButton /><h1>Users</h1></div>
      {error && <div className="error" onClick={() => setError('')}>{error}</div>}
      {notice && <div className="notice" onClick={() => setNotice('')}>{notice}</div>}
      {temp && (
        <div className="temp">
          <div>New password for <b>{temp.name}</b> (shown only once, share it securely):</div>
          <code>{temp.password}</code>
          <button onClick={copyTemp}>Copy</button>
          <button onClick={() => setTemp(null)}>Done</button>
        </div>
      )}

      <section className="card">
        <h2>Add employee</h2>
        <form onSubmit={add} className="grid" autoComplete="off">
          <label>Name<input name="emp-name" autoComplete="off" value={form.name} onChange={setF('name')} placeholder="Employee name" required /></label>
          <label>Email<input type="email" name="emp-email" autoComplete="off" value={form.email} onChange={setF('email')} placeholder="name@infosprint.com" required /></label>
          <PasswordField label="Initial password" value={form.password} onChange={(v) => setForm({ ...form, password: v })} generate />
          <label>Role
            <select value={form.role} onChange={setF('role')}><option value="user">User (can use the console)</option><option value="admin">Admin (can also manage users)</option></select>
          </label>
          <div className="actions"><button className="primary" type="submit">Add employee</button></div>
        </form>
      </section>

      <section className="card">
        <h2>Employees ({users.length})</h2>
        <table>
          <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
          <tbody>
            {users.map((u) => (
              <React.Fragment key={u.id}>
                <tr>
                  <td>{editing?.id === u.id
                    ? <input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
                    : <>{u.name}{u.id === me.id && <span className="muted"> (you)</span>}</>}</td>
                  <td>{editing?.id === u.id
                    ? <input type="email" value={editing.email} onChange={(e) => setEditing({ ...editing, email: e.target.value })} />
                    : u.email}</td>
                  <td>{editing?.id === u.id
                    ? <select value={editing.role} disabled={u.id === me.id} onChange={(e) => setEditing({ ...editing, role: e.target.value })}><option value="user">User</option><option value="admin">Admin</option></select>
                    : u.role === 'admin' ? 'Admin' : 'User'}</td>
                  <td>{u.disabled ? <span className="pill bad">Disabled</span> : <span className="pill ok">Active</span>}</td>
                  <td className="muted">{u.lastLogin ? fmt(u.lastLogin) : 'Never'}</td>
                  <td>
                    <div className="row-actions">
                      {editing?.id === u.id ? (
                        <><button className="primary" onClick={saveEdit}>Save</button><button onClick={() => setEditing(null)}>Cancel</button></>
                      ) : (
                        <>
                          <button onClick={() => { setEditing({ id: u.id, name: u.name, email: u.email, role: u.role }); }}>Edit</button>
                          {u.id !== me.id && <button onClick={() => reset(u)}>Reset password</button>}
                          {u.id !== me.id && <button onClick={() => toggle(u)}>{u.disabled ? 'Enable' : 'Disable'}</button>}
                          {u.id !== me.id && <button className="danger" onClick={() => remove(u)}>Delete</button>}
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}

/* ---------- top bar with who is signed in ---------- */
function UserBar({ user, onSignOut }) {
  return (
    <nav className="userbar">
      <a className="brand" href="#/"><i>◈</i>Infosprint Monitoring</a>
      <a href="#/">Clients</a>
      {user.role === 'admin' && <a href="#/users">Users</a>}
      <span className="grow" />
      <span className="who"><span className="avatar">{(user.name || '?').trim().slice(0, 1).toUpperCase()}</span>{user.name} <span className="muted">({user.role})</span></span>
      <a href="#/account">Change password</a>
      <button onClick={onSignOut}>Sign out</button>
    </nav>
  );
}

/* ---------- app shell ---------- */
function Console({ user, onSignOut }) {
  const route = useRoute();
  const [clients, setClients] = useState([]);
  const [reports, setReports] = useState([]);
  const [error, setError] = useState('');
  const [job, setJob] = useState(null);

  const refresh = useCallback(async () => {
    const [c, r] = await Promise.all([api.clients(), api.reports()]);
    setClients(c);
    setReports(r);
  }, []);

  useEffect(() => { refresh().catch((e) => setError(e.message)); }, [route, refresh]);

  useEffect(() => {
    if (!job || job.status !== 'running') return undefined;
    const t = setInterval(async () => {
      try {
        const j = await api.job(job.id);
        setJob(j);
        if (j.status !== 'running') refresh();
      } catch (e) { setError(e.message); }
    }, 1500);
    return () => clearInterval(t);
  }, [job, refresh]);

  async function remove(c) {
    if (!window.confirm(`Remove ${c.clientName} (${c.accountId})? Existing reports are kept on disk.`)) return;
    try { await api.deleteClient(c.id); await refresh(); } catch (err) { setError(err.message); }
  }

  async function scan(id) {
    setError('');
    try { setJob(await (id ? api.scan(id) : api.scanAll())); } catch (err) { setError(err.message); }
  }

  const busy = job?.status === 'running';
  const parts = route.split('/').filter(Boolean);

  let page;
  if (parts[0] === 'users' && user.role === 'admin') page = <UsersPage me={user} />;
  else if (parts[0] === 'account') page = <AccountPage />;
  else if (parts[0] === 'clients' && parts[1] === 'new') page = <ClientFormPage key="new" id="new" clients={clients} refresh={refresh} />;
  else if (parts[0] === 'clients' && parts[1] && parts[2] === 'edit') page = <ClientFormPage key={parts[1]} id={parts[1]} clients={clients} refresh={refresh} />;
  else if (parts[0] === 'client' && parts[1] && parts[2] === 'report' && parts[3] && parts[4]) page = <ReportViewPage clientId={parts[1]} folder={parts[3]} file={parts[4]} reports={reports} clients={clients} />;
  else if (parts[0] === 'client' && parts[1] && parts[2] === 'logs') page = clients.find((x) => x.id === parts[1])?.partnerType === 'amc' ? <LogsPage key={parts[1]} client={clients.find((x) => x.id === parts[1])} BackButton={BackButton} /> : <p className="muted">Logs are available for AMC partners only.</p>;
  else if (parts[0] === 'client' && parts[1]) page = <ClientPage id={parts[1]} clients={clients} reports={reports} job={job} busy={busy} scan={scan} />;
  else page = <Dashboard clients={clients} job={job} busy={busy} scan={scan} remove={remove} refresh={refresh} setError={setError} />;

  return (
    <div className="wrap">
      <UserBar user={user} onSignOut={onSignOut} />
      {error && <div className="error" onClick={() => setError('')}>{error}</div>}
      {page}
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(undefined); // undefined = checking, null = signed out
  const [notice, setNotice] = useState('');

  useEffect(() => { api.me().then(setUser).catch(() => setUser(null)); }, []);
  useEffect(() => {
    const expired = () => { setUser((u) => { if (u) setNotice('Your session has ended. Please sign in again.'); return null; }); };
    window.addEventListener('auth-expired', expired);
    return () => window.removeEventListener('auth-expired', expired);
  }, []);

  async function signOut() {
    try { await api.logout(); } catch { /* ignore */ }
    setNotice('');
    setUser(null);
    window.location.hash = '#/';
  }

  if (user === undefined) return <div className="wrap"><p className="muted">Loading…</p></div>;
  if (!user) return <LoginPage notice={notice} onSignedIn={(u) => { setNotice(''); window.location.hash = '#/'; setUser(u); }} />;
  return <Console user={user} onSignOut={signOut} />;
}
