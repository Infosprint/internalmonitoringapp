import React, { useCallback, useEffect, useState } from 'react';
import { api } from './api.js';

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
function Dashboard({ clients, job, busy, scan, remove }) {
  const itemFor = (id) => job?.items.find((i) => i.clientId === id);
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

      <section className="card">
        <h2>Clients</h2>
        {!clients.length ? <p className="muted">No clients yet. Click “Add client”.</p> : (
          <table>
            <thead><tr><th>Client</th><th>Account</th><th>Role</th><th>Last scan</th><th>Status</th><th /></tr></thead>
            <tbody>
              {clients.map((c) => {
                const it = itemFor(c.id);
                const ls = c.lastScan;
                return (
                  <tr key={c.id} className="clickable" onClick={() => go(`/client/${c.id}`)}>
                    <td><a className="client-link" href={`#/client/${c.id}`} onClick={(e) => e.stopPropagation()}><b>{c.clientName}</b></a></td>
                    <td>{c.accountId}</td>
                    <td className="role" title={c.roleArn}>{c.roleArn.split('/').slice(1).join('/')}</td>
                    <td>{ls ? fmt(ls.at) : <span className="muted">never</span>}</td>
                    <td>
                      {it && it.status !== 'done' && it.status !== 'failed' ? <span className="pill run">{it.status}: {it.message}</span>
                        : ls?.status === 'FAILED' ? <span className="pill bad" title={ls.error}>failed: {ls.error}</span>
                        : ls ? <Sev s={ls.summary} /> : null}
                    </td>
                    <td className="row-actions" onClick={(e) => e.stopPropagation()}>
                      <button className="primary" disabled={busy} onClick={() => scan(c.id)}>Scan</button>
                      <button onClick={() => go(`/client/${c.id}`)}>Reports</button>
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
          <p className="muted">Account {c.accountId} · <span title={c.roleArn}>{c.roleArn.split('/').slice(1).join('/')}</span></p>
        </div>
        <div className="row-actions">
          <button onClick={() => go(`/clients/${c.id}/edit`)}>Edit client</button>
          <button className="primary" disabled={busy} onClick={() => scan(c.id)}>{running ? 'Scanning…' : 'Run scan'}</button>
        </div>
      </div>

      {running && <div className="notice">Scan {it.status}: {it.message}</div>}
      {!running && ls?.status === 'FAILED' && <div className="error">Last scan failed: {ls.error}</div>}

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

/* ---------- app shell ---------- */
export default function App() {
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
  if (parts[0] === 'clients' && parts[1] === 'new') page = <ClientFormPage key="new" id="new" clients={clients} refresh={refresh} />;
  else if (parts[0] === 'clients' && parts[1] && parts[2] === 'edit') page = <ClientFormPage key={parts[1]} id={parts[1]} clients={clients} refresh={refresh} />;
  else if (parts[0] === 'client' && parts[1] && parts[2] === 'report' && parts[3] && parts[4]) page = <ReportViewPage clientId={parts[1]} folder={parts[3]} file={parts[4]} reports={reports} clients={clients} />;
  else if (parts[0] === 'client' && parts[1]) page = <ClientPage id={parts[1]} clients={clients} reports={reports} job={job} busy={busy} scan={scan} />;
  else page = <Dashboard clients={clients} job={job} busy={busy} scan={scan} remove={remove} />;

  return (
    <div className="wrap">
      {error && <div className="error" onClick={() => setError('')}>{error}</div>}
      {page}
    </div>
  );
}
