import React, { useEffect, useMemo, useState } from 'react';
import { api } from './api.js';

const go = (path) => { window.location.hash = `#${path}`; };

/* ---------- small SVG line chart (x axis: dates from startMs in steps of stepMs) ---------- */
function LineChart({ series, startMs, stepMs = 3600000, title }) {
  const W = 520; const H = 170; const m = { l: 34, r: 10, t: 22, b: 24 };
  const w = W - m.l - m.r; const h = H - m.t - m.b;
  const n = Math.max(...series.map((s) => s.values.length), 1);
  const x = (i) => m.l + (n <= 1 ? 0 : (i / (n - 1)) * w);
  const y = (v) => m.t + h - (Math.min(v, 100) / 100) * h;
  const path = (vals) => { let d = ''; let pen = false; vals.forEach((v, i) => { if (v == null) { pen = false; return; } d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`; pen = true; }); return d; };
  const ticks = Array.from({ length: 6 }, (_, k) => Math.round((k * (n - 1)) / 5));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: W, background: '#fff', border: '1px solid #e4e7eb', borderRadius: 10 }} role="img" aria-label={title}>
      {series.map((s, k) => <text key={s.name} x={m.l + 6 + k * 100} y="12" fontSize="10" fill={s.color}>■ {s.name}</text>)}
      {[0, 25, 50, 75, 100].map((v) => (
        <g key={v}><line x1={m.l} x2={W - m.r} y1={y(v)} y2={y(v)} stroke="#e4e7eb" /><text x={m.l - 4} y={y(v) + 3} textAnchor="end" fontSize="9" fill="#52606d">{v}%</text></g>
      ))}
      {ticks.map((i) => <text key={i} x={x(i)} y={H - 8} fontSize="9" fill="#52606d" textAnchor={i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'}>{new Date(startMs + i * stepMs).toISOString().slice(0, 10)}</text>)}
      {series.map((s) => <path key={s.name} d={path(s.values)} fill="none" stroke={s.color} strokeWidth="1.5" strokeDasharray={s.dash ? '3 2' : undefined} />)}
    </svg>
  );
}

const COLORS = ['#7c3aed', '#0891b2', '#db2777', '#65a30d'];

// Last 6 months of CPU, RAM and disk usage, fetched when a server's details are opened (not part of the report)
function History({ clientId, i }) {
  const [h, setH] = useState(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let live = true;
    api.amcHistory(clientId, i.region, i.instanceId).then((d) => live && setH(d)).catch((e) => live && setErr(e.message));
    return () => { live = false; };
  }, [clientId, i.region, i.instanceId]);
  if (err) return <div className="error">{err}</div>;
  if (!h) return <><div className="bar"><i /></div><p className="muted">Loading 6-month history…</p></>;
  const start = new Date(h.start).getTime(); const step = h.stepSeconds * 1000;
  return (
    <div className="charts">
      <div><div className="muted">CPU utilisation, last 6 months</div>
        <LineChart title="CPU" startMs={start} stepMs={step} series={[{ name: 'Average', color: '#4f46e5', values: h.cpu.avg }, { name: 'Peak', color: '#dc2626', values: h.cpu.max, dash: true }]} /></div>
      <div><div className="muted">RAM utilisation, last 6 months</div>
        {h.memory ? <LineChart title="RAM" startMs={start} stepMs={step} series={[{ name: 'Average', color: '#059669', values: h.memory.avg }, { name: 'Peak', color: '#d97706', values: h.memory.max, dash: true }]} />
          : <div className="notice">{ramHint(i) || 'No RAM metrics in CloudWatch.'}</div>}</div>
      <div><div className="muted">Storage utilisation, last 6 months</div>
        {h.disks.length ? <LineChart title="Storage" startMs={start} stepMs={step} series={h.disks.map((d, k) => ({ name: d.name, color: COLORS[k % COLORS.length], values: d.values }))} />
          : <div className="notice">Enable CloudWatch metric to collect storage inputs</div>}</div>
    </div>
  );
}

const ramHint = (i) => (i.memory ? null : i.state !== 'running' ? 'Server is stopped' : ['NOT_INSTALLED', 'OFFLINE'].includes(i.ssm.status) ? 'Install and enable the SSM agent on this EC2 machine to collect RAM input' : 'Enable the CloudWatch agent memory metric (mem_used_percent) to collect RAM input');
const storageHint = (i) => (i.storage.usedGiB !== null && i.storage.freeGiB !== null ? null : i.state !== 'running' ? 'Server is stopped' : 'Enable CloudWatch metric to collect storage inputs');
const Hint = ({ t }) => <span className="pill warn" style={{ whiteSpace: 'normal' }}>{t}</span>;
const Badge = ({ kind, children }) => <span className={`pill ${kind}`}>{children}</span>;
const logBadge = (s) => ({
  ENABLED: <Badge kind="ok">Enabled</Badge>, DISABLED: <Badge kind="bad">Not enabled</Badge>, NOT_ENABLED: <Badge kind="bad">Not enabled</Badge>,
  NONE: <Badge kind="bad">Not enabled</Badge>, PARTIAL: <Badge kind="warn">Partial</Badge>, 'N/A': <Badge kind="ok">No load balancer</Badge>,
}[s] || <Badge kind="warn">Unknown</Badge>);
const healthBadge = (s) => (s === 'healthy' ? <Badge kind="ok">Healthy</Badge> : <Badge kind={s === 'unused' ? 'warn' : 'bad'}>{s || 'unknown'}</Badge>);
const ssmBadge = (s) => ({ ONLINE: <Badge kind="ok">SSM online</Badge>, OFFLINE: <Badge kind="warn">SSM offline</Badge>, NOT_INSTALLED: <Badge kind="bad">SSM not installed</Badge> }[s] || <Badge kind="warn">SSM unknown</Badge>);

function ServerDetail({ i, clientId }) {
  const st = i.storage;
  return (
    <div className="amc-detail">
      <History clientId={clientId} i={i} />
      <h4>Storage</h4>
      <p>{st.volumes.length} EBS volume(s), {st.provisionedGiB} GiB provisioned{st.usedGiB !== null ? `, about ${st.usedGiB} GiB used and ${st.freeGiB} GiB free` : ''}. {st.note && <span className="muted">{st.note}</span>}</p>
      <table><thead><tr><th>Volume</th><th>Device</th><th>Size</th><th>Type</th><th>Encrypted</th></tr></thead>
        <tbody>{st.volumes.map((v) => <tr key={v.volumeId}><td>{v.volumeId}</td><td>{v.device}</td><td>{v.sizeGiB} GiB</td><td>{v.type}</td><td>{v.encrypted ? 'Yes' : 'No'}</td></tr>)}</tbody></table>
      {st.filesystems.length > 0 && <p className="muted">Filesystems: {st.filesystems.map((f) => `${f.name} ${f.usedPercent}% used`).join(' · ')}</p>}
      <h4>Load balancer / Auto Scaling health</h4>
      {i.health.length ? (
        <table><thead><tr><th>Type</th><th>Load balancer / group</th><th>State</th><th>Reason</th></tr></thead>
          <tbody>{i.health.map((h, k) => <tr key={k}><td>{h.kind === 'asg' ? 'Auto Scaling' : h.kind === 'classic' ? 'Classic LB' : 'Target group'}</td><td>{[h.lb, h.group].filter(Boolean).join(' / ')}</td><td>{healthBadge(h.state)}</td><td>{h.reason || h.description}</td></tr>)}</tbody></table>
      ) : <p className="muted">Not attached to a load balancer or Auto Scaling group.</p>}
      {i.recommendations.map((r, k) => <div key={k} className="notice"><b>Recommendation:</b> {r}</div>)}
    </div>
  );
}

export function AmcOverview({ clientId }) {
  const [data, setData] = useState(null);
  const [err, setErr] = useState('');
  const [open, setOpen] = useState({});
  useEffect(() => { api.amc(clientId).then(setData).catch((e) => setErr(e.message)); }, [clientId]);
  if (err) return <div className="error">{err}</div>;
  if (!data) return <p className="muted">Loading AMC details…</p>;
  if (!data.amc) return <section className="card"><h2>AMC server details</h2><p className="muted">{data.message}</p></section>;
  const a = data.amc;
  if (a.failed) return <section className="card"><h2>AMC server details</h2><p className="muted">The AMC checks failed in the last scan. See the report warnings.</p></section>;
  const s = a.summary;
  return (
    <section className="card">
      <h2>AMC server details <span className="muted">(last scan {new Date(data.scannedAt).toLocaleString()})</span></h2>
      <p className="muted">{s.servers} server(s) · {s.memoryMissing} without RAM metrics · {s.ssmMissing} without SSM agent · {s.unhealthy} unhealthy behind a load balancer/ASG · {s.flowLogsGaps} without full VPC flow logs · {s.cloudtrailGaps} without CloudTrail</p>
      {!a.instances.length ? <p className="muted">No servers found.</p> : (
        <div className="tablewrap"><table>
          <thead><tr><th>Server</th><th>CPU avg (7d)</th><th>CPU peak (7d)</th><th>RAM avg (7d)</th><th>RAM peak (7d)</th><th>EBS</th><th>Assigned</th><th>Utilised</th><th>Available</th><th>VPC logs</th><th>LB logs</th><th>CloudTrail</th><th /></tr></thead>
          <tbody>
            {a.instances.map((i) => (
              <React.Fragment key={i.instanceId}>
                <tr>
                  <td><span className="server-name"><span className={`dot ${i.state}`} /><b>{i.name || i.instanceId}</b></span><div className="muted">{i.instanceId} · {i.instanceType} · {i.region}</div>{ssmBadge(i.ssm.status)}</td>
                  <td>{i.cpu ? `${i.cpu.average}%` : '—'}</td><td>{i.cpu ? `${i.cpu.peak}%` : '—'}</td>
                  {ramHint(i) ? <td colSpan="2"><Hint t={ramHint(i)} /></td> : <><td>{i.memory.average}%</td><td>{i.memory.peak}%</td></>}
                  <td>{i.storage.volumes.length}</td><td>{i.storage.provisionedGiB} GiB</td>
                  {storageHint(i) ? <td colSpan="2"><Hint t={storageHint(i)} /></td> : <><td>{i.storage.usedGiB} GiB</td><td>{i.storage.freeGiB} GiB</td></>}
                  <td>{logBadge(i.logging.vpcFlowLogs)}</td><td>{logBadge(i.logging.loadBalancerLogs)}</td><td>{logBadge(i.logging.cloudtrail)}</td>
                  <td><button onClick={() => setOpen({ ...open, [i.instanceId]: !open[i.instanceId] })}>{open[i.instanceId] ? 'Hide' : 'Details'}</button></td>
                </tr>
                {open[i.instanceId] && <tr><td colSpan="13"><ServerDetail i={i} clientId={clientId} /></td></tr>}
              </React.Fragment>
            ))}
          </tbody>
        </table></div>
      )}
    </section>
  );
}

/* ---------- Logs page ---------- */
const TABS = [['vpc', 'VPC flow logs'], ['cloudtrail', 'CloudTrail'], ['loadbalancer', 'Load balancer'], ['cloudfront', 'CloudFront']];
const DURATIONS = [['1h', '1 hour'], ['24h', '24 hours'], ['1w', '1 week'], ['15d', '15 days'], ['30d', '30 days']];
const label = { vpc: 'VPC flow logs', cloudtrail: 'CloudTrail', loadbalancer: 'Load balancer access logs', cloudfront: 'CloudFront access logs' };
const HELP = {
  vpc: 'VPCs without flow logs are listed but cannot be fetched.',
  cloudtrail: 'Pick a region. Logs come from the trail\'s S3 files when readable (management and data events), otherwise from CloudTrail event history (management events, last 90 days).',
  loadbalancer: 'Reads the access logs the load balancer writes to S3. Load balancers without access logs cannot be fetched.',
  cloudfront: 'Reads standard access logs from the S3 bucket configured on the distribution.',
};
const fmtBytes = (b) => (b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.ceil(b / 1024))} KB`);

export function LogsPage({ client, BackButton }) {
  const [src, setSrc] = useState(null);
  const [err, setErr] = useState('');
  const [tab, setTab] = useState('vpc');
  const [q, setQ] = useState('');
  const [sel, setSel] = useState({ vpc: [], cloudtrail: [], loadbalancer: [], cloudfront: [] });
  const [dlg, setDlg] = useState(null); // { types: {...}, region }
  const [duration, setDuration] = useState('24h');
  const [job, setJob] = useState(null);

  useEffect(() => { api.logSources(client.id).then(setSrc).catch((e) => setErr(e.message)); }, [client.id]);
  useEffect(() => {
    if (!job || job.status !== 'running') return undefined;
    const t = setInterval(() => api.logJob(client.id, job.id).then(setJob).catch((e) => setErr(e.message)), 2000);
    return () => clearInterval(t);
  }, [job, client.id]);

  const okRow = (r) => r.fetchable;
  const toggle = (type, key) => setSel((s) => ({ ...s, [type]: s[type].includes(key) ? s[type].filter((k) => k !== key) : [...s[type], key] }));
  const counts = useMemo(() => Object.fromEntries(TABS.map(([t]) => [t, sel[t].length])), [sel]);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  function openDialog(onlyTab) {
    const types = Object.fromEntries(TABS.map(([t]) => [t, onlyTab ? t === onlyTab : counts[t] > 0]));
    setDlg({ types, onlyTab, region: sel.cloudtrail[0] || (src?.cloudtrail || []).find((r) => r.region === 'ap-south-1')?.key || src?.cloudtrail?.[0]?.key || '' });
  }
  async function start() {
    setErr('');
    const selections = Object.fromEntries(TABS.map(([t]) => [t, !dlg.types[t] ? [] : t === 'cloudtrail' && dlg.onlyTab === 'cloudtrail' ? [dlg.region] : sel[t]]));
    if (dlg.types.cloudtrail && !selections.cloudtrail.length && dlg.region) selections.cloudtrail = [dlg.region];
    try { setJob(await api.fetchLogs(client.id, { selections, duration })); setDlg(null); } catch (e) { setErr(e.message); }
  }

  const rows = (src?.[tab] || []).filter((r) => !q || `${r.name || ''} ${r.vpcId || ''} ${r.region || ''} ${r.id || ''}`.toLowerCase().includes(q.toLowerCase()));
  const busy = job?.status === 'running';
  const trailInfo = (r) => (r.trails?.length ? `${r.trails.length} trail(s): ${r.trails.map((t) => t.name).slice(0, 2).join(', ')}` : 'No trail in this region, event history will be used');

  return (
    <>
      <div className="topbar"><BackButton fallback={`/client/${client.id}`} />
        <div className="grow"><h1>Logs</h1><p className="muted">{client.clientName} · account {client.accountId}</p></div>
        <div className="row-actions">
          {tab === 'cloudtrail' && <button className="primary" disabled={busy || !src} onClick={() => openDialog('cloudtrail')}>Fetch CloudTrail logs</button>}
          <button className={tab === 'cloudtrail' ? '' : 'primary'} disabled={!total || busy} onClick={() => openDialog(null)}>Fetch selected ({total})</button>
        </div>
      </div>
      {err && <div className="error" onClick={() => setErr('')}>{err}</div>}

      {job && (
        <section className="card job">
          <h2>Log export</h2>
          {busy && <><div className="bar"><i /></div><p className="muted">{job.progress}</p></>}
          {job.status === 'done' && <p><span className="pill ok">Ready</span> Your export is ready to download.</p>}
          {(job.status === 'failed' || job.status === 'cancelled') && <p><span className="pill bad">{job.status}</span> {job.progress}</p>}
          {job.files.length > 0 && <ul className="filelist">{job.files.map((f) => <li key={f.name}><span><b>{label[f.type]}</b> · {f.name}</span><span className="muted">{fmtBytes(f.bytes)} · {f.lines.toLocaleString()} lines</span></li>)}</ul>}
          {job.notes.map((n, k) => <div key={k} className="notice">{n}</div>)}
          <div className="row-actions" style={{ justifyContent: 'flex-start' }}>
            {busy && <button className="danger" onClick={() => api.cancelLogJob(client.id, job.id).then(setJob)}>Cancel</button>}
            {job.status === 'done' && job.download && <a className="btn word" href={`/api/clients/${client.id}/logs/jobs/${job.id}/download`} download>⬇ Download {job.files.length > 1 ? 'zip' : 'file'}</a>}
          </div>
          <span className="muted small">Exports are kept on the server for 24 hours.</span>
        </section>
      )}

      <section className="card">
        <div className="tabs">{TABS.map(([t, n]) => <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => { setTab(t); setQ(''); }}>{n}{counts[t] ? <span className="count">{counts[t]}</span> : null}</button>)}</div>
        <p className="muted" style={{ marginTop: 0 }}>{HELP[tab]}</p>
        {!src && !err && <><div className="bar"><i /></div><p className="muted">Looking up log sources in the account. This can take a minute.</p></>}
        {src && <>
          {src.warnings?.length > 0 && <div className="notice">{src.warnings.length} lookup warning(s), e.g. {src.warnings[0]}</div>}
          <div className="toolbar" style={{ marginTop: 12 }}>
            <input placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
            {(src[tab] || []).filter(okRow).length > 1 && <>
              <button onClick={() => setSel((s) => ({ ...s, [tab]: (src[tab] || []).filter(okRow).map((r) => r.key) }))}>Select all</button>
              <button onClick={() => setSel((s) => ({ ...s, [tab]: [] }))}>Clear</button></>}
          </div>
          {!rows.length ? <div className="empty">Nothing found.</div> : rows.map((r) => (
            <label key={r.key} className={`source-row ${okRow(r) ? '' : 'off'} ${sel[tab].includes(r.key) ? 'sel' : ''}`} style={{ flexDirection: 'row', alignItems: 'center', color: 'inherit', fontSize: 14 }}>
              <input type="checkbox" disabled={!okRow(r)} checked={sel[tab].includes(r.key)} onChange={() => toggle(tab, r.key)} />
              <span className="meta">
                <b>{tab === 'cloudtrail' ? r.region : (r.name || r.vpcId || r.id)}</b>
                <span className="muted small">
                  {tab === 'vpc' && `${r.vpcId}${r.isDefault ? ' · default VPC' : ''} · ${r.region}`}
                  {tab === 'cloudtrail' && trailInfo(r)}
                  {tab === 'loadbalancer' && `${r.type} · ${r.region}`}
                  {tab === 'cloudfront' && (r.aliases?.length ? r.aliases.join(', ') : r.id)}
                </span>
                {r.note && <span className="muted small"> · {r.note}</span>}
              </span>
              {tab === 'cloudtrail' ? <Badge kind={r.enabled ? 'ok' : 'warn'}>{r.enabled ? 'Trail' : 'Event history'}</Badge>
                : r.fetchable ? <Badge kind="ok">Logging on</Badge> : r.enabled ? <Badge kind="warn">Not readable</Badge> : <Badge kind="bad">Logging off</Badge>}
            </label>
          ))}
        </>}
      </section>

      {dlg && (
        <div className="modal-bg" onClick={() => setDlg(null)}><div className="modal" onClick={(e) => e.stopPropagation()}>
          <h2>{dlg.onlyTab === 'cloudtrail' ? 'Fetch CloudTrail logs' : 'Fetch logs'}</h2>
          {dlg.onlyTab === 'cloudtrail' ? (
            <label>Region<select value={dlg.region} onChange={(e) => setDlg({ ...dlg, region: e.target.value })}>
              {(src?.cloudtrail || []).map((r) => <option key={r.key} value={r.key}>{r.region}{r.enabled ? ' (trail)' : ''}</option>)}</select></label>
          ) : (
            <>
              <p className="muted" style={{ margin: 0 }}>Each log type becomes its own file; more than one type is delivered as a zip.</p>
              {TABS.map(([t]) => (
                <label key={t} className="check"><input type="checkbox" disabled={!counts[t]} checked={Boolean(dlg.types[t])} onChange={(e) => setDlg({ ...dlg, types: { ...dlg.types, [t]: e.target.checked } })} />
                  {label[t]} <span className="muted">({counts[t]} selected)</span></label>
              ))}
            </>
          )}
          <div><div className="muted small" style={{ marginBottom: 6, fontWeight: 650 }}>TIME PERIOD</div>
            <div className="chips">{DURATIONS.map(([v, n]) => <button key={v} type="button" className={`chip ${duration === v ? 'on' : ''}`} onClick={() => setDuration(v)}>{n}</button>)}</div></div>
          <div className="row-actions">
            <button onClick={() => setDlg(null)}>Cancel</button>
            <button className="primary" disabled={dlg.onlyTab === 'cloudtrail' ? !dlg.region : !Object.entries(dlg.types).some(([t, v]) => v && counts[t])} onClick={start}>Start fetch</button>
          </div>
        </div></div>
      )}
    </>
  );
}
