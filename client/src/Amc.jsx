import React, { useEffect, useMemo, useState } from 'react';
import { api } from './api.js';

const go = (path) => { window.location.hash = `#${path}`; };

/* ---------- small SVG line chart ---------- */
function LineChart({ series, startMs, title }) {
  const W = 520; const H = 170; const m = { l: 34, r: 10, t: 22, b: 24 };
  const w = W - m.l - m.r; const h = H - m.t - m.b;
  const n = Math.max(...series.map((s) => s.values.length), 1);
  const x = (i) => m.l + (n <= 1 ? 0 : (i / (n - 1)) * w);
  const y = (v) => m.t + h - (Math.min(v, 100) / 100) * h;
  const path = (vals) => { let d = ''; let pen = false; vals.forEach((v, i) => { if (v == null) { pen = false; return; } d += `${pen ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`; pen = true; }); return d; };
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ maxWidth: W, background: '#fff', border: '1px solid #e4e7eb', borderRadius: 6 }} role="img" aria-label={title}>
      {series.map((s, k) => <text key={s.name} x={m.l + 6 + k * 90} y="12" fontSize="10" fill={s.color}>■ {s.name}</text>)}
      {[0, 25, 50, 75, 100].map((v) => (
        <g key={v}><line x1={m.l} x2={W - m.r} y1={y(v)} y2={y(v)} stroke="#e4e7eb" /><text x={m.l - 4} y={y(v) + 3} textAnchor="end" fontSize="9" fill="#52606d">{v}%</text></g>
      ))}
      {Array.from({ length: Math.ceil(n / 24) }, (_, d) => (
        <text key={d} x={x(d * 24)} y={H - 8} fontSize="9" fill="#52606d">{new Date(startMs + d * 86400000).toISOString().slice(5, 10)}</text>
      ))}
      {series.map((s) => <path key={s.name} d={path(s.values)} fill="none" stroke={s.color} strokeWidth="1.5" strokeDasharray={s.dash ? '3 2' : undefined} />)}
    </svg>
  );
}

const Badge = ({ kind, children }) => <span className={`pill ${kind}`}>{children}</span>;
const logBadge = (s) => ({
  ENABLED: <Badge kind="ok">Enabled</Badge>, DISABLED: <Badge kind="bad">Not enabled</Badge>, NOT_ENABLED: <Badge kind="bad">Not enabled</Badge>,
  NONE: <Badge kind="bad">Not enabled</Badge>, PARTIAL: <Badge kind="warn">Partial</Badge>, 'N/A': <Badge kind="ok">No load balancer</Badge>,
}[s] || <Badge kind="warn">Unknown</Badge>);
const healthBadge = (s) => (s === 'healthy' ? <Badge kind="ok">Healthy</Badge> : <Badge kind={s === 'unused' ? 'warn' : 'bad'}>{s || 'unknown'}</Badge>);
const ssmBadge = (s) => ({ ONLINE: <Badge kind="ok">SSM online</Badge>, OFFLINE: <Badge kind="warn">SSM offline</Badge>, NOT_INSTALLED: <Badge kind="bad">SSM not installed</Badge> }[s] || <Badge kind="warn">SSM unknown</Badge>);

function ServerDetail({ i, period }) {
  const start = new Date(period.start).getTime();
  const st = i.storage;
  return (
    <div className="amc-detail">
      {i.state === 'running' ? (
        <div className="charts">
          <div><div className="muted">CPU, last 8 days{i.cpu ? ` (avg ${i.cpu.average}%, peak ${i.cpu.peak}%)` : ''}</div>
            {i.cpu ? <LineChart title="CPU" startMs={start} series={[{ name: 'CPU average', color: '#1a73e8', values: i.cpu.avg }, { name: 'CPU peak', color: '#d93025', values: i.cpu.max, dash: true }]} /> : <p className="muted">No CPU data returned.</p>}</div>
          <div><div className="muted">RAM, last 8 days{i.memory ? ` (avg ${i.memory.average}%, peak ${i.memory.peak}%)` : ''}</div>
            {i.memory ? <LineChart title="RAM" startMs={start} series={[{ name: 'RAM average', color: '#188038', values: i.memory.avg }, { name: 'RAM peak', color: '#f29900', values: i.memory.max, dash: true }]} /> : <p className="muted">No RAM metrics in CloudWatch.</p>}</div>
        </div>
      ) : <p className="muted">Server is not running; no recent metrics.</p>}
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
        <table>
          <thead><tr><th>Server</th><th>State</th><th>CPU avg/peak</th><th>RAM avg/peak</th><th>EBS</th><th>VPC flow logs</th><th>LB logs</th><th>CloudTrail</th><th /></tr></thead>
          <tbody>
            {a.instances.map((i) => (
              <React.Fragment key={i.instanceId}>
                <tr>
                  <td><b>{i.name || i.instanceId}</b><div className="muted">{i.instanceId} · {i.instanceType} · {i.region}</div>{ssmBadge(i.ssm.status)}</td>
                  <td>{i.state}</td>
                  <td>{i.cpu ? `${i.cpu.average}% / ${i.cpu.peak}%` : '—'}</td>
                  <td>{i.memory ? `${i.memory.average}% / ${i.memory.peak}%` : <span className="muted">not reported</span>}</td>
                  <td>{i.storage.volumes.length} · {i.storage.provisionedGiB} GiB</td>
                  <td>{logBadge(i.logging.vpcFlowLogs)}</td><td>{logBadge(i.logging.loadBalancerLogs)}</td><td>{logBadge(i.logging.cloudtrail)}</td>
                  <td><button onClick={() => setOpen({ ...open, [i.instanceId]: !open[i.instanceId] })}>{open[i.instanceId] ? 'Hide' : 'Details'}</button></td>
                </tr>
                {open[i.instanceId] && <tr><td colSpan="9"><ServerDetail i={i} period={a.period} /></td></tr>}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

/* ---------- Logs page ---------- */
const TABS = [['vpc', 'VPC'], ['cloudtrail', 'CloudTrail'], ['loadbalancer', 'Load balancer'], ['cloudfront', 'CloudFront']];
const DURATIONS = [['1h', '1 hour'], ['24h', '24 hours'], ['1w', '1 week'], ['15d', '15 days'], ['30d', '30 days']];
const label = { vpc: 'VPC flow logs', cloudtrail: 'CloudTrail', loadbalancer: 'Load balancer access logs', cloudfront: 'CloudFront access logs' };
const fmtBytes = (b) => (b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${Math.ceil(b / 1024)} KB`);

export function LogsPage({ client, BackButton }) {
  const [src, setSrc] = useState(null);
  const [err, setErr] = useState('');
  const [tab, setTab] = useState('vpc');
  const [sel, setSel] = useState({ vpc: [], cloudtrail: [], loadbalancer: [], cloudfront: [] });
  const [dlg, setDlg] = useState(false);
  const [types, setTypes] = useState({});
  const [duration, setDuration] = useState('24h');
  const [job, setJob] = useState(null);

  useEffect(() => { api.logSources(client.id).then(setSrc).catch((e) => setErr(e.message)); }, [client.id]);
  useEffect(() => {
    if (!job || job.status !== 'running') return undefined;
    const t = setInterval(() => api.logJob(client.id, job.id).then(setJob).catch((e) => setErr(e.message)), 2000);
    return () => clearInterval(t);
  }, [job, client.id]);

  const toggle = (type, key) => setSel((s) => ({ ...s, [type]: s[type].includes(key) ? s[type].filter((k) => k !== key) : [...s[type], key] }));
  const fetchable = (type) => (src?.[type] || []).filter((r) => type === 'cloudtrail' || r.fetchable);
  const counts = useMemo(() => Object.fromEntries(TABS.map(([t]) => [t, sel[t].length])), [sel]);

  function openDialog() { setTypes(Object.fromEntries(TABS.map(([t]) => [t, counts[t] > 0]))); setDlg(true); setJob(null); }
  async function start() {
    setErr('');
    const selections = Object.fromEntries(TABS.map(([t]) => [t, types[t] ? sel[t] : []]));
    try { setJob(await api.fetchLogs(client.id, { selections, duration })); setDlg(false); } catch (e) { setErr(e.message); }
  }

  const rows = src?.[tab] || [];
  return (
    <>
      <div className="topbar"><BackButton fallback={`/client/${client.id}`} /><div className="grow"><h1>Logs: {client.clientName}</h1><p className="muted">Select what to fetch, then choose the log types and the time period.</p></div>
        <div className="row-actions"><button className="primary" disabled={!Object.values(counts).some(Boolean) || job?.status === 'running'} onClick={openDialog}>Fetch logs</button></div></div>
      {err && <div className="error" onClick={() => setErr('')}>{err}</div>}

      {job && (
        <section className="card">
          <h2>Log export</h2>
          <p>{job.status === 'running' ? <>⏳ {job.progress}</> : job.status === 'done' ? '✅ Ready' : `${job.status}: ${job.progress}`}</p>
          {job.files.length > 0 && <ul>{job.files.map((f) => <li key={f.name}>{f.name} ({fmtBytes(f.bytes)}, {f.lines} lines)</li>)}</ul>}
          {job.notes.map((n, k) => <div key={k} className="notice">{n}</div>)}
          <div className="row-actions">
            {job.status === 'running' && <button className="danger" onClick={() => api.cancelLogJob(client.id, job.id).then(setJob)}>Cancel</button>}
            {job.status === 'done' && job.download && <a className="btn word" href={`/api/clients/${client.id}/logs/jobs/${job.id}/download`} download>Download {job.files.length > 1 ? 'zip' : 'file'}</a>}
          </div>
          <p className="muted">Exports are kept on the server for 24 hours.</p>
        </section>
      )}

      <section className="card">
        <div className="tabs">{TABS.map(([t, n]) => <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>{n}{counts[t] ? ` (${counts[t]})` : ''}</button>)}</div>
        {!src && !err && <p className="muted">Looking up log sources in the account (this can take a minute)…</p>}
        {src && <>
          {src.warnings?.length > 0 && <div className="notice">{src.warnings.length} lookup warning(s), e.g. {src.warnings[0]}</div>}
          {tab === 'cloudtrail' && <p className="muted">Fetches management events from the CloudTrail event history of the trail's region (up to 90 days). Data events need the trail's S3 bucket and are not included.</p>}
          {tab === 'loadbalancer' && <p className="muted">Reads the access logs the load balancer writes to S3. Load balancers without access logs cannot be fetched.</p>}
          {tab === 'cloudfront' && <p className="muted">Reads standard (legacy) access logs from the S3 bucket configured on the distribution.</p>}
          {!rows.length ? <p className="muted">Nothing found.</p> : (
            <table>
              <thead><tr><th /><th>Name</th><th>Region</th><th>Logging</th><th /></tr></thead>
              <tbody>{rows.map((r) => {
                const ok = tab === 'cloudtrail' || r.fetchable;
                const key = r.key;
                return (
                  <tr key={key} className={ok ? '' : 'muted-row'}>
                    <td><input type="checkbox" disabled={!ok} checked={sel[tab].includes(key)} onChange={() => toggle(tab, key)} /></td>
                    <td><b>{r.name || r.vpcId || r.id}</b>{tab === 'vpc' && <div className="muted">{r.vpcId}{r.isDefault ? ' · default VPC' : ''}</div>}{tab === 'cloudfront' && r.aliases?.length > 0 && <div className="muted">{r.aliases.join(', ')}</div>}</td>
                    <td>{r.region || 'global'}</td>
                    <td>{tab === 'cloudtrail' ? <Badge kind="ok">Trail</Badge> : r.fetchable ? <Badge kind="ok">Enabled</Badge> : r.enabled ? <Badge kind="warn">Enabled, not readable</Badge> : <Badge kind="bad">Not enabled</Badge>}{r.note && <div className="muted">{r.note}</div>}</td>
                    <td className="muted">{ok ? '' : 'Cannot fetch'}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          )}
          {fetchable(tab).length > 1 && <div className="row-actions" style={{ marginTop: 8 }}>
            <button onClick={() => setSel((s) => ({ ...s, [tab]: fetchable(tab).map((r) => r.key) }))}>Select all</button>
            <button onClick={() => setSel((s) => ({ ...s, [tab]: [] }))}>Clear</button></div>}
        </>}
      </section>

      {dlg && (
        <div className="modal-bg"><div className="modal">
          <h2>Fetch logs</h2>
          <p className="muted">Pick the log types to include. Each type becomes its own file; more than one type is delivered as a zip.</p>
          {TABS.map(([t]) => (
            <label key={t} className="check"><input type="checkbox" disabled={!counts[t]} checked={Boolean(types[t])} onChange={(e) => setTypes({ ...types, [t]: e.target.checked })} /> {label[t]} <span className="muted">({counts[t]} selected)</span></label>
          ))}
          <label className="check">Duration&nbsp;
            <select value={duration} onChange={(e) => setDuration(e.target.value)}>{DURATIONS.map(([v, n]) => <option key={v} value={v}>{n}</option>)}</select></label>
          <div className="row-actions">
            <button onClick={() => setDlg(false)}>Cancel</button>
            <button className="primary" disabled={!Object.values(types).some(Boolean)} onClick={start}>Start fetch</button>
          </div>
        </div></div>
      )}
    </>
  );
}
