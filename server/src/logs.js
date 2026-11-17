'use strict';
// Log discovery and export for AMC clients. Everything here only reads from the customer account.
// Logs are pulled from wherever the customer already stores them (S3 buckets or CloudWatch Logs) and written to
// files under exports/<job>/ on this server. Several log types in one request become one file each, zipped.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { once } = require('events');
const yazl = require('yazl');
const { EC2Client, DescribeVpcsCommand, DescribeFlowLogsCommand, DescribeSubnetsCommand, DescribeNetworkInterfacesCommand } = require('@aws-sdk/client-ec2');
const { CloudWatchLogsClient, FilterLogEventsCommand } = require('@aws-sdk/client-cloudwatch-logs');
const { CloudTrailClient, LookupEventsCommand, DescribeTrailsCommand } = require('@aws-sdk/client-cloudtrail');
const { S3Client, ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');
const { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand, DescribeLoadBalancerAttributesCommand } = require('@aws-sdk/client-elastic-load-balancing-v2');
const { ElasticLoadBalancingClient, DescribeLoadBalancersCommand: DescribeClassic, DescribeLoadBalancerAttributesCommand: DescribeClassicAttrs } = require('@aws-sdk/client-elastic-load-balancing');
const { CloudFrontClient, ListDistributionsCommand, GetDistributionConfigCommand } = require('@aws-sdk/client-cloudfront');
const { MAX_ATTEMPTS, mapLimit, collect, errMsg, tagMap, createCredentialProvider, listRegions } = require('./aws');
const { evaluateVpcs } = require('./network');

const ROOT = path.join(__dirname, '..', '..');
const EXPORT_DIR = process.env.EXPORT_DIR || path.join(ROOT, 'exports');
const AUDIT_FILE = path.join(ROOT, 'data', 'audit.log');
const DURATIONS = { '1h': 3600e3, '24h': 24 * 3600e3, '1w': 7 * 24 * 3600e3, '15d': 15 * 24 * 3600e3, '30d': 30 * 24 * 3600e3 };
const TYPES = ['vpc', 'cloudtrail', 'loadbalancer', 'cloudfront'];
const MAX_BYTES_PER_FILE = Number(process.env.LOG_MAX_BYTES || 300 * 1024 * 1024);
const MAX_S3_OBJECTS = Number(process.env.LOG_MAX_OBJECTS || 3000);
const MAX_CT_EVENTS = 100000;
const KEEP_MS = 24 * 3600e3;
const jobs = new Map();

const audit = (rec) => { try { fs.mkdirSync(path.dirname(AUDIT_FILE), { recursive: true }); fs.appendFileSync(AUDIT_FILE, JSON.stringify({ at: new Date().toISOString(), ...rec }) + '\n'); } catch { /* best effort */ } };
const safe = (s) => String(s).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 80);
const s3Parts = (arn) => { const m = /^arn:aws[a-z-]*:s3:::([^/]+)\/?(.*)$/.exec(arn || ''); return m ? { bucket: m[1], prefix: m[2].replace(/\/+$/, '') } : null; };
const joinKey = (...p) => p.filter(Boolean).join('/').replace(/\/{2,}/g, '/');
const days = (start, end) => { const out = []; for (let t = Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()); t <= end.getTime(); t += 86400e3) { const d = new Date(t); out.push([d.getUTCFullYear(), String(d.getUTCMonth() + 1).padStart(2, '0'), String(d.getUTCDate()).padStart(2, '0')]); } return out; };

/* ---------- discovery: what can be fetched ---------- */

async function listSources(client) {
  const credentials = createCredentialProvider(client, 'infosprint-monitoring-logs');
  const regions = await listRegions(credentials);
  const out = { vpc: [], cloudtrail: [], loadbalancer: [], cloudfront: [], warnings: [] };
  await mapLimit(regions, 4, async (region) => {
    const opts = { region, credentials, maxAttempts: MAX_ATTEMPTS };
    const warn = (what, e) => out.warnings.push(`${region}: ${what}: ${errMsg(e)}`);
    try {
      const ec2 = new EC2Client(opts);
      const vpcs = await collect(ec2, (t) => new DescribeVpcsCommand({ NextToken: t }), (r) => r.Vpcs);
      if (vpcs.length) {
        const [flowLogs, subnets, enis] = await Promise.all([
          collect(ec2, (t) => new DescribeFlowLogsCommand({ NextToken: t }), (r) => r.FlowLogs),
          collect(ec2, (t) => new DescribeSubnetsCommand({ NextToken: t }), (r) => r.Subnets),
          collect(ec2, (t) => new DescribeNetworkInterfacesCommand({ NextToken: t }), (r) => r.NetworkInterfaces),
        ]);
        const gaps = new Map(evaluateVpcs({ vpcs, flowLogs, subnets, enis }).map((v) => [v.vpcId, v]));
        for (const v of vpcs) {
          const logs = flowLogs.filter((f) => f.FlowLogStatus === 'ACTIVE' && (f.ResourceId === v.VpcId || subnets.some((s) => s.VpcId === v.VpcId && s.SubnetId === f.ResourceId) || enis.some((n) => n.VpcId === v.VpcId && n.NetworkInterfaceId === f.ResourceId)))
            .map((f) => ({ id: f.FlowLogId, destinationType: f.LogDestinationType, destination: f.LogDestination || null, logGroup: f.LogGroupName || null, scope: f.ResourceId, traffic: f.TrafficType }));
          const usable = logs.filter((l) => (l.destinationType === 'cloud-watch-logs' && l.logGroup) || (l.destinationType === 's3' && l.destination));
          out.vpc.push({
            key: `${region}|${v.VpcId}`, region, vpcId: v.VpcId, name: tagMap(v.Tags).Name || '', isDefault: v.IsDefault,
            status: gaps.has(v.VpcId) ? gaps.get(v.VpcId).status : 'ENABLED', flowLogs: logs, enabled: logs.length > 0, fetchable: usable.length > 0,
            note: logs.length && !usable.length ? 'Flow logs go to a destination this tool cannot read (e.g. Kinesis Firehose).' : '',
          });
        }
      }
    } catch (e) { warn('VPCs', e); }
    try {
      const ct = new CloudTrailClient(opts);
      const r = await ct.send(new DescribeTrailsCommand({ includeShadowTrails: false }));
      if (region === regions[0] || (r.trailList || []).length) {
        for (const t of r.trailList || []) if (t.HomeRegion === region) out.cloudtrail.push({ key: `${region}|${t.Name}`, region, name: t.Name, multiRegion: Boolean(t.IsMultiRegionTrail), bucket: t.S3BucketName || null });
      }
    } catch (e) { warn('CloudTrail', e); }
    try {
      const elb = new ElasticLoadBalancingV2Client(opts);
      const lbs = await collect(elb, (m) => new DescribeLoadBalancersCommand({ Marker: m }), (r) => r.LoadBalancers, 'NextMarker', 'Marker');
      await mapLimit(lbs, 5, async (lb) => {
        const a = await elb.send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: lb.LoadBalancerArn })).catch(() => null);
        const get = (k) => (a?.Attributes || []).find((x) => x.Key === k)?.Value;
        const on = get('access_logs.s3.enabled') === 'true';
        out.loadbalancer.push({ key: `${region}|${lb.LoadBalancerName}`, region, name: lb.LoadBalancerName, type: lb.Type, enabled: on, fetchable: on, bucket: on ? get('access_logs.s3.bucket') : null, prefix: on ? get('access_logs.s3.prefix') || '' : '' });
      });
      const cl = new ElasticLoadBalancingClient(opts);
      const classic = await collect(cl, (m) => new DescribeClassic({ Marker: m }), (r) => r.LoadBalancerDescriptions, 'NextMarker', 'Marker');
      await mapLimit(classic, 5, async (lb) => {
        const a = await cl.send(new DescribeClassicAttrs({ LoadBalancerName: lb.LoadBalancerName })).catch(() => null);
        const al = a?.LoadBalancerAttributes?.AccessLog;
        out.loadbalancer.push({ key: `${region}|${lb.LoadBalancerName}`, region, name: lb.LoadBalancerName, type: 'classic', enabled: Boolean(al?.Enabled), fetchable: Boolean(al?.Enabled), bucket: al?.Enabled ? al.S3BucketName : null, prefix: al?.Enabled ? al.S3BucketPrefix || '' : '' });
      });
    } catch (e) { warn('Load balancers', e); }
  });
  try {
    const cf = new CloudFrontClient({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });
    let marker; const items = [];
    do { const r = await cf.send(new ListDistributionsCommand({ Marker: marker })); items.push(...(r.DistributionList?.Items || [])); marker = r.DistributionList?.NextMarker; } while (marker);
    await mapLimit(items, 5, async (d) => {
      const c = await cf.send(new GetDistributionConfigCommand({ Id: d.Id })).catch(() => null);
      const l = c?.DistributionConfig?.Logging;
      const bucket = l?.Enabled ? String(l.Bucket || '').replace(/\.s3(\..+)?\.amazonaws\.com$/, '') : null;
      out.cloudfront.push({ key: d.Id, id: d.Id, name: d.DomainName, aliases: d.Aliases?.Items || [], enabled: Boolean(l?.Enabled), fetchable: Boolean(l?.Enabled && bucket), bucket, prefix: l?.Prefix || '' });
    });
  } catch (e) { out.warnings.push(`CloudFront: ${errMsg(e)}`); }
  // CloudTrail event history works without any trail, so it is always fetchable per region
  const ctRegions = new Set(out.cloudtrail.map((t) => t.region));
  out.cloudtrailRegions = regions.filter((r) => ctRegions.has(r));
  for (const k of TYPES) if (Array.isArray(out[k])) out[k].sort((a, b) => `${a.region || ''}${a.name || a.id}`.localeCompare(`${b.region || ''}${b.name || b.id}`));
  return out;
}

/* ---------- writers ---------- */

function makeSink(file, ctx) {
  const stream = fs.createWriteStream(file);
  let bytes = 0; let lines = 0;
  return {
    async write(text) {
      if (ctx.cancelled) throw Object.assign(new Error('Cancelled'), { cancelled: true });
      const b = Buffer.byteLength(text);
      if (bytes + b > MAX_BYTES_PER_FILE) { ctx.truncated = true; return false; }
      bytes += b; lines += (text.match(/\n/g) || []).length;
      if (!stream.write(text)) await once(stream, 'drain');
      return true;
    },
    async close() { stream.end(); await once(stream, 'finish'); return { bytes, lines }; },
    get bytes() { return bytes; },
  };
}

async function s3Collect(s3, bucket, prefixes, startMs, endMs, nameFilter, sink, ctx, label) {
  let objects = 0;
  for (const prefix of prefixes) {
    let token;
    do {
      const r = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix, ContinuationToken: token }));
      const keys = (r.Contents || []).filter((o) => o.LastModified.getTime() >= startMs && o.LastModified.getTime() <= endMs + 15 * 60e3 && (!nameFilter || nameFilter(o.Key)) && o.Size > 0)
        .sort((a, b) => a.LastModified - b.LastModified);
      for (const o of keys) {
        if (ctx.cancelled) throw Object.assign(new Error('Cancelled'), { cancelled: true });
        if (objects >= MAX_S3_OBJECTS) { ctx.truncated = true; return; }
        objects += 1; ctx.progress(`${label}: reading file ${objects}`);
        const got = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: o.Key }));
        const src = /\.gz$/.test(o.Key) ? got.Body.pipe(zlib.createGunzip()) : got.Body;
        src.setEncoding('utf8');
        let ok = true;
        for await (const chunk of src) { if (!(await sink.write(chunk))) { ok = false; break; } }
        if (!ok) return;
      }
      token = r.NextContinuationToken;
    } while (token);
  }
}

const s3For = (credentials, region) => new S3Client({ region: region || 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS, followRegionRedirects: true });

async function fetchVpc(client, credentials, sel, win, sink, ctx) {
  const all = (await listSources(client)).vpc;
  const targets = all.filter((v) => (sel || []).includes(v.key));
  if (!targets.length) throw new Error('Select at least one VPC');
  for (const v of targets) {
    if (!v.fetchable) { await sink.write(`# ${v.region} ${v.vpcId}: flow logs are not enabled or not readable, skipped\n`); continue; }
    for (const fl of v.flowLogs) {
      await sink.write(`# --- ${v.region} ${v.vpcId} flow log ${fl.id} (${fl.destinationType}) ---\n`);
      if (fl.destinationType === 'cloud-watch-logs' && fl.logGroup) {
        const cwl = new CloudWatchLogsClient({ region: v.region, credentials, maxAttempts: MAX_ATTEMPTS });
        let token;
        do {
          const r = await cwl.send(new FilterLogEventsCommand({ logGroupName: fl.logGroup, startTime: win.start, endTime: win.end, nextToken: token }));
          for (const e of r.events || []) { if (!(await sink.write(`${new Date(e.timestamp).toISOString()} ${e.message}\n`))) return; }
          ctx.progress(`VPC ${v.vpcId}: ${sink.bytes} bytes`);
          token = r.nextToken;
        } while (token);
      } else if (fl.destinationType === 's3') {
        const p = s3Parts(fl.destination);
        const s3 = s3For(credentials, v.region);
        const acct = client.accountId;
        const prefixes = days(new Date(win.start), new Date(win.end)).map(([y, m, d]) => joinKey(p.prefix, 'AWSLogs', acct, 'vpcflowlogs', v.region, y, m, d) + '/');
        await s3Collect(s3, p.bucket, prefixes, win.start, win.end, (k) => k.includes(fl.id), sink, ctx, `VPC ${v.vpcId}`);
      }
    }
  }
}

async function fetchCloudTrail(client, credentials, sel, win, sink, ctx) {
  const regions = (sel && sel.length ? sel : []).map((k) => k.split('|')[0]);
  const uniq = [...new Set(regions)];
  if (!uniq.length) throw new Error('Select at least one CloudTrail region');
  let events = 0;
  for (const region of uniq) {
    const ct = new CloudTrailClient({ region, credentials, maxAttempts: 8 });
    await sink.write(`# --- CloudTrail management events, ${region} ---\n`);
    let token;
    do {
      const r = await ct.send(new LookupEventsCommand({ StartTime: new Date(win.start), EndTime: new Date(win.end), MaxResults: 50, NextToken: token }));
      for (const e of r.Events || []) { events += 1; if (events > MAX_CT_EVENTS) { ctx.truncated = true; return; } if (!(await sink.write((e.CloudTrailEvent || JSON.stringify({ EventId: e.EventId, EventName: e.EventName })) + '\n'))) return; }
      ctx.progress(`CloudTrail ${region}: ${events} events`);
      token = r.NextToken;
      await new Promise((res) => setTimeout(res, 550)); // LookupEvents allows 2 requests per second
    } while (token);
  }
}

async function fetchLoadBalancer(client, credentials, sel, win, sink, ctx) {
  const all = (await listSources(client)).loadbalancer;
  const targets = all.filter((l) => (sel || []).includes(l.key));
  if (!targets.length) throw new Error('Select at least one load balancer');
  for (const lb of targets) {
    if (!lb.fetchable) { await sink.write(`# ${lb.region} ${lb.name}: access logs are not enabled, skipped\n`); continue; }
    await sink.write(`# --- ${lb.region} ${lb.type} load balancer ${lb.name} ---\n`);
    const s3 = s3For(credentials, lb.region);
    const prefixes = days(new Date(win.start), new Date(win.end)).map(([y, m, d]) => joinKey(lb.prefix, 'AWSLogs', client.accountId, 'elasticloadbalancing', lb.region, y, m, d) + '/');
    await s3Collect(s3, lb.bucket, prefixes, win.start, win.end, (k) => (lb.type === 'classic' ? k.includes(`_${lb.name}_`) : k.includes(`.${lb.name}.`) || k.includes(lb.name)), sink, ctx, `LB ${lb.name}`);
  }
}

async function fetchCloudFront(client, credentials, sel, win, sink, ctx) {
  const all = (await listSources(client)).cloudfront;
  const targets = all.filter((d) => (sel || []).includes(d.key));
  if (!targets.length) throw new Error('Select at least one CloudFront distribution');
  for (const d of targets) {
    if (!d.fetchable) { await sink.write(`# ${d.id}: logging is not enabled, skipped\n`); continue; }
    await sink.write(`# --- CloudFront distribution ${d.id} (${d.name}) ---\n`);
    const s3 = s3For(credentials, 'us-east-1');
    await s3Collect(s3, d.bucket, [`${d.prefix ? d.prefix.replace(/\/*$/, '/') : ''}${d.id}.`], win.start, win.end, null, sink, ctx, `CloudFront ${d.id}`);
  }
}

const FETCHERS = { vpc: fetchVpc, cloudtrail: fetchCloudTrail, loadbalancer: fetchLoadBalancer, cloudfront: fetchCloudFront };
const EXT = { vpc: 'log', cloudtrail: 'jsonl', loadbalancer: 'log', cloudfront: 'log' };

/* ---------- jobs ---------- */

function createJob({ client, user, request }) {
  const types = Object.keys(request.selections || {}).filter((t) => TYPES.includes(t) && (request.selections[t] || []).length);
  if (!types.length) throw Object.assign(new Error('Choose at least one log type and resource'), { status: 400 });
  const ms = DURATIONS[request.duration];
  if (!ms) throw Object.assign(new Error('Duration must be 1h, 24h, 1w, 15d or 30d'), { status: 400 });
  if (jobs.size && [...jobs.values()].filter((j) => j.status === 'running' && j.clientId === client.id).length >= 1) throw Object.assign(new Error('A log fetch for this account is already running'), { status: 409 });
  const id = crypto.randomBytes(12).toString('hex');
  const end = Date.now();
  const job = { id, clientId: client.id, userId: user.id, status: 'running', types, duration: request.duration, progress: 'Starting', startedAt: new Date().toISOString(), files: [], notes: [], truncated: false, cancelled: false };
  jobs.set(id, job);
  audit({ event: 'fetch-start', user: user.email, client: client.clientName, jobId: id, types, duration: request.duration });
  run(job, client, request, { start: end - ms, end }).catch(() => {});
  return job;
}

async function run(job, client, request, win) {
  const dir = path.join(EXPORT_DIR, job.id);
  fs.mkdirSync(dir, { recursive: true });
  const credentials = createCredentialProvider(client, 'infosprint-monitoring-logs');
  const ctx = { cancelled: false, truncated: false, progress: (m) => { job.progress = m; } };
  Object.defineProperty(ctx, 'cancelled', { get: () => job.cancelled });
  try {
    for (const type of job.types) {
      ctx.truncated = false;
      const name = `${safe(client.clientName)}_${type}_${request.duration}_${new Date(win.end).toISOString().slice(0, 16).replace(/[-:T]/g, '')}.${EXT[type]}`;
      const sink = makeSink(path.join(dir, name), ctx);
      job.progress = `Fetching ${type} logs`;
      try {
        await sink.write(`# Infosprint Monitoring log export: ${client.clientName} (${client.accountId}), ${type}, ${new Date(win.start).toISOString()} to ${new Date(win.end).toISOString()}\n`);
        await FETCHERS[type](client, credentials, request.selections[type], win, sink, ctx);
      } catch (e) {
        if (e.cancelled) throw e;
        await sink.write(`# ERROR: ${errMsg(e)}\n`).catch(() => {});
        job.notes.push(`${type}: ${errMsg(e)}`);
      }
      const st = await sink.close();
      if (ctx.truncated) job.notes.push(`${type}: stopped at the size/file limit, so the earliest or latest part of the period may be missing. Use a shorter duration for a complete export.`);
      job.files.push({ type, name, bytes: st.bytes, lines: st.lines });
    }
    if (job.files.length > 1) {
      const zipName = `${safe(client.clientName)}_logs_${job.duration}.zip`;
      await new Promise((resolve, reject) => {
        const z = new yazl.ZipFile();
        job.files.forEach((f) => z.addFile(path.join(dir, f.name), f.name));
        z.end();
        const out = fs.createWriteStream(path.join(dir, zipName));
        z.outputStream.pipe(out).on('close', resolve).on('error', reject);
      });
      job.download = zipName;
    } else job.download = job.files[0].name;
    job.status = 'done'; job.progress = 'Ready to download';
  } catch (e) {
    job.status = e.cancelled ? 'cancelled' : 'failed'; job.progress = e.cancelled ? 'Cancelled' : errMsg(e);
  }
  job.finishedAt = new Date().toISOString();
  audit({ event: 'fetch-end', jobId: job.id, status: job.status, files: job.files.map((f) => `${f.name}:${f.bytes}`) });
}

const publicJob = (j) => ({ id: j.id, status: j.status, progress: j.progress, types: j.types, duration: j.duration, files: j.files, notes: j.notes, download: j.download || null, startedAt: j.startedAt, finishedAt: j.finishedAt || null });
const getJob = (id, clientId) => { const j = jobs.get(id); return j && j.clientId === clientId ? j : null; };
const downloadPath = (job) => (job && job.status === 'done' && job.download ? path.join(EXPORT_DIR, job.id, job.download) : null);

function cleanup() {
  try {
    for (const [id, j] of jobs) if (j.status !== 'running' && Date.now() - new Date(j.finishedAt || j.startedAt).getTime() > KEEP_MS) jobs.delete(id);
    if (!fs.existsSync(EXPORT_DIR)) return;
    for (const d of fs.readdirSync(EXPORT_DIR)) {
      const p = path.join(EXPORT_DIR, d);
      if (!jobs.has(d) && Date.now() - fs.statSync(p).mtimeMs > KEEP_MS) fs.rmSync(p, { recursive: true, force: true });
    }
  } catch { /* ignore */ }
}
setInterval(cleanup, 3600e3).unref();
cleanup();

module.exports = { listSources, createJob, getJob, publicJob, downloadPath, audit, DURATIONS, TYPES, s3Parts, days, joinKey, EXPORT_DIR };
