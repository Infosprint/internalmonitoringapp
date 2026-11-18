'use strict';
// Extra checks that run only for AMC partners. Everything here is read-only (Describe/List/Get calls):
// server inventory, 8-day CPU and memory history, EBS storage, load balancer / target group / Auto Scaling health,
// and whether VPC flow logs, load balancer logs and CloudTrail are enabled for each server.
const {
  EC2Client, DescribeInstancesCommand, DescribeVolumesCommand, DescribeVpcsCommand, DescribeFlowLogsCommand,
  DescribeSubnetsCommand, DescribeNetworkInterfacesCommand,
} = require('@aws-sdk/client-ec2');
const { CloudWatchClient, GetMetricDataCommand, ListMetricsCommand } = require('@aws-sdk/client-cloudwatch');
const { SSMClient, DescribeInstanceInformationCommand } = require('@aws-sdk/client-ssm');
const { AutoScalingClient, DescribeAutoScalingGroupsCommand } = require('@aws-sdk/client-auto-scaling');
const {
  ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand, DescribeLoadBalancerAttributesCommand,
  DescribeTargetGroupsCommand, DescribeTargetHealthCommand,
} = require('@aws-sdk/client-elastic-load-balancing-v2');
const {
  ElasticLoadBalancingClient, DescribeLoadBalancersCommand: DescribeClassicLbs,
  DescribeLoadBalancerAttributesCommand: DescribeClassicAttrs, DescribeInstanceHealthCommand,
} = require('@aws-sdk/client-elastic-load-balancing');
const { CloudTrailClient, DescribeTrailsCommand, GetTrailStatusCommand } = require('@aws-sdk/client-cloudtrail');
const { evaluateVpcs } = require('./network');
const { MAX_ATTEMPTS, mapLimit, collect, errMsg, tagMap, chunk } = require('./aws');

const HOUR_S = 3600;
const RANGES = { '1w': 7, '1m': 30 }; // days of CPU/RAM history
const REGION_CONCURRENCY = 3;
const MAX_TARGET_GROUPS = 150;

const round1 = (n) => Math.round(n * 10) / 10;
const mean = (a) => { const v = a.filter((x) => x !== null && x !== undefined); return v.length ? round1(v.reduce((s, x) => s + x, 0) / v.length) : null; };
const peak = (a) => { const v = a.filter((x) => x !== null && x !== undefined); return v.length ? round1(Math.max(...v)) : null; };

/* ---------- CloudWatch helpers ---------- */

// queries: [{ id, namespace, metric, dims: [{Name,Value}], stat, period }] -> Map(id -> { timestamps, values })
async function getMetrics(cw, queries, startTime, endTime) {
  const out = new Map();
  for (const part of chunk(queries, 100)) {
    let token;
    do {
      const res = await cw.send(new GetMetricDataCommand({
        StartTime: startTime, EndTime: endTime, ScanBy: 'TimestampAscending', NextToken: token,
        MetricDataQueries: part.map((q) => ({
          Id: q.id, ReturnData: true,
          MetricStat: { Metric: { Namespace: q.namespace, MetricName: q.metric, Dimensions: q.dims }, Period: q.period, Stat: q.stat },
        })),
      }));
      for (const r of res.MetricDataResults || []) {
        const cur = out.get(r.Id) || { timestamps: [], values: [] };
        cur.timestamps.push(...(r.Timestamps || []));
        cur.values.push(...(r.Values || []));
        out.set(r.Id, cur);
      }
      token = res.NextToken;
    } while (token);
  }
  return out;
}

async function listMetricDefs(cw, namespace, metricName, maxPages = 40) {
  const out = [];
  let token; let pages = 0;
  do {
    const r = await cw.send(new ListMetricsCommand({ Namespace: namespace, MetricName: metricName, NextToken: token }));
    out.push(...(r.Metrics || []));
    token = r.NextToken; pages += 1;
  } while (token && pages < maxPages);
  return out;
}

const dimValue = (m, name) => (m.Dimensions || []).find((d) => d.Name === name)?.Value;

// Where memory and disk metrics can come from (CloudWatch agent first, older monitoring scripts after)
const MEMORY_SOURCES = [
  { namespace: 'CWAgent', metric: 'mem_used_percent', label: 'Memory used %' },
  { namespace: 'CWAgent', metric: 'Memory % Committed Bytes In Use', label: 'Memory committed %' },
  { namespace: 'System/Linux', metric: 'MemoryUtilization', label: 'Memory used %' },
  { namespace: 'Windows/Default', metric: 'MemoryUtilization', label: 'Memory used %' },
];
const DISK_SOURCES = [
  { namespace: 'CWAgent', metric: 'disk_used_percent', pick: (m) => ({ name: dimValue(m, 'path') || dimValue(m, 'device'), fstype: dimValue(m, 'fstype'), usedFrom: 'used' }) },
  { namespace: 'CWAgent', metric: 'LogicalDisk % Free Space', pick: (m) => ({ name: dimValue(m, 'instance'), usedFrom: 'free' }) },
  { namespace: 'System/Linux', metric: 'DiskSpaceUtilization', pick: (m) => ({ name: dimValue(m, 'MountPath'), usedFrom: 'used' }) },
];
const SKIP_FS = new Set(['tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'iso9660', 'proc', 'sysfs']);
const SKIP_PATH = /^(\/snap|\/run|\/sys|\/dev|\/proc|\/var\/lib\/docker|\/boot\/efi)/;

/* ---------- one region ---------- */

async function amcRegion(region, credentials, win) {
  const out = { region, instances: [], balancers: [], asgs: [], vpcLogging: [], trails: [], warnings: [] };
  const opts = { region, credentials, maxAttempts: MAX_ATTEMPTS };
  const ec2 = new EC2Client(opts);
  const cw = new CloudWatchClient(opts);
  const attempt = async (label, fn, fallback) => { try { return await fn(); } catch (e) { out.warnings.push(`${region}: ${label}: ${errMsg(e)}`); return fallback; } };

  // 1. instances
  const reservations = await collect(ec2, (t) => new DescribeInstancesCommand({
    Filters: [{ Name: 'instance-state-name', Values: ['pending', 'running', 'stopping', 'stopped'] }], NextToken: t,
  }), (r) => r.Reservations);
  const raw = reservations.flatMap((r) => r.Instances || []);
  if (!raw.length) return out;
  const ids = raw.map((i) => i.InstanceId);

  const inst = new Map(raw.map((i) => [i.InstanceId, {
    region, instanceId: i.InstanceId, name: tagMap(i.Tags).Name || '', state: i.State?.Name, instanceType: i.InstanceType,
    platform: i.PlatformDetails || i.Platform || 'Linux/UNIX', az: i.Placement?.AvailabilityZone, privateIp: i.PrivateIpAddress || null,
    publicIp: i.PublicIpAddress || null, vpcId: i.VpcId || null, subnetId: i.SubnetId || null, launchTime: i.LaunchTime,
    hasInstanceProfile: Boolean(i.IamInstanceProfile),
    volumeMap: Object.fromEntries((i.BlockDeviceMappings || []).filter((b) => b.Ebs).map((b) => [b.Ebs.VolumeId, { device: b.DeviceName, deleteOnTermination: b.Ebs.DeleteOnTermination }])),
  }]));

  // 2. EBS volumes
  const volumes = (await attempt('EBS volumes', async () => {
    const list = [];
    for (const part of chunk(ids, 150)) {
      list.push(...await collect(ec2, (t) => new DescribeVolumesCommand({ Filters: [{ Name: 'attachment.instance-id', Values: part }], NextToken: t }), (r) => r.Volumes));
    }
    return list;
  }, [])) || [];
  for (const v of volumes) {
    for (const a of v.Attachments || []) {
      const i = inst.get(a.InstanceId);
      if (!i) continue;
      (i.volumes ||= []).push({
        volumeId: v.VolumeId, device: a.Device, sizeGiB: v.Size, type: v.VolumeType, iops: v.Iops || null, encrypted: Boolean(v.Encrypted), state: v.State,
        deleteOnTermination: i.volumeMap[v.VolumeId]?.deleteOnTermination ?? null,
      });
    }
  }

  // 3. SSM agent status
  const ssmInfo = new Map();
  await attempt('SSM agent status', async () => {
    const ssm = new SSMClient(opts);
    for (const part of chunk(ids, 50)) {
      let token;
      do {
        const r = await ssm.send(new DescribeInstanceInformationCommand({ Filters: [{ Key: 'InstanceIds', Values: part }], NextToken: token, MaxResults: 50 }));
        for (const x of r.InstanceInformationList || []) {
          ssmInfo.set(x.InstanceId, { pingStatus: x.PingStatus, agentVersion: x.AgentVersion, platformName: x.PlatformName, lastPing: x.LastPingDateTime });
        }
        token = r.NextToken;
      } while (token);
    }
  }, null).then((r) => { if (r === null) out.ssmUnknown = true; });

  // 4. CPU, 8 days, hourly average and peak
  const cpu = new Map();
  await attempt('CPU metrics', async () => {
    const qs = ids.flatMap((id, k) => ['Average', 'Maximum'].map((stat) => ({
      id: `${stat === 'Average' ? 'a' : 'm'}${k}`, namespace: 'AWS/EC2', metric: 'CPUUtilization', dims: [{ Name: 'InstanceId', Value: id }], stat, period: HOUR_S,
    })));
    const res = await getMetrics(cw, qs, win.start, win.end);
    ids.forEach((id, k) => cpu.set(id, { avg: res.get(`a${k}`), max: res.get(`m${k}`) }));
  }, null);

  // 5. memory and disk metrics published by the CloudWatch agent (or the older monitoring scripts)
  const memDefs = new Map(); // instanceId -> { source, dims }
  const diskDefs = new Map(); // instanceId -> [{ name, usedFrom, dims }]
  const wanted = new Set(ids);
  await attempt('Memory/disk metric discovery', async () => {
    for (const src of MEMORY_SOURCES) {
      const defs = await listMetricDefs(cw, src.namespace, src.metric);
      for (const m of defs) {
        const id = dimValue(m, 'InstanceId');
        if (id && wanted.has(id) && !memDefs.has(id)) memDefs.set(id, { source: src, dims: m.Dimensions });
      }
    }
    for (const src of DISK_SOURCES) {
      const defs = await listMetricDefs(cw, src.namespace, src.metric);
      for (const m of defs) {
        const id = dimValue(m, 'InstanceId');
        if (!id || !wanted.has(id)) continue;
        const p = src.pick(m);
        if (!p.name || p.name === '_Total' || SKIP_FS.has(p.fstype) || SKIP_PATH.test(p.name)) continue;
        const list = diskDefs.get(id) || [];
        if (list.length < 8 && !list.some((x) => x.name === p.name)) list.push({ ...p, namespace: src.namespace, metric: src.metric, dims: m.Dimensions });
        diskDefs.set(id, list);
      }
    }
  }, null);

  // optional byte-level disk metrics (disk_total / disk_used) when the agent is configured to publish them
  const byteDefs = new Map(); // instanceId -> Map(path -> { total, used })
  await attempt('Disk size metrics', async () => {
    for (const [metric, field] of [['disk_total', 'total'], ['disk_used', 'used']]) {
      for (const m of await listMetricDefs(cw, 'CWAgent', metric)) {
        const id = dimValue(m, 'InstanceId'); const p = dimValue(m, 'path');
        if (!id || !wanted.has(id) || !p || SKIP_FS.has(dimValue(m, 'fstype')) || SKIP_PATH.test(p)) continue;
        const per = byteDefs.get(id) || new Map();
        const cur = per.get(p) || {};
        cur[field] = m.Dimensions; per.set(p, cur); byteDefs.set(id, per);
      }
    }
  }, null);
  const bytesNow = new Map(); // `${id}|${path}|${field}` -> bytes
  const byteQs = [];
  for (const [id, per] of byteDefs) for (const [p, f] of per) for (const field of ['total', 'used']) if (f.total && f.used) byteQs.push({ key: `${id}|${p}|${field}`, id: `b${byteQs.length}`, namespace: 'CWAgent', metric: field === 'total' ? 'disk_total' : 'disk_used', dims: f[field], stat: 'Average', period: 300 });
  if (byteQs.length) {
    await attempt('Disk size values', async () => {
      const res = await getMetrics(cw, byteQs, new Date(win.end.getTime() - 3 * 3600 * 1000), win.end);
      for (const q of byteQs) {
        const r = res.get(q.id);
        if (!r || !r.values.length) continue;
        let latest = 0; let val = r.values[0];
        r.timestamps.forEach((t, k) => { const ms = new Date(t).getTime(); if (ms >= latest) { latest = ms; val = r.values[k]; } });
        bytesNow.set(q.key, val);
      }
    }, null);
  }

  const mem = new Map();
  const memIds = [...memDefs.keys()];
  if (memIds.length) {
    await attempt('Memory history', async () => {
      const qs = memIds.flatMap((id, k) => ['Average', 'Maximum'].map((stat) => {
        const d = memDefs.get(id);
        return { id: `${stat === 'Average' ? 'a' : 'm'}${k}`, namespace: d.source.namespace, metric: d.source.metric, dims: d.dims, stat, period: HOUR_S };
      }));
      const res = await getMetrics(cw, qs, win.start, win.end);
      memIds.forEach((id, k) => mem.set(id, { avg: res.get(`a${k}`), max: res.get(`m${k}`) }));
    }, null);
  }

  const diskNow = new Map(); // `${id}|${name}` -> latest used %
  const diskQs = [];
  for (const [id, list] of diskDefs) list.forEach((d, k) => diskQs.push({ key: `${id}|${d.name}`, id: `d${diskQs.length}`, namespace: d.namespace, metric: d.metric, dims: d.dims, stat: 'Average', period: 300, usedFrom: d.usedFrom }));
  if (diskQs.length) {
    await attempt('Disk usage', async () => {
      const res = await getMetrics(cw, diskQs, new Date(win.end.getTime() - 3 * 3600 * 1000), win.end);
      for (const q of diskQs) {
        const r = res.get(q.id);
        if (!r || !r.values.length) continue;
        let latest = 0; let val = r.values[0];
        r.timestamps.forEach((t, k) => { const ms = new Date(t).getTime(); if (ms >= latest) { latest = ms; val = r.values[k]; } });
        diskNow.set(q.key, q.usedFrom === 'free' ? 100 - val : val);
      }
    }, null);
  }

  // 6. Auto Scaling groups
  await attempt('Auto Scaling groups', async () => {
    const asg = new AutoScalingClient(opts);
    const groups = [];
    let token;
    do {
      const r = await asg.send(new DescribeAutoScalingGroupsCommand({ NextToken: token }));
      groups.push(...(r.AutoScalingGroups || []));
      token = r.NextToken;
    } while (token);
    for (const g of groups) {
      out.asgs.push({
        region, name: g.AutoScalingGroupName, desired: g.DesiredCapacity, min: g.MinSize, max: g.MaxSize,
        targetGroupArns: g.TargetGroupARNs || [], classicLbs: g.LoadBalancerNames || [],
        instances: (g.Instances || []).map((x) => ({ instanceId: x.InstanceId, health: x.HealthStatus, lifecycle: x.LifecycleState, az: x.AvailabilityZone })),
      });
    }
  }, null);

  // 7. Application / Network load balancers: target health + access-log setting
  const byIp = new Map(raw.filter((i) => i.PrivateIpAddress).map((i) => [i.PrivateIpAddress, i.InstanceId]));
  await attempt('Load balancers (ALB/NLB)', async () => {
    const elb = new ElasticLoadBalancingV2Client(opts);
    const lbs = [];
    let marker;
    do {
      const r = await elb.send(new DescribeLoadBalancersCommand({ Marker: marker }));
      lbs.push(...(r.LoadBalancers || []));
      marker = r.NextMarker;
    } while (marker);
    const lbByArn = new Map();
    await mapLimit(lbs.filter((l) => l.Type === 'application' || l.Type === 'network'), 5, async (lb) => {
      let logging = null; let bucket = null;
      try {
        const a = await elb.send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: lb.LoadBalancerArn }));
        const get = (k) => (a.Attributes || []).find((x) => x.Key === k)?.Value;
        logging = get('access_logs.s3.enabled') === 'true';
        bucket = logging ? get('access_logs.s3.bucket') : null;
      } catch (e) { out.warnings.push(`${region}: access-log setting of ${lb.LoadBalancerName}: ${errMsg(e)}`); }
      const entry = { region, name: lb.LoadBalancerName, type: lb.Type === 'application' ? 'Application' : 'Network', scheme: lb.Scheme, vpcId: lb.VpcId, loggingEnabled: logging, logBucket: bucket, groups: [] };
      lbByArn.set(lb.LoadBalancerArn, entry);
      out.balancers.push(entry);
    });
    const tgs = [];
    let m2;
    do {
      const r = await elb.send(new DescribeTargetGroupsCommand({ Marker: m2 }));
      tgs.push(...(r.TargetGroups || []));
      m2 = r.NextMarker;
    } while (m2);
    const relevant = tgs.filter((t) => (t.LoadBalancerArns || []).some((a) => lbByArn.has(a))).slice(0, MAX_TARGET_GROUPS);
    if (tgs.length > relevant.length && relevant.length === MAX_TARGET_GROUPS) out.warnings.push(`${region}: only the first ${MAX_TARGET_GROUPS} target groups were checked`);
    await mapLimit(relevant, 5, async (tg) => {
      let targets = [];
      try {
        const h = await elb.send(new DescribeTargetHealthCommand({ TargetGroupArn: tg.TargetGroupArn }));
        targets = (h.TargetHealthDescriptions || []).map((d) => {
          const tid = d.Target?.Id;
          const instanceId = tg.TargetType === 'instance' ? tid : byIp.get(tid) || null;
          return { targetId: tid, port: d.Target?.Port, instanceId, state: d.TargetHealth?.State, reason: d.TargetHealth?.Reason || '', description: d.TargetHealth?.Description || '' };
        });
      } catch (e) { out.warnings.push(`${region}: health of target group ${tg.TargetGroupName}: ${errMsg(e)}`); }
      const group = { kind: 'targetGroup', arn: tg.TargetGroupArn, name: tg.TargetGroupName, protocol: tg.Protocol, port: tg.Port, targetType: tg.TargetType, targets };
      for (const a of tg.LoadBalancerArns || []) lbByArn.get(a)?.groups.push(group);
    });
  }, null);

  // 8. Classic load balancers
  await attempt('Load balancers (Classic)', async () => {
    const elb = new ElasticLoadBalancingClient(opts);
    const lbs = [];
    let marker;
    do {
      const r = await elb.send(new DescribeClassicLbs({ Marker: marker }));
      lbs.push(...(r.LoadBalancerDescriptions || []));
      marker = r.NextMarker;
    } while (marker);
    await mapLimit(lbs, 5, async (lb) => {
      let logging = null; let bucket = null; let states = [];
      try {
        const a = await elb.send(new DescribeClassicAttrs({ LoadBalancerName: lb.LoadBalancerName }));
        logging = Boolean(a.LoadBalancerAttributes?.AccessLog?.Enabled);
        bucket = logging ? a.LoadBalancerAttributes.AccessLog.S3BucketName : null;
      } catch (e) { out.warnings.push(`${region}: access-log setting of ${lb.LoadBalancerName}: ${errMsg(e)}`); }
      try {
        if ((lb.Instances || []).length) {
          const h = await elb.send(new DescribeInstanceHealthCommand({ LoadBalancerName: lb.LoadBalancerName }));
          states = h.InstanceStates || [];
        }
      } catch (e) { out.warnings.push(`${region}: health of ${lb.LoadBalancerName}: ${errMsg(e)}`); }
      out.balancers.push({
        region, name: lb.LoadBalancerName, type: 'Classic', scheme: lb.Scheme, vpcId: lb.VPCId, loggingEnabled: logging, logBucket: bucket,
        groups: [{ kind: 'classic', name: lb.LoadBalancerName, targets: states.map((s) => ({ targetId: s.InstanceId, instanceId: s.InstanceId, state: s.State === 'InService' ? 'healthy' : 'unhealthy', reason: s.ReasonCode || '', description: s.Description || '' })) }],
      });
    });
  }, null);

  // 9. VPC flow logs for the VPCs that host servers
  await attempt('VPC flow logs', async () => {
    const vpcIds = new Set(raw.map((i) => i.VpcId).filter(Boolean));
    const [vpcs, flowLogs, subnets, enis] = await Promise.all([
      collect(ec2, (t) => new DescribeVpcsCommand({ NextToken: t }), (r) => r.Vpcs),
      collect(ec2, (t) => new DescribeFlowLogsCommand({ NextToken: t }), (r) => r.FlowLogs),
      collect(ec2, (t) => new DescribeSubnetsCommand({ NextToken: t }), (r) => r.Subnets),
      collect(ec2, (t) => new DescribeNetworkInterfacesCommand({ NextToken: t }), (r) => r.NetworkInterfaces),
    ]);
    const mine = vpcs.filter((v) => vpcIds.has(v.VpcId));
    const notFull = new Map(evaluateVpcs({ vpcs: mine, flowLogs, subnets, enis }).map((v) => [v.vpcId, v]));
    for (const v of mine) {
      const bad = notFull.get(v.VpcId);
      out.vpcLogging.push({ region, vpcId: v.VpcId, name: tagMap(v.Tags).Name || '', status: bad ? bad.status : 'ENABLED', note: bad?.note || '' });
    }
  }, null);

  // 10. CloudTrail coverage of this region
  await attempt('CloudTrail', async () => {
    const ct = new CloudTrailClient(opts);
    const r = await ct.send(new DescribeTrailsCommand({ includeShadowTrails: true }));
    for (const t of r.trailList || []) {
      let logging = null;
      try { logging = (await ct.send(new GetTrailStatusCommand({ Name: t.TrailARN }))).IsLogging; } catch { /* status unknown */ }
      out.trails.push({
        name: t.Name, arn: t.TrailARN, homeRegion: t.HomeRegion, multiRegion: Boolean(t.IsMultiRegionTrail), organization: Boolean(t.IsOrganizationTrail),
        isLogging: logging, s3Bucket: t.S3BucketName || null, cloudWatchLogsGroup: t.CloudWatchLogsLogGroupArn || null, logValidation: Boolean(t.LogFileValidationEnabled),
      });
    }
  }, null);

  /* ---------- assemble per-instance rows ---------- */
  const regionTrails = out.trails.filter((t) => t.multiRegion || t.homeRegion === region);
  const loggingTrails = regionTrails.filter((t) => t.isLogging === true);
  const trailStatus = out.warnings.some((w) => w.includes('CloudTrail:')) ? 'UNKNOWN' : loggingTrails.length ? 'ENABLED' : 'NOT_ENABLED';
  const vpcStatus = new Map(out.vpcLogging.map((v) => [v.vpcId, v]));

  for (const [id, i] of inst) {
    const health = [];
    for (const lb of out.balancers) {
      for (const g of lb.groups) {
        for (const t of g.targets) if (t.instanceId === id) health.push({ kind: g.kind, lb: lb.name, group: g.name, state: t.state, reason: t.reason, description: t.description });
      }
    }
    for (const g of out.asgs) {
      const m = g.instances.find((x) => x.instanceId === id);
      if (m) health.push({ kind: 'asg', group: g.name, state: m.health === 'Healthy' && m.lifecycle === 'InService' ? 'healthy' : 'unhealthy', reason: `${m.health}, ${m.lifecycle}` });
    }
    const attachedLbs = [...new Set(health.filter((h) => h.kind !== 'asg').map((h) => h.lb))];
    const lbRows = attachedLbs.map((n) => ({ name: n, enabled: out.balancers.find((b) => b.name === n)?.loggingEnabled ?? null }));
    const lbLogs = !lbRows.length ? 'N/A' : lbRows.every((x) => x.enabled === true) ? 'ENABLED' : lbRows.some((x) => x.enabled === false) ? 'DISABLED' : 'UNKNOWN';

    const running = i.state === 'running';
    const ssm = ssmInfo.get(id);
    const ssmState = out.ssmUnknown ? 'UNKNOWN' : ssm ? (ssm.pingStatus === 'Online' ? 'ONLINE' : 'OFFLINE') : 'NOT_INSTALLED';
    const series = (m) => {
      const fill = (r) => { const a = new Array(win.buckets).fill(null); (r?.timestamps || []).forEach((t, k) => { const idx = Math.floor((new Date(t).getTime() - win.start.getTime()) / (HOUR_S * 1000)); if (idx >= 0 && idx < win.buckets) a[idx] = round1(r.values[k]); }); return a; };
      if (!m || !m.avg) return null;
      const avg = fill(m.avg); const max = fill(m.max);
      return { avg, max, average: mean(avg), peak: peak(max) };
    };
    const cpuS = series(cpu.get(id));
    const memS = series(mem.get(id));
    const memSource = memDefs.get(id)?.source;

    const filesystems = (diskDefs.get(id) || []).map((d) => ({ name: d.name, usedPercent: diskNow.has(`${id}|${d.name}`) ? round1(diskNow.get(`${id}|${d.name}`)) : null })).filter((f) => f.usedPercent !== null);
    const vols = i.volumes || [];
    const provisioned = vols.reduce((s, v) => s + (v.sizeGiB || 0), 0);
    // Used/free space can be worked out only when one volume holds the filesystem(s); with several volumes the agent
    // does not say which filesystem sits on which volume, so only the per-filesystem percentages are shown.
    let usedGiB = null; let freeGiB = null; let storageNote = '';
    const GIB = 1024 ** 3;
    const paths = [...(byteDefs.get(id)?.keys() || [])].filter((p) => bytesNow.has(`${id}|${p}|total`) && bytesNow.has(`${id}|${p}|used`));
    if (paths.length) {
      const tot = paths.reduce((a, p) => a + bytesNow.get(`${id}|${p}|total`), 0) / GIB;
      const used = paths.reduce((a, p) => a + bytesNow.get(`${id}|${p}|used`), 0) / GIB;
      usedGiB = round1(used); freeGiB = round1(Math.max(tot - used, 0));
    } else if (vols.length === 1 && filesystems.length) {
      const root = filesystems.find((f) => f.name === '/' || /^C:?$/i.test(f.name)) || filesystems[0];
      usedGiB = round1((root.usedPercent / 100) * vols[0].sizeGiB);
      freeGiB = round1(vols[0].sizeGiB - usedGiB);
    } else if (vols.length > 1 && filesystems.length) storageNote = 'Several volumes are attached; usage is shown per filesystem because the agent does not say which volume each one is on.';
    else if (running && !filesystems.length) storageNote = 'Disk usage inside the server is not reported to CloudWatch.';

    const recs = [];
    if (running && !memS) {
      recs.push(ssmState === 'ONLINE'
        ? 'Memory (RAM) metrics are not reaching CloudWatch. Install the Amazon CloudWatch agent on this server (it can be pushed through Systems Manager) and configure it to publish memory usage (mem_used_percent), so RAM pressure and out-of-memory risks become visible.'
        : 'The SSM agent is not reporting and CloudWatch is not receiving memory (RAM) metrics. Install and enable the SSM agent (with an instance profile that allows Systems Manager) and the Amazon CloudWatch agent configured to publish memory usage (mem_used_percent), so RAM pressure and out-of-memory risks become visible.');
    }
    if (running && !filesystems.length) recs.push('Add disk usage (disk_used_percent) to the CloudWatch agent configuration so free space is monitored before a volume fills up.');

    out.instances.push({
      region, instanceId: id, name: i.name, state: i.state, instanceType: i.instanceType, platform: i.platform, az: i.az, privateIp: i.privateIp, publicIp: i.publicIp,
      vpcId: i.vpcId, subnetId: i.subnetId, launchTime: i.launchTime, hasInstanceProfile: i.hasInstanceProfile,
      ssm: { status: ssmState, agentVersion: ssm?.agentVersion || null, lastPing: ssm?.lastPing || null },
      cpu: cpuS,
      memory: memS ? { ...memS, source: memSource.label } : null,
      storage: { volumes: vols, provisionedGiB: provisioned, usedGiB, freeGiB, filesystems, note: storageNote },
      health,
      logging: {
        vpcFlowLogs: i.vpcId ? vpcStatus.get(i.vpcId)?.status || 'UNKNOWN' : 'UNKNOWN', vpcFlowLogsNote: vpcStatus.get(i.vpcId)?.note || '',
        loadBalancerLogs: lbLogs, loadBalancers: lbRows,
        cloudtrail: trailStatus, trails: loggingTrails.map((t) => t.name),
      },
      recommendations: recs,
    });
  }
  return out;
}

/* ---------- whole account ---------- */

async function scanAmc({ credentials, regions, range = '1w', onProgress = () => {} }) {
  const days = RANGES[range] || 7;
  const now = Date.now();
  const end = new Date(Math.floor(now / 3600000) * 3600000 + 3600000);
  const win = { start: new Date(end.getTime() - days * 24 * 3600000), end, days, buckets: days * 24 };
  const warnings = [];
  let done = 0;
  const results = await mapLimit(regions, REGION_CONCURRENCY, async (region) => {
    try {
      const r = await amcRegion(region, credentials, win);
      done += 1;
      onProgress(`AMC details [${done}/${regions.length}] ${region}: ${r.instances.length} server(s)`);
      return r;
    } catch (e) {
      done += 1;
      warnings.push(`${region}: AMC checks failed: ${errMsg(e)}`);
      return { region, instances: [], balancers: [], asgs: [], vpcLogging: [], trails: [], warnings: [] };
    }
  });
  results.forEach((r) => warnings.push(...r.warnings));

  const instances = results.flatMap((r) => r.instances);
  const seenTrails = new Map();
  results.flatMap((r) => r.trails).forEach((t) => { if (!seenTrails.has(t.arn)) seenTrails.set(t.arn, t); });
  const running = instances.filter((i) => i.state === 'running');
  const unhealthy = instances.filter((i) => i.health.some((h) => h.state && h.state !== 'healthy' && h.state !== 'unused'));
  return {
    period: { start: win.start.toISOString(), end: win.end.toISOString(), periodSeconds: HOUR_S, points: win.buckets, days, range },
    instances,
    loadBalancers: results.flatMap((r) => r.balancers).filter((b) => b.groups.some((g) => g.targets.length) || b.loggingEnabled !== null),
    autoScalingGroups: results.flatMap((r) => r.asgs),
    vpcLogging: results.flatMap((r) => r.vpcLogging),
    cloudtrail: { trails: [...seenTrails.values()] },
    summary: {
      servers: instances.length, running: running.length,
      memoryMissing: running.filter((i) => !i.memory).length,
      diskMissing: running.filter((i) => !i.storage.filesystems.length).length,
      ssmMissing: running.filter((i) => i.ssm.status === 'NOT_INSTALLED').length,
      highCpu: running.filter((i) => (i.cpu?.average ?? 0) >= 80 || (i.cpu?.peak ?? 0) >= 95).length,
      unhealthy: unhealthy.length,
      flowLogsGaps: instances.filter((i) => i.logging.vpcFlowLogs !== 'ENABLED').length,
      lbLogGaps: instances.filter((i) => i.logging.loadBalancerLogs === 'DISABLED').length,
      cloudtrailGaps: instances.filter((i) => i.logging.cloudtrail === 'NOT_ENABLED').length,
      provisionedGiB: instances.reduce((s, i) => s + i.storage.provisionedGiB, 0),
    },
    warnings,
  };
}

module.exports = { scanAmc, RANGES };
