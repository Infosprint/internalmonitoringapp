'use strict';
// RDS inventory: every DB instance in every region with status, pending updates, 7-day CPU / RAM / storage
// utilisation and configuration recommendations. Read-only.
const { RDSClient, DescribeDBInstancesCommand, DescribePendingMaintenanceActionsCommand } = require('@aws-sdk/client-rds');
const { EC2Client, DescribeInstanceTypesCommand } = require('@aws-sdk/client-ec2');
const { CloudWatchClient, GetMetricDataCommand } = require('@aws-sdk/client-cloudwatch');
const { MAX_ATTEMPTS, mapLimit, errMsg, chunk } = require('./aws');

const GIB = 1024 ** 3;
const DAYS = 7;
const r1 = (n) => Math.round(n * 10) / 10;
const mean = (a) => { const v = a.filter((x) => x != null); return v.length ? r1(v.reduce((s, x) => s + x, 0) / v.length) : null; };

async function pages(client, make, pick, markerKey = 'Marker', nextKey = 'Marker') {
  const out = []; let m;
  do { const r = await client.send(make(m)); out.push(...(pick(r) || [])); m = r[nextKey]; } while (m);
  return out;
}

// Turns raw instance data into recommendations; pure so it can be tested.
function rdsRecommendations(i) {
  const recs = [];
  if (i.pendingActions.length) recs.push(`Apply the pending update${i.pendingActions.length > 1 ? 's' : ''}: ${i.pendingActions.map((a) => `${a.action}${a.autoAppliedAfter ? ` (auto-applies ${String(a.autoAppliedAfter).slice(0, 10)})` : ''}`).join('; ')}. Schedule it in the maintenance window.`);
  if (i.status && i.status !== 'available') recs.push(`The instance status is "${i.status}". Check the RDS events and logs to find out why it is not available.`);
  if (!i.multiAz && !i.isReadReplica) recs.push('Enable Multi-AZ so the database fails over automatically if an Availability Zone fails.');
  if ((i.backupRetentionDays ?? 0) < 7 && !i.isReadReplica) recs.push(`Increase backup retention to at least 7 days (currently ${i.backupRetentionDays ?? 0}).`);
  if (i.publiclyAccessible) recs.push('Turn off public accessibility and reach the database through the VPC, a VPN or a bastion host.');
  if (!i.encrypted) recs.push('Storage is not encrypted. Create an encrypted snapshot copy and restore from it to encrypt the database.');
  if (!i.deletionProtection) recs.push('Enable deletion protection to stop accidental deletion.');
  if (!i.autoMinorVersionUpgrade) recs.push('Enable automatic minor version upgrades so security patches are applied in the maintenance window.');
  if (i.cpu && i.cpu.peak >= 90) recs.push(`CPU peaked at ${i.cpu.peak}% in the last ${DAYS} days. Review slow queries or move to a larger instance class.`);
  if (i.ram && i.ram.peak >= 90) recs.push(`Memory use peaked at ${i.ram.peak}%. Consider a larger instance class or tuning memory-heavy queries.`);
  if (i.storage && i.storage.usedPercent !== null && i.storage.usedPercent >= 85) recs.push(`Storage is ${i.storage.usedPercent}% used. Increase allocated storage or enable storage autoscaling.`);
  if (i.storage && i.storage.autoscaling === false && !i.aurora) recs.push('Storage autoscaling is off. Enable it (set a maximum) so the database does not run out of space.');
  return recs;
}

async function scanRdsRegion(region, credentials) {
  const out = { region, instances: [], warnings: [] };
  const opts = { region, credentials, maxAttempts: MAX_ATTEMPTS };
  const rds = new RDSClient(opts);
  const raw = await pages(rds, (m) => new DescribeDBInstancesCommand({ Marker: m }), (r) => r.DBInstances);
  if (!raw.length) return out;

  const pending = new Map();
  try {
    for (const p of await pages(rds, (m) => new DescribePendingMaintenanceActionsCommand({ Marker: m }), (r) => r.PendingMaintenanceActions)) {
      pending.set(p.ResourceIdentifier, (p.PendingMaintenanceActionDetails || []).map((d) => ({ action: d.Description || d.Action, autoAppliedAfter: d.AutoAppliedAfterDate || d.CurrentApplyDate || null })));
    }
  } catch (e) { out.warnings.push(`${region}: pending maintenance: ${errMsg(e)}`); }

  // memory size of each instance class (db.r5.large -> EC2 type r5.large), to turn FreeableMemory into a percentage
  const memGiB = new Map();
  try {
    const ec2 = new EC2Client(opts);
    const classes = [...new Set(raw.map((d) => d.DBInstanceClass.replace(/^db\./, '')).filter((c) => !/^serverless/.test(c)))];
    for (const part of chunk(classes, 90)) {
      let r;
      try { r = await ec2.send(new DescribeInstanceTypesCommand({ InstanceTypes: part })); } catch { continue; }
      for (const t of r.InstanceTypes || []) memGiB.set(`db.${t.InstanceType}`, (t.MemoryInfo?.SizeInMiB || 0) / 1024);
    }
  } catch (e) { out.warnings.push(`${region}: instance class memory: ${errMsg(e)}`); }

  // 7-day metrics: daily buckets are enough for an average and a peak
  const cw = new CloudWatchClient(opts);
  const end = new Date(); const start = new Date(end.getTime() - DAYS * 86400000);
  const qs = [];
  raw.forEach((d, k) => {
    const dims = [{ Name: 'DBInstanceIdentifier', Value: d.DBInstanceIdentifier }];
    for (const [tag, metric, stat] of [['ca', 'CPUUtilization', 'Average'], ['cm', 'CPUUtilization', 'Maximum'], ['ma', 'FreeableMemory', 'Average'], ['mm', 'FreeableMemory', 'Minimum'], ['sa', 'FreeStorageSpace', 'Average'], ['sm', 'FreeStorageSpace', 'Minimum']]) {
      qs.push({ id: `${tag}${k}`, metric, dims, stat });
    }
  });
  const res = new Map();
  try {
    for (const part of chunk(qs, 400)) {
      const r = await cw.send(new GetMetricDataCommand({ StartTime: start, EndTime: end, MetricDataQueries: part.map((q) => ({ Id: q.id, ReturnData: true, MetricStat: { Metric: { Namespace: 'AWS/RDS', MetricName: q.metric, Dimensions: q.dims }, Period: 86400, Stat: q.stat } })) }));
      for (const x of r.MetricDataResults || []) res.set(x.Id, x.Values || []);
    }
  } catch (e) { out.warnings.push(`${region}: RDS metrics: ${errMsg(e)}`); }

  raw.forEach((d, k) => {
    const v = (tag) => res.get(`${tag}${k}`) || [];
    const aurora = /aurora/i.test(d.Engine || '');
    const total = memGiB.get(d.DBInstanceClass) || null;
    const freeAvg = mean(v('ma')); const freeMin = v('mm').length ? Math.min(...v('mm')) : null;
    const ram = total && freeAvg !== null ? { totalGiB: r1(total), average: r1(100 - (freeAvg / GIB / total) * 100), peak: freeMin !== null ? r1(100 - (freeMin / GIB / total) * 100) : null } : null;
    const cpu = v('ca').length ? { average: mean(v('ca')), peak: r1(Math.max(...v('cm'))) } : null;
    const alloc = d.AllocatedStorage || 0;
    const freeS = mean(v('sa')); const freeSMin = v('sm').length ? Math.min(...v('sm')) : null;
    let storage = null;
    if (!aurora && alloc) {
      storage = { allocatedGiB: alloc, autoscaling: Boolean(d.MaxAllocatedStorage), maxAllocatedGiB: d.MaxAllocatedStorage || null, usedGiB: null, freeGiB: null, usedPercent: null };
      if (freeS !== null) {
        const free = freeS / GIB; const minFree = freeSMin !== null ? freeSMin / GIB : free;
        storage.freeGiB = r1(free); storage.usedGiB = r1(Math.max(alloc - minFree, 0)); storage.usedPercent = r1(Math.max(alloc - minFree, 0) / alloc * 100);
      }
    }
    const inst = {
      region, id: d.DBInstanceIdentifier, engine: d.Engine, engineVersion: d.EngineVersion, instanceClass: d.DBInstanceClass, status: d.DBInstanceStatus, aurora,
      multiAz: Boolean(d.MultiAZ), isReadReplica: Boolean(d.ReadReplicaSourceDBInstanceIdentifier), publiclyAccessible: Boolean(d.PubliclyAccessible), encrypted: Boolean(d.StorageEncrypted),
      deletionProtection: Boolean(d.DeletionProtection), autoMinorVersionUpgrade: Boolean(d.AutoMinorVersionUpgrade), backupRetentionDays: d.BackupRetentionPeriod,
      az: d.AvailabilityZone, vpcId: d.DBSubnetGroup?.VpcId || null, maintenanceWindow: d.PreferredMaintenanceWindow, caCertificate: d.CACertificateIdentifier || null,
      pendingActions: pending.get(d.DBInstanceArn) || [], cpu, ram, storage,
    };
    inst.health = inst.status === 'available' ? 'HEALTHY' : ['stopped', 'stopping'].includes(inst.status) ? 'STOPPED' : 'ATTENTION';
    inst.recommendations = rdsRecommendations(inst);
    out.instances.push(inst);
  });
  return out;
}

async function scanRds({ credentials, regions, onProgress = () => {} }) {
  const warnings = [];
  let done = 0;
  const results = await mapLimit(regions, 4, async (region) => {
    try { const r = await scanRdsRegion(region, credentials); done += 1; if (r.instances.length) onProgress(`RDS [${done}/${regions.length}] ${region}: ${r.instances.length} database(s)`); return r; }
    catch (e) { done += 1; warnings.push(`${region}: RDS: ${errMsg(e)}`); return { instances: [], warnings: [] }; }
  });
  results.forEach((r) => warnings.push(...r.warnings));
  const instances = results.flatMap((r) => r.instances).sort((a, b) => a.region.localeCompare(b.region) || a.id.localeCompare(b.id));
  return {
    instances,
    summary: { instances: instances.length, pendingUpdates: instances.filter((i) => i.pendingActions.length).length, needAttention: instances.filter((i) => i.health === 'ATTENTION').length, withRecommendations: instances.filter((i) => i.recommendations.length).length },
    warnings,
  };
}

module.exports = { scanRds, rdsRecommendations };
