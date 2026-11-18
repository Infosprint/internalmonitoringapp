'use strict';
const { STSClient, AssumeRoleCommand, GetCallerIdentityCommand } = require('@aws-sdk/client-sts');
const {
  EC2Client, DescribeRegionsCommand, DescribeInstancesCommand, DescribeVolumesCommand,
  DescribeSnapshotsCommand, DescribeImagesCommand,
} = require('@aws-sdk/client-ec2');
const { GuardDutyClient, ListDetectorsCommand, GetDetectorCommand } = require('@aws-sdk/client-guardduty');
const { SecurityHubClient, DescribeHubCommand } = require('@aws-sdk/client-securityhub');
const { Inspector2Client, BatchGetAccountStatusCommand } = require('@aws-sdk/client-inspector2');
const { BackupClient, ListProtectedResourcesCommand } = require('@aws-sdk/client-backup');
const { collectFindings, groupFindings } = require('./findings');
const { scanNetworkRegion, scanCloudFront } = require('./network');
const { AMI_RECOMMENDATION, AMI_WHY } = require('./guidance');
const { scanAmc } = require('./amc');
const { DLMClient, GetLifecyclePoliciesCommand, GetLifecyclePolicyCommand } = require('@aws-sdk/client-dlm');

const { MAX_ATTEMPTS, mapLimit, collect, errMsg, tagMap, chunk, createCredentialProvider, listRegions } = require('./aws');
const REGION_CONCURRENCY = 4;

const maxDate = (a, b) => (!a ? b : !b ? a : new Date(a) > new Date(b) ? a : b);

/* ---------- security service checks (per region) ---------- */

async function checkGuardDuty(region, credentials) {
  const gd = new GuardDutyClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  const ids = await collect(gd, (t) => new ListDetectorsCommand({ NextToken: t }), (r) => r.DetectorIds);
  if (!ids.length) return { status: 'NOT_ENABLED', detail: 'No GuardDuty detector exists in this region.' };
  const d = await gd.send(new GetDetectorCommand({ DetectorId: ids[0] }));
  if (d.Status === 'ENABLED') return { status: 'ENABLED', detail: `Detector ${ids[0]} is enabled.` };
  return { status: 'NOT_ENABLED', detail: `Detector ${ids[0]} exists but is ${d.Status || 'disabled'}.` };
}

async function checkSecurityHub(region, credentials) {
  const sh = new SecurityHubClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  try {
    const hub = await sh.send(new DescribeHubCommand({}));
    return { status: 'ENABLED', detail: `Hub enabled${hub.SubscribedAt ? ` since ${hub.SubscribedAt}` : ''}.` };
  } catch (e) {
    if (e.name === 'InvalidAccessException' || e.name === 'ResourceNotFoundException') {
      return { status: 'NOT_ENABLED', detail: 'Security Hub is not enabled in this region.' };
    }
    throw e;
  }
}

async function checkInspector(region, accountId, credentials) {
  const ins = new Inspector2Client({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  const res = await ins.send(new BatchGetAccountStatusCommand({ accountIds: [accountId] }));
  const acct = (res.accounts || [])[0];
  if (!acct) return { status: 'NOT_ENABLED', detail: 'Inspector returned no status for this account.' };
  const overall = acct.state?.status;
  const ec2 = acct.resourceState?.ec2?.status;
  if (overall !== 'ENABLED') {
    return { status: 'NOT_ENABLED', detail: `Inspector account status is ${overall || 'unknown'}.`, ec2Scanning: ec2 };
  }
  if (ec2 !== 'ENABLED') {
    return { status: 'PARTIAL', detail: `Inspector is enabled but EC2 scanning is ${ec2 || 'not enabled'}.`, ec2Scanning: ec2 };
  }
  return { status: 'ENABLED', detail: 'Inspector enabled with EC2 scanning.', ec2Scanning: ec2 };
}

async function safe(fn) {
  try { return await fn(); } catch (e) { return { status: 'ERROR', detail: 'Check could not be completed.', error: errMsg(e) }; }
}

/* ---------- backup evaluation (pure functions, unit-testable) ---------- */

// A DLM policy applies to a resource when the resource type is targeted and it carries
// at least one of the policy's target tags (key + value).
function dlmPolicyMatches(policy, resourceType, tags) {
  if (!policy.resourceTypes.includes(resourceType)) return false;
  if (!policy.targetTags.length) return false;
  return policy.targetTags.some((t) => tags[t.Key] === t.Value);
}

function evaluateInstance({ instance, volumes, snapsByVolume, imagesByInstance, protectedArns, dlmPolicies, region, accountId }) {
  const tags = tagMap(instance.Tags);
  const instArn = `arn:aws:ec2:${region}:${accountId}:instance/${instance.InstanceId}`;
  const policies = [];

  let instanceCovered = false;
  if (protectedArns.has(instArn)) { instanceCovered = true; policies.push('AWS Backup (instance)'); }
  for (const p of dlmPolicies) {
    if (dlmPolicyMatches(p, 'INSTANCE', tags)) {
      instanceCovered = true;
      policies.push(`DLM ${p.type === 'IMAGE_MANAGEMENT' ? 'AMI' : 'snapshot'} policy ${p.id}`);
    }
  }

  let lastSnapshot = null;
  let coveredVols = 0;
  const volumeRows = volumes.map((v) => {
    const vTags = tagMap(v.Tags);
    const vSources = [];
    if (protectedArns.has(`arn:aws:ec2:${region}:${accountId}:volume/${v.VolumeId}`)) vSources.push('AWS Backup (volume)');
    for (const p of dlmPolicies) {
      if (dlmPolicyMatches(p, 'VOLUME', vTags)) vSources.push(`DLM snapshot policy ${p.id}`);
    }
    const s = snapsByVolume.get(v.VolumeId);
    lastSnapshot = maxDate(lastSnapshot, s?.latest);
    if (vSources.length) { coveredVols += 1; policies.push(...vSources.map((x) => `${x} → ${v.VolumeId}`)); }
    return {
      volumeId: v.VolumeId,
      sizeGiB: v.Size,
      policyCovered: instanceCovered || vSources.length > 0,
      snapshotCount: s?.count || 0,
      lastSnapshot: s?.latest || null,
    };
  });

  const lastAmi = imagesByInstance.get(instance.InstanceId) || null;
  const allVolsCovered = volumes.length > 0 && coveredVols === volumes.length;

  let status;
  if (instanceCovered || allVolsCovered) status = 'PROTECTED';
  else if (coveredVols > 0) status = 'PARTIAL';
  else if (lastSnapshot || lastAmi) status = 'MANUAL_ONLY';
  else status = 'NONE';

  return {
    instanceId: instance.InstanceId,
    name: tags.Name || '',
    state: instance.State?.Name,
    instanceType: instance.InstanceType,
    platform: instance.PlatformDetails || instance.Platform || 'Linux/UNIX',
    launchTime: instance.LaunchTime,
    volumes: volumeRows,
    backup: { status, policies: [...new Set(policies)], lastSnapshot, lastAmi },
  };
}

/* ---------- one region ---------- */

async function loadBackupContext(region, accountId, credentials, instances) {
  const ec2 = new EC2Client({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  const errors = [];

  const instanceIds = new Set(instances.map((i) => i.InstanceId));
  const allVolumes = await collect(ec2, (t) => new DescribeVolumesCommand({ NextToken: t }), (r) => r.Volumes);
  const volsByInstance = new Map();
  for (const v of allVolumes) {
    for (const a of v.Attachments || []) {
      if (instanceIds.has(a.InstanceId)) {
        if (!volsByInstance.has(a.InstanceId)) volsByInstance.set(a.InstanceId, []);
        volsByInstance.get(a.InstanceId).push(v);
      }
    }
  }

  // Snapshots, looked up by volume in chunks (EC2 filter value limit)
  const snapsByVolume = new Map();
  try {
    const volIds = [...new Set([...volsByInstance.values()].flat().map((v) => v.VolumeId))];
    for (const ids of chunk(volIds, 100)) {
      const snaps = await collect(
        ec2,
        (t) => new DescribeSnapshotsCommand({ OwnerIds: ['self'], Filters: [{ Name: 'volume-id', Values: ids }], NextToken: t }),
        (r) => r.Snapshots,
      );
      for (const s of snaps) {
        const e = snapsByVolume.get(s.VolumeId) || { count: 0, latest: null };
        e.count += 1;
        e.latest = maxDate(e.latest, s.StartTime);
        snapsByVolume.set(s.VolumeId, e);
      }
    }
  } catch (e) { errors.push(`Snapshots: ${errMsg(e)}`); }

  // AMIs created from these instances
  const imagesByInstance = new Map();
  try {
    const images = await collect(ec2, (t) => new DescribeImagesCommand({ Owners: ['self'], NextToken: t }), (r) => r.Images);
    for (const img of images) {
      if (img.SourceInstanceId && instanceIds.has(img.SourceInstanceId)) {
        imagesByInstance.set(img.SourceInstanceId, maxDate(imagesByInstance.get(img.SourceInstanceId), img.CreationDate));
      }
    }
  } catch (e) { errors.push(`AMIs: ${errMsg(e)}`); }

  // AWS Backup protected resources
  const protectedArns = new Set();
  try {
    const bk = new BackupClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
    const res = await collect(bk, (t) => new ListProtectedResourcesCommand({ NextToken: t }), (r) => r.Results);
    res.forEach((r) => protectedArns.add(r.ResourceArn));
  } catch (e) { errors.push(`AWS Backup: ${errMsg(e)}`); }

  // Data Lifecycle Manager policies (automated EBS snapshot / AMI policies)
  const dlmPolicies = [];
  try {
    const dlm = new DLMClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
    const list = await dlm.send(new GetLifecyclePoliciesCommand({ State: 'ENABLED' }));
    for (const s of list.Policies || []) {
      const p = await dlm.send(new GetLifecyclePolicyCommand({ PolicyId: s.PolicyId }));
      const d = p.Policy?.PolicyDetails;
      if (!d || d.PolicyType === 'EVENT_BASED_POLICY') continue;
      dlmPolicies.push({
        id: s.PolicyId,
        type: d.PolicyType || 'EBS_SNAPSHOT_MANAGEMENT',
        resourceTypes: d.ResourceTypes || [],
        targetTags: d.TargetTags || [],
      });
    }
  } catch (e) { errors.push(`DLM: ${errMsg(e)}`); }

  return { volsByInstance, snapsByVolume, imagesByInstance, protectedArns, dlmPolicies, errors };
}

async function scanRegion(region, accountId, credentials) {
  const ec2 = new EC2Client({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  let instances;
  try {
    const reservations = await collect(
      ec2,
      (t) => new DescribeInstancesCommand({
        Filters: [{ Name: 'instance-state-name', Values: ['pending', 'running', 'stopping', 'stopped'] }],
        NextToken: t,
      }),
      (r) => r.Reservations,
    );
    instances = reservations.flatMap((r) => r.Instances || []);
  } catch (e) {
    return { region, instanceCount: 0, skipped: true, error: `Could not list instances: ${errMsg(e)}`, instances: [], services: null, backupErrors: [] };
  }
  if (!instances.length) return { region, instanceCount: 0, instances: [], services: null, backupErrors: [] };

  const [guardduty, securityhub, inspector, ctx] = await Promise.all([
    safe(() => checkGuardDuty(region, credentials)),
    safe(() => checkSecurityHub(region, credentials)),
    safe(() => checkInspector(region, accountId, credentials)),
    loadBackupContext(region, accountId, credentials, instances).catch((e) => ({ fatal: errMsg(e) })),
  ]);

  let rows;
  let backupErrors = [];
  if (ctx.fatal) {
    backupErrors = [`Backup checks failed: ${ctx.fatal}`];
    rows = instances.map((i) => ({
      instanceId: i.InstanceId, name: tagMap(i.Tags).Name || '', state: i.State?.Name, instanceType: i.InstanceType,
      platform: i.PlatformDetails || 'Linux/UNIX', launchTime: i.LaunchTime, volumes: [],
      backup: { status: 'UNKNOWN', policies: [], lastSnapshot: null, lastAmi: null },
    }));
  } else {
    backupErrors = ctx.errors;
    rows = instances.map((instance) => evaluateInstance({
      instance, volumes: ctx.volsByInstance.get(instance.InstanceId) || [], snapsByVolume: ctx.snapsByVolume,
      imagesByInstance: ctx.imagesByInstance, protectedArns: ctx.protectedArns, dlmPolicies: ctx.dlmPolicies, region, accountId,
    }));
  }

  const services = { guardduty, securityhub, inspector };
  const fx = await collectFindings(region, credentials, services).catch((e) => ({ items: [], meta: [{ source: 'Findings', count: 0, error: errMsg(e) }] }));

  return {
    region, instanceCount: instances.length, instances: rows, services, backupErrors,
    securityFindings: fx.items, findingsMeta: fx.meta,
  };
}

/* ---------- findings & report ---------- */

const SERVICE_INFO = {
  guardduty: {
    name: 'Amazon GuardDuty',
    severity: 'HIGH',
    why: 'GuardDuty continuously analyses CloudTrail, VPC Flow Logs and DNS logs to detect threats such as compromised EC2 instances, crypto-mining, credential exfiltration, backdoor/C2 communication and traffic to known-malicious IPs. Without it, an attack on your instances can go unnoticed for weeks.',
    action: 'Enable GuardDuty in this region (and consider enabling it for all regions via AWS Organizations).',
  },
  securityhub: {
    name: 'AWS Security Hub',
    severity: 'MEDIUM',
    why: 'Security Hub gives a single view of your security posture: it runs automated checks against standards such as AWS Foundational Security Best Practices, CIS and PCI-DSS, and aggregates findings from GuardDuty, Inspector and others. Without it, misconfigurations (open security groups, unencrypted volumes, public resources) are not continuously detected.',
    action: 'Enable Security Hub in this region with the AWS Foundational Security Best Practices standard (AWS Config recording is required for its controls).',
  },
  inspector: {
    name: 'Amazon Inspector',
    severity: 'MEDIUM',
    why: 'Inspector continuously scans EC2 instances for software vulnerabilities (CVEs) and unintended network exposure. Without it, unpatched packages and exploitable vulnerabilities on your instances stay invisible until they are exploited.',
    action: 'Enable Amazon Inspector with EC2 scanning in this region (instances must be SSM-managed for agent-based scanning).',
  },
};

const BACKUP_WHY = AMI_WHY;

function buildFindings(regionResults) {
  const findings = [];
  for (const r of regionResults) {
    if (!r.instanceCount || !r.services) continue;
    for (const key of ['guardduty', 'securityhub', 'inspector']) {
      const s = r.services[key];
      const info = SERVICE_INFO[key];
      if (s.status === 'NOT_ENABLED' || s.status === 'PARTIAL') {
        findings.push({
          category: 'Security service', service: key, severity: info.severity, region: r.region, resource: info.name,
          title: `${info.name} is ${s.status === 'PARTIAL' ? 'only partially enabled' : 'not enabled'} in ${r.region}`,
          detail: s.detail, why: info.why, recommendation: info.action,
        });
      }
    }
    for (const i of r.instances) {
      const b = i.backup;
      const label = `${i.instanceId}${i.name ? ` (${i.name})` : ''}`;
      if (b.status === 'NONE') {
        findings.push({
          category: 'Backup', severity: 'HIGH', region: r.region, resource: i.instanceId,
          title: `Backup is not enabled for instance ${label}`,
          detail: 'No AWS Backup plan, DLM snapshot/AMI policy, snapshot or AMI was found for this instance or its volumes.',
          why: BACKUP_WHY,
          recommendation: AMI_RECOMMENDATION,
        });
      } else if (b.status === 'MANUAL_ONLY') {
        findings.push({
          category: 'Backup', severity: 'MEDIUM', region: r.region, resource: i.instanceId,
          title: `No automated backup policy for instance ${label}`,
          detail: `Only manual backups exist (latest snapshot: ${b.lastSnapshot || 'none'}, latest AMI: ${b.lastAmi || 'none'}). No AWS Backup plan or DLM policy covers it.`,
          why: BACKUP_WHY,
          recommendation: `${AMI_RECOMMENDATION} This replaces the manual backups, which are easy to forget and are never expired.`,
        });
      } else if (b.status === 'PARTIAL') {
        const missing = i.volumes.filter((v) => !v.policyCovered).map((v) => v.volumeId).join(', ');
        findings.push({
          category: 'Backup', severity: 'MEDIUM', region: r.region, resource: i.instanceId,
          title: `Backup policy covers only some volumes of instance ${label}`,
          detail: `Volumes without a backup policy: ${missing}.`,
          why: BACKUP_WHY,
          recommendation: `Extend the backup policy to every attached volume, and enable an AMI backup policy for this instance. ${AMI_RECOMMENDATION}`,
        });
      }
    }
  }
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity] || a.region.localeCompare(b.region));
}

function buildWarnings(regionResults) {
  const w = [];
  for (const r of regionResults) {
    if (r.error) w.push(`${r.region}: ${r.error}`);
    for (const key of ['guardduty', 'securityhub', 'inspector']) {
      const s = r.services?.[key];
      if (s?.status === 'ERROR') w.push(`${r.region}: ${SERVICE_INFO[key].name} check failed (${s.error}). Verify the role has read access; no recommendation was made for this check.`);
    }
    (r.findingsMeta || []).forEach((m) => {
      if (m.error) w.push(`${r.region}: could not retrieve ${m.source} findings (${m.error}). Findings for this service are missing from the report.`);
      else if (m.truncated) w.push(`${r.region}: ${m.source} has more active findings than the report limit; the ${m.count} most severe are shown.`);
    });
    (r.backupErrors || []).forEach((e) => w.push(`${r.region}: ${e}. Backup results for this region may be incomplete.`));
  }
  return w;
}

// Merge per-region network results into one report section
function buildNetwork(results, cloudfront) {
  const sorted = [...results].sort((a, b) => a.region.localeCompare(b.region));
  const securityGroups = sorted.flatMap((r) => r.securityGroups);
  const flowLogs = sorted.flatMap((r) => r.vpcs);
  const loadBalancers = sorted.flatMap((r) => r.loadBalancers);
  const sg = (s) => securityGroups.filter((x) => x.severity === s).length;
  const warnings = [
    ...sorted.flatMap((r) => r.errors.map((e) => `${r.region}: ${e}. Network checks for this region may be incomplete.`)),
    ...cloudfront.errors,
  ];
  return {
    securityGroups, flowLogs, loadBalancers, cloudfront: cloudfront.items,
    totals: {
      securityGroups: sorted.reduce((n, r) => n + r.totals.securityGroups, 0),
      vpcs: sorted.reduce((n, r) => n + r.totals.vpcs, 0),
      loadBalancers: sorted.reduce((n, r) => n + r.totals.loadBalancers, 0),
      cloudfrontDistributions: cloudfront.total,
    },
    summary: {
      openSecurityGroups: { total: securityGroups.length, critical: sg('CRITICAL'), high: sg('HIGH'), low: sg('LOW') },
      vpcsWithoutFlowLogs: flowLogs.length,
      loadBalancersWithoutLogs: loadBalancers.length,
      cloudfrontWithoutLogs: cloudfront.items.length,
      issues: sg('CRITICAL') + sg('HIGH') + flowLogs.length + loadBalancers.length + cloudfront.items.length,
    },
    warnings,
  };
}

async function scanClient(client, onProgress = () => {}, options = {}) {
  const startedAt = new Date();
  const credentials = createCredentialProvider(client);

  onProgress(`Assuming role ${client.roleArn}`);
  const sts = new STSClient({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });
  const identity = await sts.send(new GetCallerIdentityCommand({}));
  if (identity.Account !== client.accountId) {
    throw new Error(`Assumed role belongs to account ${identity.Account}, expected ${client.accountId}`);
  }

  const regions = await listRegions(credentials);

  onProgress(`Scanning ${regions.length} regions`);
  let done = 0;
  const networkResults = [];
  const regionResults = await mapLimit(regions, REGION_CONCURRENCY, async (region) => {
    const [r, net] = await Promise.all([
      scanRegion(region, client.accountId, credentials),
      scanNetworkRegion(region, client.accountId, credentials).catch((e) => ({
        region, securityGroups: [], vpcs: [], loadBalancers: [], totals: { securityGroups: 0, vpcs: 0, loadBalancers: 0 }, errors: [`Network checks: ${errMsg(e)}`],
      })),
    ]);
    networkResults.push(net);
    done += 1;
    onProgress(`[${done}/${regions.length}] ${region}: ${r.instanceCount} instance(s)`);
    return r;
  });

  onProgress('Checking CloudFront distributions');
  const cloudfront = await scanCloudFront(credentials).catch((e) => ({ items: [], total: 0, errors: [`CloudFront: ${errMsg(e)}`] }));
  const network = buildNetwork(networkResults, cloudfront);

  // AMC partners get extra detail: server inventory, 8-day CPU/RAM, EBS, load balancer / ASG health, logging status
  let amc = null;
  if (client.partnerType === 'amc') {
    const range = options.range === '1m' ? '1m' : '1w';
    onProgress(`AMC partner: collecting server details and ${range === '1m' ? '30-day' : '7-day'} metrics`);
    amc = await scanAmc({ credentials, range, regions: regionResults.filter((r) => r.instanceCount > 0).map((r) => r.region), onProgress })
      .catch((e) => ({ failed: true, warnings: [`AMC checks failed: ${errMsg(e)}`], instances: [], summary: null }));
  }

  const findings = buildFindings(regionResults);

  // Active findings from the three services. Duplicate IDs are dropped (Security Hub aggregation can repeat
  // them across regions); then repeated findings of the same type are merged into one entry with a count.
  const seen = new Set();
  const all = regionResults.flatMap((r) => r.securityFindings || []).filter((f) => {
    const k = `${f.source}|${f.id}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const grouped = groupFindings(all);
  const securityFindings = {
    guardduty: grouped.filter((f) => f.source === 'GuardDuty'),
    securityhub: grouped.filter((f) => f.source === 'Security Hub'),
    inspector: grouped.filter((f) => f.source === 'Inspector'),
  };
  const sevCount = (s) => grouped.filter((f) => f.severity === s).length;
  const instances = regionResults.flatMap((r) => r.instances);
  regionResults.forEach((r) => { delete r.securityFindings; });
  const sev = (s) => findings.filter((f) => f.severity === s).length;
  const warnings = [...buildWarnings(regionResults), ...network.warnings, ...(amc?.warnings || [])];
  if (amc) delete amc.warnings;
  delete network.warnings;
  return {
    client: { id: client.id, name: client.clientName, accountId: client.accountId, roleArn: client.roleArn, partnerType: client.partnerType || 'general' },
    scan: { startedAt: startedAt.toISOString(), finishedAt: new Date().toISOString() },
    summary: {
      regionsScanned: regions.length,
      regionsWithInstances: regionResults.filter((r) => r.instanceCount > 0).length,
      totalInstances: instances.length,
      instancesProtected: instances.filter((i) => i.backup.status === 'PROTECTED').length,
      instancesWithoutBackup: instances.filter((i) => i.backup.status === 'NONE').length,
      findings: { total: findings.length, high: sev('HIGH'), medium: sev('MEDIUM'), low: sev('LOW') },
      network: network.summary,
      ...(amc && amc.summary ? { amc: amc.summary } : {}),
      securityFindings: {
        total: grouped.length, totalOccurrences: all.length,
        guardduty: securityFindings.guardduty.length, securityhub: securityFindings.securityhub.length, inspector: securityFindings.inspector.length,
        occurrences: {
          guardduty: all.filter((f) => f.source === 'GuardDuty').length,
          securityhub: all.filter((f) => f.source === 'Security Hub').length,
          inspector: all.filter((f) => f.source === 'Inspector').length,
        },
        critical: sevCount('CRITICAL'), high: sevCount('HIGH'), medium: sevCount('MEDIUM'), low: sevCount('LOW'),
      },
    },
    regions: regionResults.filter((r) => r.instanceCount > 0 || r.error),
    findings,
    network,
    ...(amc ? { amc } : {}),
    securityFindings,
    warnings,
  };
}

module.exports = { buildNetwork, scanClient, evaluateInstance, dlmPolicyMatches, buildFindings };
