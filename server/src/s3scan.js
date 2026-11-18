'use strict';
// S3 inventory: every bucket in every region with size, object count, storage classes, bucket policy review,
// versioning and replication. Read-only (List/Get calls and CloudWatch storage metrics).
const {
  S3Client, ListBucketsCommand, GetBucketLocationCommand, GetBucketVersioningCommand, GetBucketReplicationCommand,
  GetBucketPolicyCommand, GetBucketPolicyStatusCommand, GetPublicAccessBlockCommand,
} = require('@aws-sdk/client-s3');
const { CloudWatchClient, GetMetricDataCommand, ListMetricsCommand } = require('@aws-sdk/client-cloudwatch');
const { MAX_ATTEMPTS, mapLimit, errMsg, chunk } = require('./aws');

const CLASS_NAMES = {
  StandardStorage: 'Standard', StandardIAStorage: 'Standard-IA', OneZoneIAStorage: 'One Zone-IA', IntelligentTieringFAStorage: 'Intelligent-Tiering (frequent)',
  IntelligentTieringIAStorage: 'Intelligent-Tiering (infrequent)', IntelligentTieringAAStorage: 'Intelligent-Tiering (archive instant)', IntelligentTieringAIAStorage: 'Intelligent-Tiering (archive instant)',
  IntAAStorage: 'Intelligent-Tiering (archive)', IntDAAStorage: 'Intelligent-Tiering (deep archive)', GlacierInstantRetrievalStorage: 'Glacier Instant Retrieval',
  GlacierStorage: 'Glacier Flexible Retrieval', GlacierS3ObjectOverhead: 'Glacier overhead', GlacierObjectOverhead: 'Glacier overhead', DeepArchiveStorage: 'Glacier Deep Archive',
  DeepArchiveObjectOverhead: 'Glacier overhead', DeepArchiveS3ObjectOverhead: 'Glacier overhead', ReducedRedundancyStorage: 'Reduced Redundancy', StandardIAObjectOverhead: 'Standard-IA overhead', OneZoneIASizeOverhead: 'One Zone-IA overhead',
};
const SKIP_CLASS = /Overhead$/;

const IS_STAR = (p) => p === '*' || (p && typeof p === 'object' && ([].concat(p.AWS || [])).includes('*'));
const arr = (x) => (x === undefined ? [] : [].concat(x));
const hasCondition = (st) => st.Condition && Object.keys(st.Condition).length > 0;

// Reviews a bucket policy document and returns the problems found, each with a fix.
function analyzeBucketPolicy(policyText, { accountId } = {}) {
  const issues = [];
  let doc;
  try { doc = typeof policyText === 'string' ? JSON.parse(policyText) : policyText; } catch { return [{ severity: 'MEDIUM', title: 'Bucket policy is not valid JSON', recommendation: 'Review the bucket policy in the S3 console and correct it.' }]; }
  const statements = arr(doc?.Statement);
  const allow = statements.filter((s) => s.Effect === 'Allow');
  const deny = statements.filter((s) => s.Effect === 'Deny');

  for (const st of allow) {
    const actions = arr(st.Action).map(String);
    const star = actions.some((a) => a === '*' || a === 's3:*');
    const writes = actions.some((a) => /^s3:(Put|Delete|Replicate|Restore|Abort)/i.test(a) || a === 's3:*' || a === '*');
    if (IS_STAR(st.Principal) && !hasCondition(st)) {
      issues.push({
        severity: writes ? 'CRITICAL' : 'HIGH',
        title: `Policy statement${st.Sid ? ` "${st.Sid}"` : ''} grants ${writes ? 'write/admin' : 'read'} access to everyone (Principal "*")`,
        recommendation: 'Replace the wildcard principal with the specific accounts, roles or CloudFront origin access identity/control that need access, or add a Condition (aws:SourceArn, aws:SourceAccount, aws:PrincipalOrgID). Enable S3 Block Public Access on the bucket.',
      });
    } else if (IS_STAR(st.Principal)) {
      issues.push({ severity: 'MEDIUM', title: `Statement${st.Sid ? ` "${st.Sid}"` : ''} uses Principal "*" with a condition`, recommendation: 'Confirm the condition really limits access to the intended source (for example aws:SourceArn or aws:PrincipalOrgID) and that it cannot be satisfied by an outsider.' });
    }
    if (star && !IS_STAR(st.Principal)) {
      issues.push({ severity: 'MEDIUM', title: `Statement${st.Sid ? ` "${st.Sid}"` : ''} allows all S3 actions (s3:*)`, recommendation: 'Grant only the actions required (for example s3:GetObject, s3:PutObject) following least privilege.' });
    }
    const res = arr(st.Resource).map(String);
    if (res.includes('*')) issues.push({ severity: 'LOW', title: `Statement${st.Sid ? ` "${st.Sid}"` : ''} applies to Resource "*"`, recommendation: 'Scope the statement to this bucket and the object prefixes it should cover.' });
    const ext = arr(st.Principal?.AWS).map(String).map((p) => (/^\d{12}$/.test(p) ? p : (/::(\d{12}):/.exec(p) || [])[1])).filter((a) => a && a !== accountId);
    if (ext.length) issues.push({ severity: 'LOW', title: `Grants access to other AWS account(s): ${[...new Set(ext)].join(', ')}`, recommendation: 'Confirm each external account is expected (partner, log delivery, replication) and remove any that are not.' });
  }
  const forcesTls = deny.some((s) => JSON.stringify(s.Condition || {}).toLowerCase().includes('securetransport'));
  if (!forcesTls) issues.push({ severity: 'LOW', title: 'Policy does not require encrypted transport (HTTPS)', recommendation: 'Add a Deny statement for requests where aws:SecureTransport is false so data is never sent over plain HTTP.' });
  return issues;
}

const WHY_VERSIONING = 'Versioning keeps every version of an object, so an accidental overwrite or delete (or ransomware that overwrites data) can be undone by restoring the earlier version. Without it, a deleted or overwritten object is gone permanently. Enable versioning and add a lifecycle rule to expire old versions so storage cost stays under control.';
const WHY_REPLICATION = 'Replication copies new objects to a second bucket (another Region or account) automatically. It protects against loss of a Region, accidental or malicious deletion of the whole bucket, and helps meet disaster-recovery and compliance requirements. Without it, the bucket is a single copy in a single Region. Versioning must be enabled before replication can be configured.';

const bucketRegion = (loc) => (!loc ? 'us-east-1' : loc === 'EU' ? 'eu-west-1' : loc);

async function scanS3({ credentials, accountId, onProgress = () => {} }) {
  const warnings = [];
  const root = new S3Client({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });
  const named = [];
  let token;
  do {
    const r = await root.send(new ListBucketsCommand({ ContinuationToken: token, MaxBuckets: 1000 }));
    named.push(...(r.Buckets || []));
    token = r.ContinuationToken;
  } while (token);
  onProgress(`S3: found ${named.length} bucket(s)`);

  const buckets = [];
  await mapLimit(named, 8, async (b) => {
    const row = { name: b.Name, created: b.CreationDate, region: b.BucketRegion || null, versioning: 'UNKNOWN', mfaDelete: false, replication: 'UNKNOWN', policy: { present: false, issues: [] }, publicAccess: null, sizeBytes: null, objects: null, classes: [] };
    try {
      if (!row.region) row.region = bucketRegion((await root.send(new GetBucketLocationCommand({ Bucket: b.Name }))).LocationConstraint);
      const s3 = new S3Client({ region: row.region, credentials, maxAttempts: MAX_ATTEMPTS });
      const attempt = async (what, fn) => { try { return await fn(); } catch (e) { return { __err: e, what }; } };

      const v = await attempt('versioning', () => s3.send(new GetBucketVersioningCommand({ Bucket: b.Name })));
      if (v.__err) warnings.push(`S3 ${b.Name}: versioning: ${errMsg(v.__err)}`);
      else { row.versioning = v.Status === 'Enabled' ? 'ENABLED' : v.Status === 'Suspended' ? 'SUSPENDED' : 'DISABLED'; row.mfaDelete = v.MFADelete === 'Enabled'; }

      const rep = await attempt('replication', () => s3.send(new GetBucketReplicationCommand({ Bucket: b.Name })));
      if (rep.__err) {
        if (rep.__err.name === 'ReplicationConfigurationNotFoundError') row.replication = 'DISABLED';
        else warnings.push(`S3 ${b.Name}: replication: ${errMsg(rep.__err)}`);
      } else {
        const rules = rep.ReplicationConfiguration?.Rules || [];
        row.replication = rules.some((r) => r.Status === 'Enabled') ? 'ENABLED' : 'DISABLED';
        row.replicationTargets = rules.filter((r) => r.Status === 'Enabled').map((r) => (r.Destination?.Bucket || '').split(':::')[1]).filter(Boolean);
      }

      const pol = await attempt('policy', () => s3.send(new GetBucketPolicyCommand({ Bucket: b.Name })));
      if (pol.__err) {
        if (pol.__err.name !== 'NoSuchBucketPolicy') warnings.push(`S3 ${b.Name}: bucket policy: ${errMsg(pol.__err)}`);
      } else { row.policy = { present: true, issues: analyzeBucketPolicy(pol.Policy, { accountId }) }; }

      const ps = await attempt('policy status', () => s3.send(new GetBucketPolicyStatusCommand({ Bucket: b.Name })));
      if (!ps.__err && ps.PolicyStatus?.IsPublic) {
        row.publicAccess = 'PUBLIC';
        if (!row.policy.issues.some((i) => i.severity === 'CRITICAL' || i.severity === 'HIGH')) row.policy.issues.unshift({ severity: 'HIGH', title: 'AWS evaluates this bucket as publicly accessible', recommendation: 'Remove the public statements from the bucket policy/ACLs and turn on S3 Block Public Access unless the bucket is meant to serve public content.' });
      }
      const pab = await attempt('public access block', () => s3.send(new GetPublicAccessBlockCommand({ Bucket: b.Name })));
      if (pab.__err) {
        if (pab.__err.name === 'NoSuchPublicAccessBlockConfiguration') row.policy.issues.push({ severity: 'MEDIUM', title: 'S3 Block Public Access is not configured on this bucket', recommendation: 'Enable all four Block Public Access settings on the bucket (and at account level) unless public access is intended.' });
      } else {
        const c = pab.PublicAccessBlockConfiguration || {};
        if (!(c.BlockPublicAcls && c.IgnorePublicAcls && c.BlockPublicPolicy && c.RestrictPublicBuckets)) row.policy.issues.push({ severity: 'MEDIUM', title: 'S3 Block Public Access is only partly enabled', recommendation: 'Enable all four Block Public Access settings unless public access is intended.' });
      }
    } catch (e) { warnings.push(`S3 ${b.Name}: ${errMsg(e)}`); }
    buckets.push(row);
  });

  // size, object count and storage classes from CloudWatch daily storage metrics (one call group per region)
  const byRegion = new Map();
  for (const b of buckets) if (b.region) (byRegion.get(b.region) || byRegion.set(b.region, []).get(b.region)).push(b);
  await mapLimit([...byRegion.keys()], 4, async (region) => {
    const cw = new CloudWatchClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
    try {
      const defs = [];
      let t;
      do { const r = await cw.send(new ListMetricsCommand({ Namespace: 'AWS/S3', MetricName: 'BucketSizeBytes', NextToken: t })); defs.push(...(r.Metrics || [])); t = r.NextToken; } while (t);
      const mine = new Map(byRegion.get(region).map((b) => [b.name, b]));
      const qs = [];
      for (const m of defs) {
        const name = m.Dimensions.find((d) => d.Name === 'BucketName')?.Value;
        const cls = m.Dimensions.find((d) => d.Name === 'StorageType')?.Value;
        if (mine.has(name) && cls) qs.push({ name, cls, id: `s${qs.length}`, metric: 'BucketSizeBytes', dims: m.Dimensions });
      }
      for (const name of mine.keys()) qs.push({ name, cls: 'AllStorageTypes', id: `s${qs.length}`, metric: 'NumberOfObjects', dims: [{ Name: 'BucketName', Value: name }, { Name: 'StorageType', Value: 'AllStorageTypes' }] });
      const end = new Date(); const start = new Date(end.getTime() - 4 * 86400000);
      for (const part of chunk(qs, 200)) {
        const res = await cw.send(new GetMetricDataCommand({
          StartTime: start, EndTime: end, ScanBy: 'TimestampDescending',
          MetricDataQueries: part.map((q) => ({ Id: q.id, ReturnData: true, MetricStat: { Metric: { Namespace: 'AWS/S3', MetricName: q.metric, Dimensions: q.dims }, Period: 86400, Stat: 'Average' } })),
        }));
        const got = new Map((res.MetricDataResults || []).map((r) => [r.Id, (r.Values || [])[0]]));
        for (const q of part) {
          const v = got.get(q.id);
          if (v === undefined) continue;
          const b = mine.get(q.name);
          if (q.metric === 'NumberOfObjects') b.objects = Math.round(v);
          else { b.classes.push({ storageClass: CLASS_NAMES[q.cls] || q.cls, bytes: Math.round(v), overhead: SKIP_CLASS.test(q.cls) || /Overhead/.test(CLASS_NAMES[q.cls] || '') }); b.sizeBytes = (b.sizeBytes || 0) + Math.round(v); }
        }
      }
    } catch (e) { warnings.push(`S3 size metrics ${region}: ${errMsg(e)}`); }
  });
  for (const b of buckets) {
    const merged = new Map();
    for (const c of b.classes) merged.set(c.storageClass, (merged.get(c.storageClass) || 0) + c.bytes);
    b.classes = [...merged].map(([storageClass, bytes]) => ({ storageClass, bytes })).sort((x, y) => y.bytes - x.bytes);
    b.worstPolicy = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].find((s) => b.policy.issues.some((i) => i.severity === s)) || null;
  }
  buckets.sort((a, b) => a.name.localeCompare(b.name));
  return {
    buckets, whyVersioning: WHY_VERSIONING, whyReplication: WHY_REPLICATION,
    summary: {
      buckets: buckets.length,
      totalBytes: buckets.reduce((s, b) => s + (b.sizeBytes || 0), 0),
      versioningOff: buckets.filter((b) => b.versioning !== 'ENABLED').length,
      replicationOff: buckets.filter((b) => b.replication !== 'ENABLED').length,
      policyIssues: buckets.filter((b) => b.policy.issues.some((i) => ['CRITICAL', 'HIGH', 'MEDIUM'].includes(i.severity))).length,
      public: buckets.filter((b) => b.publicAccess === 'PUBLIC').length,
    },
    warnings,
  };
}

module.exports = { scanS3, analyzeBucketPolicy, WHY_VERSIONING, WHY_REPLICATION };
