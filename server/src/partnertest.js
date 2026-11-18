'use strict';
const assert = require('assert');
const fs = require('fs'); const os = require('os'); const path = require('path');
process.env.EXPORT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exp-'));
const logs = require('./logs');
const { renderServerOverview } = require('./amc-render');
const { renderHtml } = require('./report');
const { buildDocx } = require('./docx');
const { analyzeBucketPolicy } = require('./s3scan');
const { rdsRecommendations } = require('./rdsscan');
const { distributionRecommendations } = require('./cfscan');
const { s3Tables, rdsTables, cfTables, fmtBytes } = require('./svc-text');
const { evaluateVpcs } = require('./network');

// logs helpers
assert.deepStrictEqual(logs.s3Parts('arn:aws:s3:::my-bucket/some/prefix/'), { bucket: 'my-bucket', prefix: 'some/prefix' });
assert.strictEqual(logs.days(new Date('2026-01-01T10:00:00Z'), new Date('2026-01-03T01:00:00Z')).length, 3);
assert.throws(() => logs.createJob({ client: { id: 'c' }, user: { id: 'u' }, request: { selections: {}, duration: '1h' } }), /at least one/);

// only VPCs with something attached are checked
const enis = [{ NetworkInterfaceId: 'eni-1', VpcId: 'vpc-used', Status: 'in-use' }];
assert.deepStrictEqual(evaluateVpcs({ vpcs: [{ VpcId: 'vpc-used' }, { VpcId: 'vpc-empty' }], flowLogs: [], subnets: [], enis }).map((v) => v.vpcId), ['vpc-used']);

// S3 bucket policy review
const open = analyzeBucketPolicy(JSON.stringify({ Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }));
assert.ok(open.some((i) => i.severity === 'HIGH' && /everyone/.test(i.title)));
const wr = analyzeBucketPolicy({ Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:*', Resource: '*' }] });
assert.ok(wr.some((i) => i.severity === 'CRITICAL'));
const good = analyzeBucketPolicy({ Statement: [{ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*', Condition: { Bool: { 'aws:SecureTransport': 'false' } } }] });
assert.strictEqual(good.length, 0);
assert.ok(analyzeBucketPolicy({ Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111122223333:root' }, Action: 's3:GetObject', Resource: 'x' }] }, { accountId: '999999999999' }).some((i) => /other AWS account/.test(i.title)));
assert.strictEqual(fmtBytes(1536), '1.5 KB');

// RDS and CloudFront recommendations
const db = { pendingActions: [{ action: 'system-update', autoAppliedAfter: '2026-12-01T00:00:00Z' }], status: 'available', multiAz: false, backupRetentionDays: 1, publiclyAccessible: true, encrypted: false, deletionProtection: false, autoMinorVersionUpgrade: false, cpu: { peak: 95 }, ram: { peak: 50 }, storage: { usedPercent: 90, autoscaling: false } };
const recs = rdsRecommendations(db);
assert.ok(recs.some((r) => /pending/i.test(r)) && recs.some((r) => /Multi-AZ/.test(r)) && recs.some((r) => /95%/.test(r)) && recs.some((r) => /90% used/.test(r)));
const cfr = distributionRecommendations({ enabled: true, logging: false, webAcl: null, alarms: 0, minTls: 'TLSv1', certificate: { daysToExpiry: 5 }, metrics: { errors5xxPeak: 9 }, invalidations: { inProgress: 1, last7Days: 60 } });
assert.ok(cfr.length >= 7);

// report and Word file with every new section
const inst = { region: 'ap-south-1', instanceId: 'i-1', name: 'web', state: 'running', instanceType: 't3.micro', ssm: { status: 'NOT_INSTALLED' }, cpu: { average: 3, peak: 9 }, memory: null,
  storage: { volumes: [{}], provisionedGiB: 100, usedGiB: null, freeGiB: null, filesystems: [] }, health: [{ kind: 'targetGroup', lb: 'alb', group: 'tg', state: 'unhealthy', reason: 'Target.Timeout' }],
  logging: { vpcFlowLogs: 'NONE', loadBalancerLogs: 'DISABLED', cloudtrail: 'ENABLED' }, recommendations: [] };
const okInst = { ...inst, instanceId: 'i-2', ssm: { status: 'ONLINE' }, memory: { average: 40, peak: 70 }, storage: { volumes: [{}], provisionedGiB: 100, usedGiB: 30, freeGiB: 70, filesystems: [] } };
const ov = renderServerOverview({ amc: { period: { days: 7 }, instances: [inst, okInst] } });
assert.ok(ov.includes('Install and enable the SSM agent') && ov.includes('Enable CloudWatch metric to collect storage inputs') && ov.includes('70 GiB') && ov.includes('Target.Timeout'));
assert.ok(!ov.includes('<svg'));

const bucket = { name: 'data-bucket', region: 'ap-south-1', sizeBytes: 5e9, objects: 1200, classes: [{ storageClass: 'Standard', bytes: 5e9 }], versioning: 'DISABLED', replication: 'DISABLED', policy: { present: true, issues: open.map((i) => ({ ...i })) }, worstPolicy: 'HIGH' };
const report = {
  client: { name: 'T', accountId: '1' }, scan: { finishedAt: new Date().toISOString() }, warnings: [], network: null, findings: [], regions: [],
  summary: { totalInstances: 2, regionsWithInstances: 1, regionsScanned: 1, instancesProtected: 0, instancesWithoutBackup: 2, findings: { high: 0, medium: 0, total: 0 } },
  amc: { period: { days: 7 }, instances: [inst, okInst], summary: {} },
  s3: { buckets: [bucket], summary: { buckets: 1, totalBytes: 5e9, versioningOff: 1, replicationOff: 1, policyIssues: 1, public: 0 } },
  rds: { instances: [{ region: 'ap-south-1', id: 'db1', engine: 'mysql', engineVersion: '8.0', instanceClass: 'db.t3.medium', status: 'available', health: 'HEALTHY', multiAz: false, pendingActions: [{ action: 'x' }], cpu: { average: 5, peak: 20 }, ram: { average: 50, peak: 60 }, storage: { allocatedGiB: 100, usedGiB: 40, freeGiB: 60, usedPercent: 40 }, recommendations: ['Apply the pending update'] }], summary: { instances: 1, pendingUpdates: 1, needAttention: 0 } },
  cloudfrontService: { distributions: [{ id: 'E1', domain: 'd.cloudfront.net', aliases: ['www.x.com'], enabled: true, status: 'Deployed', metrics: { requests: 1000, errors5xxPeak: 0, errors4xxPeak: 1 }, invalidations: { last7Days: 2, inProgress: 0 }, logging: false, webAcl: null, alarms: 0, certificate: null, recommendations: ['Enable access logging'] }], monitorList: [['5xx error rate', 'why', 'how']], summary: { distributions: 1 } },
};
const html = renderHtml(report);
assert.ok(html.indexOf('Server overview') < html.indexOf('1. Backup status'));
assert.ok(html.indexOf('3. S3 buckets') < html.indexOf('4. RDS databases') && html.indexOf('4. RDS databases') < html.indexOf('5. CloudFront') && html.indexOf('5. CloudFront') < html.indexOf('6. Amazon GuardDuty'));
assert.ok(!html.includes('AMC server details') && !html.includes('<svg') && html.includes('Why versioning should be enabled') && html.includes('What the AMC team should monitor'));
buildDocx(report).then((b) => { assert.ok(b.length > 5000); console.log('partner/AMC/S3/RDS/CloudFront tests passed'); }).catch((e) => { console.error(e); process.exit(1); });
