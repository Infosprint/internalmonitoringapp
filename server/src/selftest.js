'use strict';
// Offline test of the backup-evaluation logic and report rendering (no AWS calls).
const assert = require('assert');
const { evaluateInstance, buildFindings } = require('./scanner');
const { renderHtml } = require('./report');

const region = 'ap-south-1', accountId = '111122223333';
const mk = (id, tags = []) => ({ InstanceId: id, Tags: tags, State: { Name: 'running' }, InstanceType: 't3.micro' });
const vol = (id, tags = []) => ({ VolumeId: id, Size: 50, Tags: tags });
const base = { snapsByVolume: new Map(), imagesByInstance: new Map(), protectedArns: new Set(), dlmPolicies: [], region, accountId };

// 1. nothing at all -> NONE
let r = evaluateInstance({ ...base, instance: mk('i-1'), volumes: [vol('vol-1')] });
assert.strictEqual(r.backup.status, 'NONE');

// 2. manual snapshot only -> MANUAL_ONLY
r = evaluateInstance({ ...base, instance: mk('i-2'), volumes: [vol('vol-2')], snapsByVolume: new Map([['vol-2', { count: 3, latest: new Date('2026-10-01') }]]) });
assert.strictEqual(r.backup.status, 'MANUAL_ONLY');

// 3. DLM volume policy by tag -> PROTECTED
const dlm = [{ id: 'policy-1', type: 'EBS_SNAPSHOT_MANAGEMENT', resourceTypes: ['VOLUME'], targetTags: [{ Key: 'backup', Value: 'daily' }] }];
r = evaluateInstance({ ...base, instance: mk('i-3'), volumes: [vol('vol-3', [{ Key: 'backup', Value: 'daily' }])], dlmPolicies: dlm });
assert.strictEqual(r.backup.status, 'PROTECTED');

// 4. one of two volumes covered -> PARTIAL
r = evaluateInstance({ ...base, instance: mk('i-4'), volumes: [vol('vol-4a', [{ Key: 'backup', Value: 'daily' }]), vol('vol-4b')], dlmPolicies: dlm });
assert.strictEqual(r.backup.status, 'PARTIAL');

// 5. AWS Backup protects the instance ARN -> PROTECTED
r = evaluateInstance({ ...base, instance: mk('i-5'), volumes: [vol('vol-5')], protectedArns: new Set([`arn:aws:ec2:${region}:${accountId}:instance/i-5`]) });
assert.strictEqual(r.backup.status, 'PROTECTED');

// 6. tag value mismatch -> not covered
r = evaluateInstance({ ...base, instance: mk('i-6'), volumes: [vol('vol-6', [{ Key: 'backup', Value: 'weekly' }])], dlmPolicies: dlm });
assert.strictEqual(r.backup.status, 'NONE');

// findings + report
const instances = ['i-1', 'i-2'].map((id, n) => evaluateInstance({ ...base, instance: mk(id, [{ Key: 'Name', Value: '<b>x</b>' }]), volumes: [vol('v' + n)], snapsByVolume: n ? new Map([['v1', { count: 1, latest: new Date() }]]) : new Map() }));
const regions = [{ region, instanceCount: 2, instances, backupErrors: [], services: {
  guardduty: { status: 'NOT_ENABLED', detail: 'none' }, securityhub: { status: 'ENABLED', detail: '' }, inspector: { status: 'PARTIAL', detail: 'ec2 off' } } }];
const findings = buildFindings(regions);
assert.strictEqual(findings.length, 4); // GuardDuty, Inspector, 1 NONE, 1 MANUAL_ONLY
assert.strictEqual(findings[0].severity, 'HIGH');
const html = renderHtml({
  client: { name: 'Acme', accountId }, scan: { finishedAt: new Date().toISOString() },
  summary: { regionsScanned: 17, regionsWithInstances: 1, totalInstances: 2, instancesProtected: 0, instancesWithoutBackup: 1, findings: { total: 4, high: 2, medium: 2, low: 0 } },
  regions, findings, warnings: ['x'],
});
assert(!html.includes('<b>x</b>'), 'HTML must be escaped');
assert(html.includes('GuardDuty'));

// service findings: mapping + rendering
const { mapGuardDuty, mapSecurityHub, mapInspector, gdSeverity } = require('./findings');
assert.strictEqual(gdSeverity(9.5), 'CRITICAL'); assert.strictEqual(gdSeverity(7), 'HIGH'); assert.strictEqual(gdSeverity(4), 'MEDIUM'); assert.strictEqual(gdSeverity(2), 'LOW');
const g = mapGuardDuty({ Id: 'g1', Type: 'Backdoor:EC2/C&CActivity.B', Severity: 8, Title: 'EC2 talks to C&C', Description: 'd', Resource: { ResourceType: 'Instance', InstanceDetails: { InstanceId: 'i-1' } }, Service: { Count: 3 } }, region);
assert.strictEqual(g.severity, 'HIGH'); assert.strictEqual(g.resource.id, 'i-1'); assert(g.recommendation.url.endsWith('compromised-ec2.html'));
const h = mapSecurityHub({ Id: 'h1', Title: 'SG open', Description: 'd', Severity: { Label: 'HIGH', Normalized: 70 }, Resources: [{ Type: 'AwsEc2SecurityGroup', Id: 'sg-1' }], Remediation: { Recommendation: { Text: 'Restrict it', Url: 'https://docs.aws.amazon.com/x' } } }, region);
assert.strictEqual(h.recommendation.text, 'Restrict it');
const n = mapInspector({ findingArn: 'arn:x', title: 'CVE-1 - openssl', severity: 'CRITICAL', type: 'PACKAGE_VULNERABILITY', description: 'd', resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-1' }],
  packageVulnerabilityDetails: { vulnerabilityId: 'CVE-1', vulnerablePackages: [{ name: 'openssl', version: '1.0', fixedInVersion: '1.1' }] }, remediation: { recommendation: { text: 'Upgrade', Url: 'https://x' } } }, region);
assert(n.recommendation.steps[0].includes('1.1'));
const html2 = renderHtml({
  client: { name: 'Acme', accountId }, scan: { finishedAt: new Date().toISOString() },
  summary: { regionsScanned: 1, regionsWithInstances: 1, totalInstances: 0, instancesProtected: 0, instancesWithoutBackup: 0, findings: { total: 0, high: 0, medium: 0, low: 0 }, securityFindings: { total: 3, guardduty: 1, securityhub: 1, inspector: 1, critical: 1, high: 2, medium: 0, low: 0 } },
  regions: [], findings: [], warnings: [], securityFindings: { guardduty: [g], securityhub: [h], inspector: [n] },
});
assert(html2.includes('Recommended remediation') && html2.includes('compromised-ec2.html') && html2.includes('CVE-1'));
assert(!renderHtml({ ...JSON.parse(JSON.stringify({ client: { name: 'a', accountId }, scan: { finishedAt: 'x' }, summary: { regionsScanned: 0, regionsWithInstances: 0, totalInstances: 0, instancesProtected: 0, instancesWithoutBackup: 0, findings: { total: 0, high: 0, medium: 0, low: 0 } }, regions: [], findings: [], warnings: [] })) }).includes('Active security findings'), 'old reports still render');
// grouping: same finding type collapses into one entry with a count
const { groupFindings } = require('./findings');
const dup = (i, inst) => mapGuardDuty({ Id: 'd' + i, Type: 'Recon:EC2/PortProbeUnprotectedPort', Severity: 2, Title: 'Port probe', Description: 'd', Resource: { ResourceType: 'Instance', InstanceDetails: { InstanceId: inst } }, Service: { Count: 2, EventFirstSeen: '2026-11-0' + (1 + (i % 9)) + 'T00:00:00Z', EventLastSeen: '2026-11-1' + (i % 9) + 'T00:00:00Z' } }, region);
const many = Array.from({ length: 10 }, (_, i) => dup(i, i % 2 ? 'i-A' : 'i-B')).concat([g]);
const grp = groupFindings(many);
assert.strictEqual(grp.length, 2, 'two finding types');
const probe = grp.find((x) => x.type.startsWith('Recon'));
assert.strictEqual(probe.occurrences, 10); assert.strictEqual(probe.resourceCount, 2); assert.strictEqual(probe.eventCount, 20);
assert.strictEqual(grp[0].severity, 'HIGH', 'sorted by severity');
const insA = mapInspector({ findingArn: 'a1', title: 'CVE-9 - openssl', severity: 'HIGH', type: 'PACKAGE_VULNERABILITY', resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-1' }], packageVulnerabilityDetails: { vulnerabilityId: 'CVE-9', vulnerablePackages: [{ name: 'openssl', version: '1', fixedInVersion: '2' }] } }, region);
const insB = mapInspector({ findingArn: 'a2', title: 'CVE-9 - libssl', severity: 'HIGH', type: 'PACKAGE_VULNERABILITY', resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-2' }], packageVulnerabilityDetails: { vulnerabilityId: 'CVE-9', vulnerablePackages: [{ name: 'libssl', version: '1', fixedInVersion: '2' }] } }, region);
const gi = groupFindings([insA, insB]);
assert.strictEqual(gi.length, 1); assert.strictEqual(gi[0].occurrences, 2); assert.strictEqual(gi[0].recommendation.steps.length, 2);
const htmlG = renderHtml({ client: { name: 'A', accountId }, scan: { finishedAt: new Date().toISOString() },
  summary: { regionsScanned: 1, regionsWithInstances: 1, totalInstances: 2, instancesProtected: 0, instancesWithoutBackup: 1, findings: { total: 4, high: 2, medium: 2, low: 0 }, securityFindings: { total: 2, totalOccurrences: 11, guardduty: 2, securityhub: 0, inspector: 0, occurrences: { guardduty: 11, securityhub: 0, inspector: 0 }, critical: 0, high: 1, medium: 0, low: 1 } },
  regions, findings, warnings: [], securityFindings: { guardduty: grp, securityhub: [], inspector: [] } });
assert(!htmlG.includes('How to enable an AMI backup policy'), 'no how-to guide');
assert(htmlG.includes('lower-severity finding'), 'low severity hidden with note');
assert(!htmlG.includes('Port probe'), 'low severity finding not listed');
const bigHigh = Array.from({ length: 40 }, (_, i) => ({ ...grp[0], severity: 'HIGH', title: 'High ' + i, key: 'k' + i }));
const htmlBig = renderHtml({ client: { name: 'A', accountId }, scan: { finishedAt: new Date().toISOString() },
  summary: { regionsScanned: 1, regionsWithInstances: 1, totalInstances: 0, instancesProtected: 0, instancesWithoutBackup: 0, findings: { total: 0, high: 0, medium: 0, low: 0 }, securityFindings: { total: 40, totalOccurrences: 400, guardduty: 40, securityhub: 0, inspector: 0, occurrences: { guardduty: 400, securityhub: 0, inspector: 0 }, critical: 0, high: 40, medium: 0, low: 0 } },
  regions: [], findings: [], warnings: [], securityFindings: { guardduty: bigHigh, securityhub: [], inspector: [] } });
assert((htmlBig.match(/<td class="num">/g) || []).length === 25, 'capped at 25 per service');
assert(htmlBig.includes('15 more'), 'overflow noted');
assert(htmlG.includes('Enable an AMI backup policy'), 'AMI recommendation present');
assert(htmlG.includes('Report prepared by') && htmlG.includes('Infosprint Technologies Private Limited'), 'prepared by');
assert(htmlG.includes('Report prepared for') && htmlG.includes('A (111122223333)'), 'prepared for with account id');
const pos = ['<h2>1. Backup status and recommendations', '<h2>2. Network exposure and logging', '<h2>3. S3 buckets', '<h2>4. RDS databases', '<h2>5. CloudFront', '<h2>6. Amazon GuardDuty', '<h2>7. Amazon Inspector', '<h2>8. AWS Security Hub'].map((x) => htmlG.indexOf(x));
assert(pos.every((p) => p > 0) && pos.every((p, i) => i === 0 || p > pos[i - 1]), 'sections in order: backup, network, S3, RDS, CloudFront, then GuardDuty, Inspector, Security Hub');
assert(htmlG.indexOf('Why enabling an AMI backup policy is mandatory') < pos[1], 'backup info comes before network');
{
  const net = require('./network');
  const rule = (o) => ({ IpProtocol: 'tcp', FromPort: 22, ToPort: 22, IpRanges: [{ CidrIp: '0.0.0.0/0' }], Ipv6Ranges: [], ...o });
  const sevOf = (rules) => (net.evaluateSecurityGroup({ GroupId: 'sg-1', GroupName: 'x', VpcId: 'vpc-1', IpPermissions: rules }, true) || {}).severity;
  assert.strictEqual(sevOf([rule({})]), 'CRITICAL', 'SSH open is critical');
  assert.strictEqual(sevOf([rule({ FromPort: 443, ToPort: 443 })]), 'LOW', '443 open is low');
  assert.strictEqual(sevOf([rule({ IpRanges: [{ CidrIp: '10.0.0.0/8' }] })]), undefined, 'private range ignored');
  const rep = { ...JSON.parse(JSON.stringify({ client: { name: 'A', accountId }, scan: { finishedAt: new Date().toISOString() } })),
    summary: { regionsScanned: 1, regionsWithInstances: 0, totalInstances: 0, instancesProtected: 0, instancesWithoutBackup: 0, findings: { total: 0, high: 0, medium: 0, low: 0 } },
    regions: [], findings: [], warnings: [],
    network: { securityGroups: [{ region: 'us-east-1', groupId: 'sg-1', groupName: 'web', vpcId: 'vpc-1', severity: 'CRITICAL', ports: ['TCP 22'], inUse: true }],
      flowLogs: [{ region: 'us-east-1', vpcId: 'vpc-1', status: 'NONE', isDefault: true }], loadBalancers: [{ region: 'us-east-1', name: 'lb1', type: 'Application', scheme: 'internet-facing' }],
      cloudfront: [{ id: 'E123', domain: 'd.cloudfront.net', aliases: [] }], totals: { securityGroups: 1, vpcs: 1, loadBalancers: 1, cloudfrontDistributions: 1 } } };
  const hn = renderHtml(rep);
  for (const k of ['sg-1', 'TCP 22', 'vpc-1', 'lb1', 'E123', 'VPC Flow Logs record']) assert(hn.includes(k), 'network html has ' + k);
  global.__netRep = rep;
}

(async () => {
  const { buildDocx } = require('./docx');
  const buf = await buildDocx({
    client: { name: 'Acme <Corp>', accountId }, scan: { finishedAt: new Date().toISOString() },
    summary: { regionsScanned: 17, regionsWithInstances: 1, totalInstances: 2, instancesProtected: 0, instancesWithoutBackup: 1, findings: { total: 4, high: 2, medium: 2, low: 0 }, securityFindings: { total: 3, guardduty: 1, securityhub: 1, inspector: 1, critical: 1, high: 2, medium: 0, low: 0 } },
    regions, findings, warnings: ['us-east-1: example warning'], network: global.__netRep.network, securityFindings: { guardduty: [g], securityhub: [h], inspector: [n] },
  });
  assert.strictEqual(buf.slice(0, 2).toString(), 'PK', 'docx must be a zip');
  assert(buf.length > 5000);
  console.log('selftest passed');
})();
