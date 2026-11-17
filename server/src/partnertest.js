'use strict';
const assert = require('assert');
const fs = require('fs'); const os = require('os'); const path = require('path');
process.env.EXPORT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'exp-'));
const logs = require('./logs');
const { renderAmcSection } = require('./amc-render');
const { lineChart } = require('./charts');
const { renderHtml } = require('./report');

assert.deepStrictEqual(logs.s3Parts('arn:aws:s3:::my-bucket/some/prefix/'), { bucket: 'my-bucket', prefix: 'some/prefix' });
assert.strictEqual(logs.s3Parts('arn:aws:logs:x'), null);
assert.strictEqual(logs.days(new Date('2026-01-01T10:00:00Z'), new Date('2026-01-03T01:00:00Z')).length, 3);
assert.strictEqual(logs.joinKey('', 'AWSLogs', '1/', 'x'), 'AWSLogs/1/x');
assert.ok(logs.DURATIONS['30d'] > logs.DURATIONS['15d']);
assert.throws(() => logs.createJob({ client: { id: 'c' }, user: { id: 'u' }, request: { selections: {}, duration: '1h' } }), /at least one/);
assert.throws(() => logs.createJob({ client: { id: 'c' }, user: { id: 'u' }, request: { selections: { vpc: ['a'] }, duration: '2h' } }), /Duration/);
assert.ok(lineChart({ series: [{ name: 'a', color: '#000', values: [1, null, 50] }], startMs: 0 }).includes('<path'));

const inst = { region: 'ap-south-1', instanceId: 'i-1', name: 'web', state: 'running', instanceType: 't3.micro', platform: 'Linux/UNIX', ssm: { status: 'NOT_INSTALLED' },
  cpu: { avg: [1, 2], max: [3, 4], average: 1.5, peak: 4 }, memory: null, storage: { volumes: [{ volumeId: 'vol-1', device: '/dev/xvda', sizeGiB: 8, type: 'gp3', encrypted: false }], provisionedGiB: 8, usedGiB: null, freeGiB: null, filesystems: [], note: '' },
  health: [{ kind: 'targetGroup', lb: 'alb', group: 'tg', state: 'unhealthy', reason: 'Target.Timeout' }], logging: { vpcFlowLogs: 'NONE', loadBalancerLogs: 'DISABLED', cloudtrail: 'ENABLED' }, recommendations: ['Install the Amazon CloudWatch agent'] };
const html = renderAmcSection({ amc: { period: { start: '2026-01-01T00:00:00Z', end: '2026-01-09T00:00:00Z', days: 8 }, instances: [inst], summary: { servers: 1, memoryMissing: 1, ssmMissing: 1, unhealthy: 1, flowLogsGaps: 1 } } }, 6);
assert.ok(html.includes('No RAM metrics') && html.includes('CloudWatch agent') && html.includes('Target.Timeout'));
console.log('partner/AMC tests passed');
