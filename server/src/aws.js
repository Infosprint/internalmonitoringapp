'use strict';
// Shared AWS helpers: role assumption, region listing, pagination, small utilities.
const { STSClient, AssumeRoleCommand } = require('@aws-sdk/client-sts');
const { EC2Client, DescribeRegionsCommand } = require('@aws-sdk/client-ec2');

const MAX_ATTEMPTS = 6;

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

async function collect(client, makeCommand, pick, nextKey = 'NextToken') {
  const out = [];
  let token;
  do {
    const res = await client.send(makeCommand(token));
    out.push(...(pick(res) || []));
    token = res[nextKey];
  } while (token);
  return out;
}

const errMsg = (e) => `${e.name || 'Error'}: ${e.message || e}`;
const tagMap = (tags) => Object.fromEntries((tags || []).map((t) => [t.Key, t.Value]));
const chunk = (arr, n) => Array.from({ length: Math.ceil(arr.length / n) }, (_, i) => arr.slice(i * n, i * n + n));

// Assume the client's read-only role; credentials refresh automatically before they expire.
function createCredentialProvider(client, sessionName = 'infosprint-monitoring-scan') {
  const sts = new STSClient({ region: 'us-east-1', maxAttempts: MAX_ATTEMPTS });
  let cached = null;
  let inflight = null;
  const refresh = async () => {
    const res = await sts.send(new AssumeRoleCommand({
      RoleArn: client.roleArn,
      RoleSessionName: sessionName,
      DurationSeconds: 3600,
      ExternalId: client.externalId || undefined,
    }));
    const c = res.Credentials;
    cached = { accessKeyId: c.AccessKeyId, secretAccessKey: c.SecretAccessKey, sessionToken: c.SessionToken, expiration: new Date(c.Expiration) };
    return cached;
  };
  return async () => {
    if (cached && cached.expiration.getTime() - Date.now() > 5 * 60 * 1000) return cached;
    if (!inflight) inflight = refresh().finally(() => { inflight = null; });
    return inflight;
  };
}

async function listRegions(credentials) {
  let lastErr;
  for (const home of ['us-east-1', 'ap-south-1', 'eu-west-1']) {
    try {
      const ec2 = new EC2Client({ region: home, credentials, maxAttempts: MAX_ATTEMPTS });
      const res = await ec2.send(new DescribeRegionsCommand({ AllRegions: false }));
      return res.Regions.map((r) => r.RegionName).sort();
    } catch (e) { lastErr = e; }
  }
  throw new Error(`Could not list regions: ${errMsg(lastErr)}`);
}

// redact the client's External ID from any message
const redact = (client, msg) => (client?.externalId ? String(msg).split(client.externalId).join('***') : String(msg));

module.exports = { MAX_ATTEMPTS, mapLimit, collect, errMsg, tagMap, chunk, createCredentialProvider, listRegions, redact };
