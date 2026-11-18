'use strict';
// CloudFront service review: distributions, recent invalidations, 7-day traffic and error rates, alarms, certificate
// expiry and the items the AMC team should monitor. Read-only.
const { CloudFrontClient, ListDistributionsCommand, GetDistributionConfigCommand, ListInvalidationsCommand } = require('@aws-sdk/client-cloudfront');
const { CloudWatchClient, GetMetricDataCommand, DescribeAlarmsCommand } = require('@aws-sdk/client-cloudwatch');
const { ACMClient, DescribeCertificateCommand } = require('@aws-sdk/client-acm');
const { MAX_ATTEMPTS, mapLimit, errMsg, chunk } = require('./aws');

const DAYS = 7;
const r1 = (n) => Math.round(n * 10) / 10;

// What the AMC team should keep watching for CloudFront (shown in the report)
const MONITOR_LIST = [
  ['5xx error rate', 'Alert when 5xxErrorRate stays above 1-2% for 5-10 minutes. It usually means the origin is failing.', 'CloudWatch alarm on 5xxErrorRate (needs the distribution in us-east-1 metrics).'],
  ['4xx error rate', 'Watch for sudden rises (broken links, blocked requests, expired signed URLs).', 'CloudWatch alarm on 4xxErrorRate.'],
  ['Origin health and latency', 'Slow or failing origins surface as 5xx and high latency. Enable additional metrics for OriginLatency and cache hit rate.', 'Enable "Additional metrics" on the distribution.'],
  ['Cache hit ratio', 'A falling hit ratio raises origin load and cost. Review cache policies and query-string/header forwarding.', 'CacheHitRate (additional metrics).'],
  ['Invalidations', 'Check that invalidations complete and are not run constantly (the first 1,000 paths per month are free, then charged).', 'ListInvalidations; alert on InProgress for long periods.'],
  ['Traffic and data transfer', 'Spikes in Requests or BytesDownloaded may mean an attack, a bot, or a cost surprise.', 'CloudWatch alarm on Requests / BytesDownloaded against the normal range.'],
  ['TLS certificate expiry', 'An expired certificate takes the site down. ACM renews automatically only when DNS/email validation stays in place.', 'Alarm on days to expiry (ACM DaysToExpiry).'],
  ['WAF and security', 'Confirm a web ACL is attached and review blocked/allowed request trends.', 'AWS WAF metrics and logging.'],
  ['Access logging', 'Standard or real-time logs are needed for investigations and audits.', 'Logging enabled on each distribution.'],
  ['Origin failover and TLS policy', 'Use origin groups for resilience and a modern minimum TLS version (TLSv1.2_2021).', 'Review distribution configuration after any change.'],
];

function distributionRecommendations(d) {
  const recs = [];
  if (!d.enabled) return ['The distribution is disabled. Confirm this is intended; disabled distributions serve no traffic.'];
  if (!d.logging) recs.push('Enable access logging (standard logs to S3 or real-time logs) for investigations and audits.');
  if (!d.webAcl) recs.push('No AWS WAF web ACL is attached. Attach one to block common web attacks and bots.');
  if (!d.alarms) recs.push('No CloudWatch alarms exist for this distribution. Add alarms for 5xxErrorRate, 4xxErrorRate and Requests.');
  if (d.minTls && !/TLSv1\.2/.test(d.minTls)) recs.push(`Minimum TLS version is ${d.minTls}. Move to TLSv1.2_2021 or later.`);
  if (d.certificate && d.certificate.daysToExpiry !== null && d.certificate.daysToExpiry < 30) recs.push(`The viewer certificate expires in ${d.certificate.daysToExpiry} days. Check that ACM renewal/validation is working.`);
  if (d.metrics && d.metrics.errors5xxPeak >= 5) recs.push(`5xx error rate peaked at ${d.metrics.errors5xxPeak}% in the last ${DAYS} days. Check the origin health and logs.`);
  if (d.invalidations.inProgress > 0) recs.push(`${d.invalidations.inProgress} invalidation(s) are still in progress.`);
  if (d.invalidations.last7Days >= 50) recs.push(`${d.invalidations.last7Days} invalidations in the last ${DAYS} days. Prefer versioned file names to avoid frequent invalidations.`);
  return recs;
}

async function scanCloudFrontService({ credentials, onProgress = () => {} }) {
  const warnings = [];
  const cf = new CloudFrontClient({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });
  const items = []; let marker;
  do { const r = await cf.send(new ListDistributionsCommand({ Marker: marker })); items.push(...(r.DistributionList?.Items || [])); marker = r.DistributionList?.NextMarker; } while (marker);
  onProgress(`CloudFront: ${items.length} distribution(s)`);
  if (!items.length) return { distributions: [], monitorList: MONITOR_LIST, summary: { distributions: 0, withRecommendations: 0 }, warnings };

  const cw = new CloudWatchClient({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });
  const acm = new ACMClient({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });

  // alarms that watch CloudFront distributions
  const alarmed = new Map();
  try {
    let t;
    do {
      const r = await cw.send(new DescribeAlarmsCommand({ NextToken: t, AlarmTypes: ['MetricAlarm'] }));
      for (const a of r.MetricAlarms || []) {
        if (a.Namespace !== 'AWS/CloudFront') continue;
        const id = (a.Dimensions || []).find((d) => d.Name === 'DistributionId')?.Value;
        if (id) alarmed.set(id, (alarmed.get(id) || 0) + 1);
      }
      t = r.NextToken;
    } while (t);
  } catch (e) { warnings.push(`CloudFront alarms: ${errMsg(e)}`); }

  // 7-day traffic and errors
  const metrics = new Map();
  const end = new Date(); const start = new Date(end.getTime() - DAYS * 86400000);
  try {
    const qs = [];
    items.forEach((d, k) => {
      const dims = [{ Name: 'DistributionId', Value: d.Id }, { Name: 'Region', Value: 'Global' }];
      qs.push({ id: `r${k}`, metric: 'Requests', stat: 'Sum', dims }, { id: `e${k}`, metric: '5xxErrorRate', stat: 'Maximum', dims }, { id: `f${k}`, metric: '4xxErrorRate', stat: 'Maximum', dims }, { id: `b${k}`, metric: 'BytesDownloaded', stat: 'Sum', dims });
    });
    const res = new Map();
    for (const part of chunk(qs, 400)) {
      const r = await cw.send(new GetMetricDataCommand({ StartTime: start, EndTime: end, MetricDataQueries: part.map((q) => ({ Id: q.id, ReturnData: true, MetricStat: { Metric: { Namespace: 'AWS/CloudFront', MetricName: q.metric, Dimensions: q.dims }, Period: 86400, Stat: q.stat } })) }));
      for (const x of r.MetricDataResults || []) res.set(x.Id, x.Values || []);
    }
    items.forEach((d, k) => {
      const sum = (id) => (res.get(id) || []).reduce((s, x) => s + x, 0);
      const peak = (id) => ((res.get(id) || []).length ? r1(Math.max(...res.get(id))) : null);
      metrics.set(d.Id, { requests: Math.round(sum(`r${k}`)), bytesDownloadedGiB: r1(sum(`b${k}`) / 1024 ** 3), errors5xxPeak: peak(`e${k}`), errors4xxPeak: peak(`f${k}`) });
    });
  } catch (e) { warnings.push(`CloudFront metrics: ${errMsg(e)}`); }

  const distributions = [];
  await mapLimit(items, 5, async (d) => {
    const row = {
      id: d.Id, domain: d.DomainName, aliases: d.Aliases?.Items || [], comment: d.Comment || '', status: d.Status, enabled: Boolean(d.Enabled), priceClass: d.PriceClass, httpVersion: d.HttpVersion,
      origins: (d.Origins?.Items || []).map((o) => o.DomainName), webAcl: d.WebACLId || null, minTls: d.ViewerCertificate?.MinimumProtocolVersion || null,
      logging: null, certificate: null, alarms: alarmed.get(d.Id) || 0, metrics: metrics.get(d.Id) || null, invalidations: { last7Days: 0, inProgress: 0, recent: [] },
    };
    try { const c = await cf.send(new GetDistributionConfigCommand({ Id: d.Id })); row.logging = Boolean(c.DistributionConfig?.Logging?.Enabled); } catch (e) { warnings.push(`CloudFront ${d.Id}: config: ${errMsg(e)}`); }
    try {
      const r = await cf.send(new ListInvalidationsCommand({ DistributionId: d.Id, MaxItems: 50 }));
      const list = r.InvalidationList?.Items || [];
      row.invalidations = {
        last7Days: list.filter((i) => new Date(i.CreateTime).getTime() >= start.getTime()).length,
        inProgress: list.filter((i) => i.Status === 'InProgress').length,
        recent: list.slice(0, 5).map((i) => ({ id: i.Id, status: i.Status, created: i.CreateTime })),
      };
    } catch (e) { warnings.push(`CloudFront ${d.Id}: invalidations: ${errMsg(e)}`); }
    const arn = d.ViewerCertificate?.ACMCertificateArn;
    if (arn) {
      try { const c = (await acm.send(new DescribeCertificateCommand({ CertificateArn: arn }))).Certificate; row.certificate = { domain: c.DomainName, status: c.Status, notAfter: c.NotAfter, daysToExpiry: c.NotAfter ? Math.floor((new Date(c.NotAfter).getTime() - Date.now()) / 86400000) : null }; }
      catch (e) { warnings.push(`CloudFront ${d.Id}: certificate: ${errMsg(e)}`); }
    }
    row.recommendations = distributionRecommendations(row);
    distributions.push(row);
  });
  distributions.sort((a, b) => a.domain.localeCompare(b.domain));
  return { distributions, monitorList: MONITOR_LIST, summary: { distributions: distributions.length, withRecommendations: distributions.filter((d) => d.recommendations.length).length }, warnings };
}

module.exports = { scanCloudFrontService, distributionRecommendations, MONITOR_LIST };
