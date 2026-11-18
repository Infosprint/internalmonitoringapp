'use strict';
// CloudFront service review: distributions, recent invalidations, 7-day traffic and error rates, alarms, certificate
// expiry and the items the AMC team should monitor. Read-only.
const { CloudFrontClient, ListDistributionsCommand, GetDistributionConfigCommand, ListInvalidationsCommand } = require('@aws-sdk/client-cloudfront');
const { CloudWatchClient, GetMetricDataCommand, DescribeAlarmsCommand } = require('@aws-sdk/client-cloudwatch');
const { ACMClient, DescribeCertificateCommand } = require('@aws-sdk/client-acm');
const { MAX_ATTEMPTS, mapLimit, errMsg, chunk } = require('./aws');

const DAYS = 7;
const r1 = (n) => Math.round(n * 10) / 10;

function distributionRecommendations(d) {
  const recs = [];
  if (!d.enabled) return ['The distribution is disabled. Confirm this is intended; disabled distributions serve no traffic.'];
  if (!d.logging) recs.push('Enable access logging (standard logs to S3 or real-time logs) for investigations and audits.');
  if (!d.webAcl) recs.push('No AWS WAF web ACL is attached. Attach one to block common web attacks and bots.');
  if (!d.alarms) recs.push('No CloudWatch alarms exist for this distribution. Add alarms for 5xxErrorRate, 4xxErrorRate and Requests.');
  if (d.minTls && !/TLSv1\.2/.test(d.minTls)) recs.push(`Minimum TLS version is ${d.minTls}. Move to TLSv1.2_2021 or later.`);
  if (d.certificate && d.certificate.daysToExpiry !== null && d.certificate.daysToExpiry < 30) recs.push(`The viewer certificate expires in ${d.certificate.daysToExpiry} days. Check that ACM renewal/validation is working.`);
  if (d.metrics && d.metrics.errors5xxPeak >= 5) recs.push(`5xx error rate peaked at ${d.metrics.errors5xxPeak}% in the last ${DAYS} days. Check the origin health and logs.`);
  if (d.alarmsInAlarm > 0) recs.push(`${d.alarmsInAlarm} CloudWatch alarm(s) for this distribution are in ALARM state right now. Investigate immediately.`);
  if (d.metrics && !d.metrics.additionalMetrics && d.metrics.requests > 0) recs.push('Enable "Additional metrics" on the distribution so cache hit rate and origin latency can be monitored and reported.');
  if (d.metrics && d.metrics.cacheHitRate !== null && d.metrics.cacheHitRate < 50) recs.push(`Cache hit rate is only ${d.metrics.cacheHitRate}%. Review cache policies, TTLs and query-string/header forwarding to cut origin load.`);
  if (d.metrics && d.metrics.originLatencyPeakMs !== null && d.metrics.originLatencyPeakMs >= 3000) recs.push(`Origin latency peaked at ${d.metrics.originLatencyPeakMs} ms. Check origin performance and capacity.`);
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
  if (!items.length) return { distributions: [], summary: { distributions: 0, withRecommendations: 0 }, warnings };

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
        if (id) { const cur = alarmed.get(id) || { total: 0, inAlarm: 0 }; cur.total += 1; if (a.StateValue === 'ALARM') cur.inAlarm += 1; alarmed.set(id, cur); }
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
      qs.push({ id: `r${k}`, metric: 'Requests', stat: 'Sum', dims }, { id: `e${k}`, metric: '5xxErrorRate', stat: 'Maximum', dims }, { id: `E${k}`, metric: '5xxErrorRate', stat: 'Average', dims },
        { id: `f${k}`, metric: '4xxErrorRate', stat: 'Maximum', dims }, { id: `F${k}`, metric: '4xxErrorRate', stat: 'Average', dims }, { id: `t${k}`, metric: 'TotalErrorRate', stat: 'Average', dims },
        { id: `b${k}`, metric: 'BytesDownloaded', stat: 'Sum', dims },
        // these two exist only when 'Additional metrics' is turned on for the distribution
        { id: `h${k}`, metric: 'CacheHitRate', stat: 'Average', dims }, { id: `l${k}`, metric: 'OriginLatency', stat: 'Average', dims }, { id: `L${k}`, metric: 'OriginLatency', stat: 'Maximum', dims });
    });
    const res = new Map();
    for (const part of chunk(qs, 400)) {
      const r = await cw.send(new GetMetricDataCommand({ StartTime: start, EndTime: end, MetricDataQueries: part.map((q) => ({ Id: q.id, ReturnData: true, MetricStat: { Metric: { Namespace: 'AWS/CloudFront', MetricName: q.metric, Dimensions: q.dims }, Period: 86400, Stat: q.stat } })) }));
      for (const x of r.MetricDataResults || []) res.set(x.Id, x.Values || []);
    }
    items.forEach((d, k) => {
      const sum = (id) => (res.get(id) || []).reduce((s, x) => s + x, 0);
      const peak = (id) => ((res.get(id) || []).length ? r1(Math.max(...res.get(id))) : null);
      const avg = (id) => { const v = res.get(id) || []; return v.length ? r1(v.reduce((s, x) => s + x, 0) / v.length) : null; };
      metrics.set(d.Id, {
        requests: Math.round(sum(`r${k}`)), bytesDownloadedGiB: r1(sum(`b${k}`) / 1024 ** 3),
        errors5xxPeak: peak(`e${k}`), errors5xxAvg: avg(`E${k}`), errors4xxPeak: peak(`f${k}`), errors4xxAvg: avg(`F${k}`), totalErrorAvg: avg(`t${k}`),
        cacheHitRate: avg(`h${k}`), originLatencyAvgMs: avg(`l${k}`), originLatencyPeakMs: peak(`L${k}`), additionalMetrics: (res.get(`h${k}`) || []).length > 0 || (res.get(`l${k}`) || []).length > 0,
      });
    });
  } catch (e) { warnings.push(`CloudFront metrics: ${errMsg(e)}`); }

  const distributions = [];
  await mapLimit(items, 5, async (d) => {
    const row = {
      id: d.Id, domain: d.DomainName, aliases: d.Aliases?.Items || [], comment: d.Comment || '', status: d.Status, enabled: Boolean(d.Enabled), priceClass: d.PriceClass, httpVersion: d.HttpVersion,
      origins: (d.Origins?.Items || []).map((o) => o.DomainName), webAcl: d.WebACLId || null, minTls: d.ViewerCertificate?.MinimumProtocolVersion || null,
      logging: null, certificate: null, alarms: (alarmed.get(d.Id) || {}).total || 0, alarmsInAlarm: (alarmed.get(d.Id) || {}).inAlarm || 0, metrics: metrics.get(d.Id) || null, invalidations: { last7Days: 0, inProgress: 0, recent: [] },
    };
    try { const c = await cf.send(new GetDistributionConfigCommand({ Id: d.Id })); row.logging = Boolean(c.DistributionConfig?.Logging?.Enabled); } catch (e) { warnings.push(`CloudFront ${d.Id}: config: ${errMsg(e)}`); }
    try {
      const r = await cf.send(new ListInvalidationsCommand({ DistributionId: d.Id, MaxItems: 50 }));
      const list = r.InvalidationList?.Items || [];
      row.invalidations = {
        last7Days: list.filter((i) => new Date(i.CreateTime).getTime() >= start.getTime()).length,
        inProgress: list.filter((i) => i.Status === 'InProgress').length,
        recent: list.slice(0, 10).map((i) => ({ id: i.Id, status: i.Status, created: i.CreateTime })),
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
  return { distributions, summary: { distributions: distributions.length, withRecommendations: distributions.filter((d) => d.recommendations.length).length }, warnings };
}

module.exports = { scanCloudFrontService, distributionRecommendations };
