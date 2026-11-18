'use strict';
// Collects ACTIVE findings from GuardDuty, Security Hub and Inspector for one region,
// each with a remediation recommendation.
const { GuardDutyClient, ListDetectorsCommand, ListFindingsCommand, GetFindingsCommand } = require('@aws-sdk/client-guardduty');
const { SecurityHubClient, GetFindingsCommand: ShGetFindingsCommand } = require('@aws-sdk/client-securityhub');
const { Inspector2Client, ListFindingsCommand: InsListFindingsCommand } = require('@aws-sdk/client-inspector2');

const CAP = Number(process.env.FINDINGS_CAP) || 500; // max findings per service per region
const MAX_ATTEMPTS = 6;
// Only findings first detected within this many days are collected (the report covers the last 7 days)
const FINDINGS_DAYS = Number(process.env.FINDINGS_DAYS) || 7;
const sinceDate = () => new Date(Date.now() - FINDINGS_DAYS * 24 * 3600 * 1000);
const DOCS = 'https://docs.aws.amazon.com/guardduty/latest/ug';
const errMsg = (e) => `${e.name || 'Error'}: ${e.message || e}`;
const chunk = (arr, n) => Array.from({ length: Math.ceil(arr.length / n) }, (_, i) => arr.slice(i * n, i * n + n));

/* ---------- severity helpers ---------- */
function gdSeverity(score) {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}
const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4 };
const normLabel = (l) => (SEV_RANK[l] !== undefined ? l : 'INFORMATIONAL'); // Inspector "UNTRIAGED" -> INFORMATIONAL

/* ---------- GuardDuty ---------- */
// GuardDuty's API returns no remediation text, so guidance is taken from AWS's published
// "Remediating GuardDuty findings" pages, chosen by the finding's resource type.
function gdRecommendation(f) {
  const type = f.Type || '';
  const seg = (type.split(':')[1] || '').split('/')[0];
  const rt = f.Resource?.ResourceType || '';
  const suppress = 'If the activity was expected in this environment, create a GuardDuty suppression rule instead of remediating.';

  if (rt === 'Instance' || seg === 'EC2') {
    return {
      text: 'Treat the EC2 instance as potentially compromised and follow the AWS GuardDuty EC2 remediation guide.',
      url: `${DOCS}/compromised-ec2.html`,
      steps: [
        'Identify the instance from the finding and review what the finding type says it did.',
        'Isolate it: create an isolation security group (no inbound/outbound), attach it and remove all other security groups.',
        'Snapshot its EBS volumes for forensics before changing anything else.',
        'Revoke/rotate the credentials of the instance profile role, since they may have been exfiltrated.',
        'Find and stop the unauthorized activity or malware (GuardDuty on-demand malware scan can help).',
        'If you cannot clean it with confidence, terminate it and relaunch from a known-good AMI.',
        suppress,
      ],
    };
  }
  if (rt === 'AccessKey' || seg === 'IAMUser' || seg === 'IAMRole') {
    return {
      text: 'Treat the AWS credentials as compromised and follow the AWS GuardDuty credentials remediation guide.',
      url: `${DOCS}/compromised-creds.html`,
      steps: [
        'Identify the access key / IAM user or role named in the finding.',
        'Deactivate and rotate the access key, or reset the user password; for roles, revoke active sessions.',
        'Review CloudTrail for what the credentials did and remove any unauthorized resources or permissions.',
        'Move workloads to IAM roles instead of long-lived access keys where possible.',
        suppress,
      ],
    };
  }
  if (rt.startsWith('EKS') || seg === 'Kubernetes') {
    return { text: 'Follow the AWS GuardDuty EKS Protection remediation guide for the affected user, pod or node.', url: `${DOCS}/guardduty-remediate-kubernetes.html`, steps: [suppress] };
  }
  if (seg === 'Runtime') {
    return { text: 'Follow the AWS GuardDuty Runtime Monitoring remediation guide for the affected instance, container or cluster.', url: `${DOCS}/guardduty-remediate-runtime-monitoring.html`, steps: [suppress] };
  }
  if (rt.startsWith('ECS') || rt === 'Container') {
    return { text: 'Follow the AWS GuardDuty guidance for compromised ECS clusters / standalone containers.', url: `${DOCS}/compromised-ecs.html`, steps: [suppress] };
  }
  if (rt === 'S3Bucket' || seg === 'S3') {
    return {
      text: 'Follow the AWS GuardDuty S3 remediation guide.',
      url: `${DOCS}/guardduty_remediate.html`,
      steps: [
        'Review the bucket policy and ACLs named in the finding and remove unintended public or cross-account access.',
        'Enable S3 Block Public Access for the bucket (and the account) unless public access is required.',
        'Review CloudTrail data events for the principal that accessed the bucket and rotate its credentials if suspicious.',
        suppress,
      ],
    };
  }
  return { text: 'Follow the AWS GuardDuty remediation guide for this finding type.', url: `${DOCS}/guardduty_remediate.html`, steps: [suppress] };
}

function gdResourceId(r = {}) {
  return r.InstanceDetails?.InstanceId
    || (r.AccessKeyDetails && `${r.AccessKeyDetails.UserName || ''}${r.AccessKeyDetails.AccessKeyId ? ` (${r.AccessKeyDetails.AccessKeyId})` : ''}`.trim())
    || r.S3BucketDetails?.[0]?.Name
    || r.EksClusterDetails?.Name
    || r.RdsDbInstanceDetails?.DbInstanceIdentifier
    || r.LambdaDetails?.FunctionName
    || r.ContainerDetails?.Name
    || r.EcsClusterDetails?.Name
    || '';
}

function mapGuardDuty(f, region) {
  return {
    source: 'GuardDuty', id: f.Id, region: f.Region || region,
    severity: gdSeverity(f.Severity), score: f.Severity,
    title: f.Title, type: f.Type, description: f.Description,
    resource: { type: f.Resource?.ResourceType || '', id: gdResourceId(f.Resource) },
    firstSeen: f.Service?.EventFirstSeen, lastSeen: f.Service?.EventLastSeen, count: f.Service?.Count,
    recommendation: gdRecommendation(f),
  };
}

async function guarddutyFindings(region, credentials) {
  const gd = new GuardDutyClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  const det = await gd.send(new ListDetectorsCommand({}));
  const detectorId = (det.DetectorIds || [])[0];
  if (!detectorId) return { items: [], truncated: false };

  const ids = [];
  let token;
  do {
    const res = await gd.send(new ListFindingsCommand({
      DetectorId: detectorId, MaxResults: 50, NextToken: token,
      SortCriteria: { AttributeName: 'severity', OrderBy: 'DESC' },
      FindingCriteria: { Criterion: { 'service.archived': { Eq: ['false'] }, createdAt: { GreaterThanOrEqual: sinceDate().getTime() } } },
    }));
    ids.push(...(res.FindingIds || []));
    token = res.NextToken;
  } while (token && ids.length < CAP);
  const truncated = Boolean(token) || ids.length > CAP;
  const wanted = ids.slice(0, CAP);

  const items = [];
  for (const batch of chunk(wanted, 50)) {
    const res = await gd.send(new GetFindingsCommand({ DetectorId: detectorId, FindingIds: batch }));
    items.push(...(res.Findings || []).map((f) => mapGuardDuty(f, region)));
  }
  return { items, truncated };
}

/* ---------- Security Hub ---------- */
function mapSecurityHub(f, region) {
  const res = (f.Resources || [])[0] || {};
  const rec = f.Remediation?.Recommendation || {};
  return {
    source: 'Security Hub', id: f.Id, region: f.Region || region,
    severity: normLabel(f.Severity?.Label), score: f.Severity?.Normalized,
    title: f.Title, type: (f.Types || [])[0] || f.GeneratorId, description: f.Description,
    resource: { type: res.Type || '', id: res.Id || '' },
    extra: { product: f.ProductName, compliance: f.Compliance?.Status, workflow: f.Workflow?.Status },
    firstSeen: f.FirstObservedAt || f.CreatedAt, lastSeen: f.UpdatedAt,
    recommendation: {
      text: rec.Text || 'Security Hub provided no remediation text for this finding. Review the finding in the Security Hub console.',
      url: rec.Url || '', steps: [],
    },
  };
}

async function securityHubFindings(region, credentials) {
  const sh = new SecurityHubClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  // Active, not suppressed/resolved, not informational (passed controls). GuardDuty and Inspector
  // findings are excluded here because they are collected directly from those services.
  const Filters = {
    RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }],
    WorkflowStatus: [{ Value: 'NEW', Comparison: 'EQUALS' }, { Value: 'NOTIFIED', Comparison: 'EQUALS' }],
    SeverityLabel: [{ Value: 'INFORMATIONAL', Comparison: 'NOT_EQUALS' }],
    CreatedAt: [{ DateRange: { Value: FINDINGS_DAYS, Unit: 'DAYS' } }],
    ProductName: [{ Value: 'GuardDuty', Comparison: 'NOT_EQUALS' }, { Value: 'Inspector', Comparison: 'NOT_EQUALS' }],
  };
  const items = [];
  let token;
  do {
    const res = await sh.send(new ShGetFindingsCommand({
      Filters, MaxResults: 100, NextToken: token,
      SortCriteria: [{ Field: 'SeverityNormalized', SortOrder: 'desc' }],
    }));
    items.push(...(res.Findings || []).map((f) => mapSecurityHub(f, region)));
    token = res.NextToken;
  } while (token && items.length < CAP);
  const truncated = Boolean(token) || items.length > CAP;
  return { items: items.slice(0, CAP), truncated };
}

/* ---------- Inspector ---------- */
function mapInspector(f, region) {
  const res = (f.resources || [])[0] || {};
  const pv = f.packageVulnerabilityDetails;
  const steps = [];
  for (const p of (pv?.vulnerablePackages || []).slice(0, 8)) {
    steps.push(p.fixedInVersion
      ? `Update ${p.name} from ${p.version} to ${p.fixedInVersion} or later.`
      : `${p.name} ${p.version}: no fixed version published yet. Apply mitigations or monitor for a patch.`);
    if (p.remediation) steps.push(p.remediation);
  }
  const rec = f.remediation?.recommendation || {};
  return {
    source: 'Inspector', id: f.findingArn, region,
    severity: normLabel(f.severity), score: f.inspectorScore,
    title: f.title, type: f.type, description: f.description,
    resource: { type: res.type || '', id: res.id || '' },
    extra: {
      cve: pv?.vulnerabilityId, exploitAvailable: f.exploitAvailable, fixAvailable: f.fixAvailable,
      status: f.status,
    },
    firstSeen: f.firstObservedAt, lastSeen: f.lastObservedAt,
    recommendation: { text: rec.text || 'Review the finding in the Inspector console.', url: rec.Url || rec.url || '', steps },
  };
}

async function inspectorFindings(region, credentials) {
  const ins = new Inspector2Client({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  const items = [];
  let token;
  do {
    const res = await ins.send(new InsListFindingsCommand({
      maxResults: 100, nextToken: token,
      filterCriteria: { findingStatus: [{ comparison: 'EQUALS', value: 'ACTIVE' }], firstObservedAt: [{ startInclusive: sinceDate() }] },
      sortCriteria: { field: 'SEVERITY', sortOrder: 'DESC' },
    }));
    items.push(...(res.findings || []).map((f) => mapInspector(f, region)));
    token = res.nextToken;
  } while (token && items.length < CAP);
  const truncated = Boolean(token) || items.length > CAP;
  return { items: items.slice(0, CAP), truncated };
}

/* ---------- grouping: one entry per finding type ---------- */
function groupKey(f) {
  if (f.source === 'GuardDuty') return `GD|${f.type || f.title}`;
  if (f.source === 'Security Hub') return `SH|${f.title}`;
  return `IN|${f.extra?.cve || f.title}`; // Inspector: one entry per CVE
}

const minDate = (a, b) => (!a ? b : !b ? a : new Date(a) < new Date(b) ? a : b);
const maxDate = (a, b) => (!a ? b : !b ? a : new Date(a) > new Date(b) ? a : b);
const MAX_RESOURCES = 50;

// Collapses repeated findings of the same type into a single entry with an occurrence count.
function groupFindings(list) {
  const map = new Map();
  for (const f of list) {
    const key = groupKey(f);
    let g = map.get(key);
    if (!g) {
      g = {
        source: f.source, key, title: f.title, type: f.type, severity: f.severity, score: f.score,
        description: f.description, extra: { ...(f.extra || {}) },
        recommendation: { text: f.recommendation?.text, url: f.recommendation?.url, steps: [...(f.recommendation?.steps || [])] },
        occurrences: 0, eventCount: 0, resourceCount: 0, resources: [], regions: [], firstSeen: f.firstSeen, lastSeen: f.lastSeen,
        _seen: new Set(),
      };
      map.set(key, g);
    }
    g.occurrences += 1;
    g.eventCount += f.count || 0;
    if (SEV_RANK[f.severity] < SEV_RANK[g.severity]) g.severity = f.severity;
    if ((f.score || 0) > (g.score || 0)) g.score = f.score;
    const rk = `${f.region}|${f.resource?.id || ''}`;
    if (!g._seen.has(rk)) {
      g._seen.add(rk);
      g.resourceCount += 1;
      if (g.resources.length < MAX_RESOURCES) g.resources.push({ id: f.resource?.id || '', type: f.resource?.type || '', region: f.region });
    }
    if (!g.regions.includes(f.region)) g.regions.push(f.region);
    g.firstSeen = minDate(g.firstSeen, f.firstSeen);
    g.lastSeen = maxDate(g.lastSeen, f.lastSeen);
    for (const st of f.recommendation?.steps || []) {
      if (g.recommendation.steps.length < 12 && !g.recommendation.steps.includes(st)) g.recommendation.steps.push(st);
    }
  }
  return [...map.values()]
    .map(({ _seen, ...g }) => g)
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.occurrences - a.occurrences || (b.score || 0) - (a.score || 0));
}

/* ---------- entry point ---------- */
async function collectFindings(region, credentials, services) {
  const jobs = [];
  if (services.guardduty.status === 'ENABLED') jobs.push(['GuardDuty', guarddutyFindings]);
  if (services.securityhub.status === 'ENABLED') jobs.push(['Security Hub', securityHubFindings]);
  if (services.inspector.status === 'ENABLED' || services.inspector.status === 'PARTIAL') jobs.push(['Inspector', inspectorFindings]);

  const results = await Promise.all(jobs.map(async ([source, fn]) => {
    try { return { source, ...(await fn(region, credentials)) }; }
    catch (e) { return { source, items: [], truncated: false, error: errMsg(e) }; }
  }));
  return {
    items: results.flatMap((r) => r.items),
    meta: results.map((r) => ({ source: r.source, count: r.items.length, truncated: r.truncated, error: r.error })),
  };
}

module.exports = { groupFindings, collectFindings, gdSeverity, gdRecommendation, mapGuardDuty, mapSecurityHub, mapInspector, SEV_RANK, CAP };
