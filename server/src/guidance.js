'use strict';
// Shared wording used by the HTML and Word reports.

const AMI_RECOMMENDATION = 'Enable an AMI backup policy for this instance: an AWS Backup plan or an Amazon Data Lifecycle Manager (DLM) "EBS-backed AMI" policy that creates an AMI on a schedule, keeps a defined number of recovery points, and ideally copies them to a second region.';

const AMI_WHY = 'An AMI backup captures the whole server - operating system, installed software, settings and every attached EBS volume - so a failed, corrupted, ransomware-encrypted or terminated instance can be rebuilt quickly by launching a new instance from the latest AMI. Snapshots alone protect disk data only, and manual backups are routinely forgotten, so recovery points are missing or stale exactly when they are needed. An automated AMI policy gives a predictable recovery point (RPO) and recovery time (RTO), lets you roll back a bad patch or deployment, supports copies to another region or account for disaster recovery, and meets the backup expectations of most compliance frameworks (for example ISO 27001 and SOC 2). Without it, a single incident can mean permanent data loss and extended downtime for the client.';

// Resources affected by a (possibly grouped) finding
function affected(f, limit = 15) {
  const res = f.resources || (f.resource?.id ? [{ id: f.resource.id, type: f.resource.type, region: f.region }] : []);
  const total = f.resourceCount ?? res.length;
  const shown = res.slice(0, limit).map((r) => `${r.id || r.type || 'unknown'}${r.region ? ` [${r.region}]` : ''}`);
  return { total, shown, more: Math.max(0, total - shown.length) };
}

const PREPARED_BY = 'Infosprint Technologies Private Limited';

// Report order: GuardDuty, then Inspector, then Security Hub
const SERVICES = [
  ['guardduty', 'Amazon GuardDuty', 'Threat detection findings'],
  ['inspector', 'Amazon Inspector', 'Software vulnerability and network exposure findings'],
  ['securityhub', 'AWS Security Hub', 'Misconfiguration and compliance findings'],
];
const SERVICE_BY_NAME = { 'Amazon GuardDuty': 'guardduty', 'Amazon Inspector': 'inspector', 'AWS Security Hub': 'securityhub' };
const serviceOf = (f) => f.service || SERVICE_BY_NAME[f.resource];

// Recommendation shown next to each instance in the backup section (null = nothing to do)
function instanceRecommendation(i) {
  const st = i.backup?.status;
  if (st === 'PROTECTED') return null;
  if (st === 'UNKNOWN') return 'Backup status could not be checked for this instance. Verify the role can read EC2, AWS Backup and DLM, then scan again.';
  const base = 'Enable an AMI backup policy (AWS Backup plan or DLM "EBS-backed AMI" policy) so this instance gets automated, policy-protected backups.';
  if (st === 'NONE') return `Backup is not enabled for this instance. ${base}`;
  if (st === 'MANUAL_ONLY') return `Only manual backups exist, with no policy. ${base}`;
  if (st === 'PARTIAL') {
    const missing = (i.volumes || []).filter((v) => !v.policyCovered).map((v) => v.volumeId).join(', ');
    return `A policy covers only some volumes${missing ? ` (not covered: ${missing})` : ''}. ${base}`;
  }
  return base;
}

// ---- keeping reports short: only mandatory (critical/high) findings are listed ----
const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFORMATIONAL: 4 };
const MIN_SEVERITY = (process.env.REPORT_MIN_SEVERITY || 'HIGH').toUpperCase();
const MAX_PER_SERVICE = Number(process.env.REPORT_MAX_FINDINGS) || 25;
const LABELS = { CRITICAL: 'Critical', HIGH: 'Critical and High', MEDIUM: 'Critical, High and Medium', LOW: 'Critical, High, Medium and Low' };
const thresholdLabel = () => LABELS[MIN_SEVERITY] || LABELS.HIGH;

function selectFindings(list, cap = MAX_PER_SERVICE) {
  const limit = RANK[MIN_SEVERITY] ?? 1;
  const eligible = list.filter((f) => RANK[f.severity] <= limit);
  const shown = eligible.slice(0, cap);
  return { shown, total: list.length, belowThreshold: list.length - eligible.length, overflow: eligible.length - shown.length };
}

function findingsNote(sel) {
  const parts = [];
  if (sel.belowThreshold > 0) parts.push(`${sel.belowThreshold} lower-severity finding type${sel.belowThreshold === 1 ? '' : 's'} not listed (full detail is in the JSON export).`);
  if (sel.overflow > 0) parts.push(`${sel.overflow} more ${thresholdLabel()} finding type${sel.overflow === 1 ? '' : 's'} not listed (limit ${MAX_PER_SERVICE} per service; see the JSON export).`);
  return parts.join(' ');
}

const trunc = (s, n) => (s && s.length > n ? `${s.slice(0, n - 1).trimEnd()}…` : s || '');

// "Service not enabled" recommendations: one entry per service/problem, listing all regions
function groupServiceRecs(findings, key) {
  const map = new Map();
  for (const f of findings.filter((x) => x.category === 'Security service' && serviceOf(x) === key)) {
    const k = f.title.replace(f.region, '{r}');
    if (!map.has(k)) map.set(k, { severity: f.severity, why: f.why, recommendation: f.recommendation, template: k, regions: [] });
    map.get(k).regions.push(f.region);
  }
  return [...map.values()].map((x) => ({ ...x, title: x.template.replace('{r}', x.regions.join(', ')) }));
}

// ---- network and logging section ----
const NET = {
  sg: {
    why: 'A port open to 0.0.0.0/0 (or ::/0) can be reached by anyone on the internet. Attackers continuously scan for exposed SSH, RDP and database ports and then brute-force or exploit them, which leads to server compromise, data theft and ransomware. Rules that allow all traffic or administrative and database ports are critical; every other internet-facing port should be limited to the sources that really need it.',
    rec: 'Block this exposure: replace 0.0.0.0/0 with specific trusted IP ranges or security groups, or remove the rule. For administration (SSH 22 / RDP 3389) use AWS Systems Manager Session Manager or a VPN instead of opening the port to the internet.',
  },
  flow: {
    why: 'VPC Flow Logs record the IP traffic going to and from network interfaces. Without them there is no network evidence of who connected to your servers, which ports were probed, or where data was sent, so an incident or data leak cannot be investigated, and port scans or unusual outbound traffic go unnoticed. Most compliance frameworks also expect network traffic logging.',
    rec: 'Enable VPC Flow Logs (traffic type: All) on each VPC listed, delivered to CloudWatch Logs or an S3 bucket with a retention period.',
  },
  lb: {
    why: 'Load balancer access logs record every request the load balancer handles: client IP, request path, response code, latency and TLS details. Without them there is no record of who reached the application or which requests were attacks (scanners, injection attempts, brute force), and errors and slowdowns are much harder to troubleshoot or investigate after an incident.',
    rec: 'Enable access logs for each load balancer listed, delivered to an S3 bucket with a lifecycle/retention policy.',
  },
  cf: {
    why: 'CloudFront logs record every viewer request to the distribution: client IP, URL, status code and cache result. Without them there is no visibility into bot traffic, scraping, abuse or attack attempts at the edge, and no evidence for forensics or compliance.',
    rec: 'Enable standard logging for each CloudFront distribution listed, delivered to S3 or CloudWatch Logs.',
  },
};

// group items by region for compact tables: [{ region, items: [] }]
function byRegion(list) {
  const m = new Map();
  for (const x of list) { if (!m.has(x.region)) m.set(x.region, []); m.get(x.region).push(x); }
  return [...m.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([region, items]) => ({ region, items }));
}

const NET_CAP = 40;

function selectSecurityGroups(list) {
  const sel = selectFindings(list, NET_CAP);
  return { ...sel, note: [
    sel.belowThreshold > 0 ? `${sel.belowThreshold} security group${sel.belowThreshold === 1 ? '' : 's'} expose only low-risk ports to the internet (HTTP/HTTPS 80/443 or ICMP, normal for public web servers) and are not listed; see the JSON export.` : '',
    sel.overflow > 0 ? `${sel.overflow} more critical/high security group${sel.overflow === 1 ? '' : 's'} not listed (limit ${NET_CAP}); see the JSON export.` : '',
  ].filter(Boolean).join(' ') };
}

function capList(list) {
  return { shown: list.slice(0, NET_CAP), more: Math.max(0, list.length - NET_CAP) };
}

module.exports = { NET, byRegion, selectSecurityGroups, capList, NET_CAP, AMI_RECOMMENDATION, AMI_WHY, affected, PREPARED_BY, SERVICES, serviceOf, instanceRecommendation, selectFindings, findingsNote, thresholdLabel, trunc, groupServiceRecs, MAX_PER_SERVICE };
