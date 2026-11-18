'use strict';
// Network and logging checks: internet-open security groups, VPC flow logs,
// load balancer access logs and CloudFront logging.
const {
  EC2Client, DescribeSecurityGroupsCommand, DescribeNetworkInterfacesCommand, DescribeVpcsCommand,
  DescribeFlowLogsCommand, DescribeSubnetsCommand,
} = require('@aws-sdk/client-ec2');
const { ElasticLoadBalancingV2Client, DescribeLoadBalancersCommand, DescribeLoadBalancerAttributesCommand } = require('@aws-sdk/client-elastic-load-balancing-v2');
const {
  ElasticLoadBalancingClient, DescribeLoadBalancersCommand: DescribeClassicLbCommand,
  DescribeLoadBalancerAttributesCommand: DescribeClassicLbAttrsCommand,
} = require('@aws-sdk/client-elastic-load-balancing');
const { CloudFrontClient, ListDistributionsCommand, GetDistributionConfigCommand } = require('@aws-sdk/client-cloudfront');
const { CloudWatchLogsClient, DescribeDeliverySourcesCommand, DescribeDeliveriesCommand } = require('@aws-sdk/client-cloudwatch-logs');

const MAX_ATTEMPTS = 6;
const RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const errMsg = (e) => `${e.name || 'Error'}: ${e.message || e}`;
const tagName = (tags) => (tags || []).find((t) => t.Key === 'Name')?.Value || '';

async function collect(client, makeCommand, pick) {
  const out = [];
  let token;
  do {
    const res = await client.send(makeCommand(token));
    out.push(...(pick(res) || []));
    token = res.NextToken;
  } while (token);
  return out;
}

async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) { const i = next++; results[i] = await fn(items[i], i); }
  }));
  return results;
}

/* ---------- security groups: rules open to the whole internet ---------- */
const SENSITIVE = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS', 2181: 'ZooKeeper',
  2375: 'Docker', 2376: 'Docker TLS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'RabbitMQ', 5900: 'VNC',
  5984: 'CouchDB', 5985: 'WinRM', 5986: 'WinRM', 6379: 'Redis', 6443: 'Kubernetes API', 9092: 'Kafka', 9200: 'Elasticsearch',
  9300: 'Elasticsearch', 10250: 'Kubelet', 11211: 'Memcached', 27017: 'MongoDB',
};
const WEB_NAME = { 80: 'HTTP', 443: 'HTTPS' };
const PROTO = { 6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6' };

const openToWorld = (p) => (p.IpRanges || []).some((r) => r.CidrIp === '0.0.0.0/0') || (p.Ipv6Ranges || []).some((r) => r.CidrIpv6 === '::/0');

// CRITICAL: all traffic, administrative/database ports, or very wide port ranges.
// HIGH: any other port. LOW: only HTTP/HTTPS (80/443) or ICMP, which public web servers normally expose.
function classifyRule(p) {
  const proto = PROTO[String(p.IpProtocol)] || String(p.IpProtocol);
  if (proto === '-1') return { label: 'All traffic (all ports and protocols)', severity: 'CRITICAL' };
  if (proto === 'icmp' || proto === 'icmpv6') return { label: 'ICMP', severity: 'LOW' };
  if (proto !== 'tcp' && proto !== 'udp') return { label: `Protocol ${proto}`, severity: 'HIGH' };
  const from = p.FromPort ?? 0;
  const to = p.ToPort ?? 65535;
  const P = proto.toUpperCase();
  if (from === to) {
    if (SENSITIVE[from]) return { label: `${P} ${from} (${SENSITIVE[from]})`, severity: 'CRITICAL' };
    if (WEB_NAME[from]) return { label: `${P} ${from} (${WEB_NAME[from]})`, severity: 'LOW' };
    return { label: `${P} ${from}`, severity: 'HIGH' };
  }
  const hits = Object.keys(SENSITIVE).map(Number).filter((n) => n >= from && n <= to);
  if (hits.length || to - from >= 1000) {
    const names = [...new Set(hits.map((n) => SENSITIVE[n]))].slice(0, 4).join(', ');
    return { label: `${P} ${from}-${to}${names ? ` (includes ${names})` : ''}`, severity: 'CRITICAL' };
  }
  return { label: `${P} ${from}-${to}`, severity: 'HIGH' };
}

function evaluateSecurityGroup(sg, inUse) {
  const found = new Map();
  for (const p of sg.IpPermissions || []) {
    if (!openToWorld(p)) continue;
    const c = classifyRule(p);
    if (!found.has(c.label)) found.set(c.label, c);
  }
  if (!found.size) return null;
  const rules = [...found.values()].sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return {
    groupId: sg.GroupId, groupName: sg.GroupName, vpcId: sg.VpcId, severity: rules[0].severity,
    ports: rules.map((r) => r.label), inUse, // inUse: true / false / null (unknown)
  };
}

/* ---------- VPC flow logs ---------- */
function evaluateVpcs({ vpcs, flowLogs, subnets, enis }) {
  const active = flowLogs.filter((f) => f.FlowLogStatus === 'ACTIVE');
  const subnetVpc = new Map(subnets.map((s) => [s.SubnetId, s.VpcId]));
  const eniVpc = new Map(enis.map((e) => [e.NetworkInterfaceId, e.VpcId]));
  const out = [];
  // Only VPCs that actually host something (an attached network interface: EC2, RDS, load balancer, ...) are worth checking
  const inUse = new Set(enis.filter((e) => e.Status === 'in-use' || e.Attachment).map((e) => e.VpcId));
  for (const v of vpcs) {
    if (!inUse.has(v.VpcId)) continue;
    const vpcLevel = active.filter((f) => f.ResourceId === v.VpcId);
    const partial = active.filter((f) => subnetVpc.get(f.ResourceId) === v.VpcId || eniVpc.get(f.ResourceId) === v.VpcId);
    let status; let note = '';
    if (vpcLevel.some((f) => f.TrafficType === 'ALL')) continue;
    if (vpcLevel.length) { status = 'PARTIAL'; note = `Flow log captures ${[...new Set(vpcLevel.map((f) => f.TrafficType))].join('/')} traffic only`; }
    else if (partial.length) { status = 'PARTIAL'; note = 'Only some subnets or network interfaces have flow logs'; }
    else status = 'NONE';
    out.push({ vpcId: v.VpcId, name: tagName(v.Tags), cidr: v.CidrBlock, isDefault: Boolean(v.IsDefault), status, note });
  }
  return out;
}

/* ---------- one region ---------- */
async function scanNetworkRegion(region, accountId, credentials) {
  const out = { region, securityGroups: [], vpcs: [], loadBalancers: [], totals: { securityGroups: 0, vpcs: 0, loadBalancers: 0 }, errors: [] };
  const ec2 = new EC2Client({ region, credentials, maxAttempts: MAX_ATTEMPTS });
  const attempt = async (label, fn) => { try { return await fn(); } catch (e) { out.errors.push(`${label}: ${errMsg(e)}`); return null; } };

  const [sgs, enis, vpcs, flowLogs, subnets] = await Promise.all([
    attempt('Security groups', () => collect(ec2, (t) => new DescribeSecurityGroupsCommand({ NextToken: t }), (r) => r.SecurityGroups)),
    attempt('Network interfaces', () => collect(ec2, (t) => new DescribeNetworkInterfacesCommand({ NextToken: t }), (r) => r.NetworkInterfaces)),
    attempt('VPCs', () => collect(ec2, (t) => new DescribeVpcsCommand({ NextToken: t }), (r) => r.Vpcs)),
    attempt('Flow logs', () => collect(ec2, (t) => new DescribeFlowLogsCommand({ NextToken: t }), (r) => r.FlowLogs)),
    attempt('Subnets', () => collect(ec2, (t) => new DescribeSubnetsCommand({ NextToken: t }), (r) => r.Subnets)),
  ]);

  if (sgs) {
    out.totals.securityGroups = sgs.length;
    const used = enis ? new Set(enis.flatMap((e) => (e.Groups || []).map((g) => g.GroupId))) : null;
    for (const sg of sgs) {
      const ev = evaluateSecurityGroup(sg, used ? used.has(sg.GroupId) : null);
      if (ev) out.securityGroups.push({ region, ...ev });
    }
  }
  if (vpcs && flowLogs) {
    out.totals.vpcs = vpcs.length;
    out.vpcs = evaluateVpcs({ vpcs, flowLogs, subnets: subnets || [], enis: enis || [] }).map((v) => ({ region, ...v }));
  }

  // Application / Network load balancers
  await attempt('Load balancers (ALB/NLB)', async () => {
    const elb = new ElasticLoadBalancingV2Client({ region, credentials, maxAttempts: MAX_ATTEMPTS });
    const lbs = [];
    let marker;
    do {
      const res = await elb.send(new DescribeLoadBalancersCommand({ Marker: marker }));
      lbs.push(...(res.LoadBalancers || []));
      marker = res.NextMarker;
    } while (marker);
    const eligible = lbs.filter((l) => l.Type === 'application' || l.Type === 'network');
    out.totals.loadBalancers += eligible.length;
    await mapLimit(eligible, 5, async (lb) => {
      const a = await elb.send(new DescribeLoadBalancerAttributesCommand({ LoadBalancerArn: lb.LoadBalancerArn }));
      const on = (a.Attributes || []).find((x) => x.Key === 'access_logs.s3.enabled')?.Value === 'true';
      if (!on) out.loadBalancers.push({ region, name: lb.LoadBalancerName, type: lb.Type === 'application' ? 'Application' : 'Network', scheme: lb.Scheme, dns: lb.DNSName, vpcId: lb.VpcId });
    });
  });

  // Classic load balancers
  await attempt('Load balancers (Classic)', async () => {
    const elb = new ElasticLoadBalancingClient({ region, credentials, maxAttempts: MAX_ATTEMPTS });
    const lbs = [];
    let marker;
    do {
      const res = await elb.send(new DescribeClassicLbCommand({ Marker: marker }));
      lbs.push(...(res.LoadBalancerDescriptions || []));
      marker = res.NextMarker;
    } while (marker);
    out.totals.loadBalancers += lbs.length;
    await mapLimit(lbs, 5, async (lb) => {
      const a = await elb.send(new DescribeClassicLbAttrsCommand({ LoadBalancerName: lb.LoadBalancerName }));
      if (!a.LoadBalancerAttributes?.AccessLog?.Enabled) {
        out.loadBalancers.push({ region, name: lb.LoadBalancerName, type: 'Classic', scheme: lb.Scheme, dns: lb.DNSName, vpcId: lb.VPCId });
      }
    });
  });

  out.securityGroups.sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  return out;
}

/* ---------- CloudFront (global) ---------- */
async function scanCloudFront(credentials) {
  const out = { items: [], total: 0, errors: [] };
  const cf = new CloudFrontClient({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });
  const dists = [];
  let marker;
  try {
    do {
      const res = await cf.send(new ListDistributionsCommand({ Marker: marker }));
      const list = res.DistributionList;
      dists.push(...(list?.Items || []));
      marker = list?.IsTruncated ? list.NextMarker : undefined;
    } while (marker);
  } catch (e) { out.errors.push(`CloudFront: ${errMsg(e)}`); return out; }
  const live = dists.filter((d) => d.Enabled);
  out.total = dists.length;
  if (!live.length) return out;

  // Standard logging (v2) is configured through CloudWatch Logs vended-log deliveries, not the distribution config
  let v2Arns = null;
  try {
    const logs = new CloudWatchLogsClient({ region: 'us-east-1', credentials, maxAttempts: MAX_ATTEMPTS });
    const pages = async (Cmd, key) => {
      const items = []; let token;
      do { const res = await logs.send(new Cmd({ nextToken: token })); items.push(...(res[key] || [])); token = res.nextToken; } while (token);
      return items;
    };
    const [sources, deliveries] = await Promise.all([pages(DescribeDeliverySourcesCommand, 'deliverySources'), pages(DescribeDeliveriesCommand, 'deliveries')]);
    const delivered = new Set(deliveries.map((d) => d.deliverySourceName));
    v2Arns = new Set(sources.filter((s) => delivered.has(s.name)).flatMap((s) => s.resourceArns || []));
  } catch (e) { out.errors.push(`CloudFront standard logging (v2) could not be checked: ${errMsg(e)}`); }

  await mapLimit(live, 5, async (d) => {
    try {
      const res = await cf.send(new GetDistributionConfigCommand({ Id: d.Id }));
      const c = res.DistributionConfig || {};
      const behaviors = [c.DefaultCacheBehavior, ...(c.CacheBehaviors?.Items || [])].filter(Boolean);
      const legacy = Boolean(c.Logging?.Enabled);
      const realtime = behaviors.some((b) => b.RealtimeLogConfigArn);
      const v2 = v2Arns ? v2Arns.has(d.ARN) : null;
      if (!legacy && !realtime && v2 !== true) {
        out.items.push({
          id: d.Id, domain: d.DomainName, aliases: d.Aliases?.Items || [], comment: d.Comment || '', status: d.Status,
          note: v2 === null ? 'Standard logging (v2) could not be verified' : '',
        });
      }
    } catch (e) { out.errors.push(`CloudFront ${d.Id}: ${errMsg(e)}`); }
  });
  return out;
}

module.exports = { scanNetworkRegion, scanCloudFront, classifyRule, evaluateSecurityGroup, evaluateVpcs, openToWorld };
