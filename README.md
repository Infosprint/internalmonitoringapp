# Infosprint Monitoring

Multi-account AWS scanner with a React console and a Node.js API. **No database** – clients live in `data/clients.json`; every scan writes a separate report per client under `reports/<client>-<accountId>/` (HTML + JSON).

## What a scan checks (per client, using that client's read-only IAM role)

1. Assumes the client's role via STS and verifies it landed in the expected account.
2. Finds every enabled region and lists EC2 instances (pending/running/stopping/stopped).
3. **Only in regions that have instances**, checks whether **GuardDuty**, **Security Hub** and **Inspector (EC2 scanning)** are enabled. If not → recommendation with the reason it matters.
4. For every instance, checks backup coverage:
   - **PROTECTED** – an AWS Backup plan (protected resource) or a DLM snapshot/AMI lifecycle policy covers the instance or all its volumes
   - **PARTIAL** – only some volumes are covered
   - **MANUAL_ONLY** – snapshots/AMIs exist but no policy automates them
   - **NONE** – nothing at all → "backup is not enabled" recommendation
4b. **Network exposure and logging (all regions)**: security groups with ports open to `0.0.0.0/0` / `::/0` (Critical: all traffic, SSH/RDP/database/admin ports or wide ranges; High: other ports; 80/443 and ICMP only are counted, not listed), VPCs without flow logs, load balancers (ALB/NLB/Classic) without access logs, and CloudFront distributions without logging. Each comes with a reason and a recommendation, shown right after the backup section. Needs the extra read-only actions in the CloudFormation template (re-deploy/update the stack for existing clients).
5. Collects every **active GuardDuty, Security Hub and Inspector finding** in those regions (services that are enabled), each with the remediation the service gives:
   - **Security Hub** and **Inspector** – the remediation text/link from the finding itself (Inspector also lists the fixed package versions).
   - **GuardDuty** – the API returns no remediation text, so the report uses AWS's GuardDuty remediation guide for the finding's resource type (EC2, credentials, S3, EKS, runtime, ECS) with a link.
   - Security Hub findings that merely repeat GuardDuty/Inspector are left out; informational (passed) findings are skipped. Limit: 500 findings per service per region (most severe first), change with the `FINDINGS_CAP` environment variable. Anything cut off is noted in *Scan warnings*.
6. Writes `reports/<client>-<accountId>/<timestamp>.html` and `.json`.

Checks that fail (e.g. access denied) are listed under *Scan warnings* – they never produce a false "not enabled" recommendation.

## Sign-in and users

The console requires a sign-in (email + password). Users are stored in `data/users.json` (scrypt password hashes only; the file is git-ignored). Two roles: **User** (use the console) and **Admin** (also manage users).

- **First admin** (run on the machine that runs the app, in the project folder): `npm run create-admin`. Run it again with an existing email to reset that admin's password (recovery).
- **Admin page** (`Users` in the top bar): add an employee (name, email, initial password or *Generate*), edit name/email/role, reset a password, disable/enable, delete. Resetting or disabling ends that person's open sessions immediately.
- Everyone can change their own password under *Change password*.
- Passwords: 10-128 characters. 5 failed sign-ins lock that account/IP for 15 minutes. Sessions end after 8 idle hours (`SESSION_HOURS` to change) and at most 24 hours; a server restart signs everyone out.
- Behind nginx/HTTPS the proxy must send `X-Forwarded-Proto` and `X-Forwarded-For` (see the nginx block in the deployment notes) so the session cookie gets the `Secure` flag and rate limiting sees real client IPs. Set `COOKIE_SECURE=1` to force the flag.
- Tests: `npm test --prefix server` (report logic + sign-in/user rules + an HTTP run against the real app).

## Partner types, AMC details and logs

Each client has a partner type, set from the **General** tab of the client list (General / AMC partner / Billing partner).

- **Billing partner and General**: the standard scan only.
- **AMC partner**: the standard scan plus, per server: instance list, 8-day hourly CPU and RAM charts, EBS volumes with provisioned and (when the CloudWatch agent reports it) used/free space, load balancer / target group / Auto Scaling health, and whether VPC flow logs, load balancer logs and CloudTrail are enabled. The client page shows the same data in the console; it is also added to the HTML and Word reports.
- RAM and in-guest disk usage exist in CloudWatch only when the CloudWatch agent runs on the server. The scan checks SSM agent status and, when RAM metrics are missing, recommends installing the agent. The role stays read-only; nothing is run on the servers.
- **Logs page** (AMC clients, button "Logs"): tabs for VPC, CloudTrail, Load balancer and CloudFront. VPCs without flow logs are listed but cannot be fetched. Choose log types and a duration (1 hour, 24 hours, 1 week, 15 days, 30 days); one type gives one file, several types give one file each in a zip. Logs are read from the S3 buckets or CloudWatch Logs the client already uses (CloudTrail uses event history), capped at 300 MB per file and 3000 S3 objects (change with `LOG_MAX_BYTES`, `LOG_MAX_OBJECTS`). Exports live in `exports/` and are deleted after 24 hours; fetches and downloads are written to `data/audit.log`.
- Existing client roles need the extra read actions in `cloudformation/infosprint-readonly-role.yaml` unless they use the full ReadOnlyAccess managed policy (update the stack if the role was created from an older template).

## What the report contains

Server overview (AMC only, first), 1 Backup, 2 Network exposure and logging, 3 S3 buckets (size, objects, storage classes, bucket policy review, versioning, replication), 4 RDS (status, pending updates, 7-day CPU/RAM/storage, recommendations), 5 CloudFront (7-day requests, data transferred, 4xx/5xx and total error rates, cache hit rate and origin latency when additional metrics are on, invalidations, alarms and their state, logging, WAF, certificate expiry), then 6 GuardDuty, 7 Inspector, 8 Security Hub. The three security services list only findings first detected in the last 7 days (`FINDINGS_DAYS` changes this). Reports contain no charts: servers show 7-day average and peak. The 6-month CPU, RAM and storage charts are in the console (open a server's Details on an AMC client page).

## Run it (Windows PowerShell, in this project folder)

Prerequisites: Node.js 18+ and AWS credentials on the machine running the app (this is the identity that calls `sts:AssumeRole` into each client role – e.g. `aws configure`, `aws sso login`, or `AWS_PROFILE` / `AWS_ACCESS_KEY_ID` env vars).

```powershell
npm run setup      # installs root, server and client dependencies
npm run build      # builds the React console
npm start          # then open http://127.0.0.1:4000
```

Development with hot reload: `npm run dev` (UI on http://localhost:5173, API on :4000).

To use a specific profile: `$env:AWS_PROFILE="infosprint-admin"; npm start`

The server listens on `127.0.0.1` only (there is no login on the console).

## IAM setup in each client account

**Easiest: CloudFormation.** Give the client `cloudformation/infosprint-readonly-role.yaml`. In the client account: CloudFormation > Create stack > Upload template. Parameters: `TrustedPrincipal` (your Infosprint account ID or the ARN of the identity running this app), optional `RoleName` and `ExternalId`. The stack creates the role with the AWS-managed `ReadOnlyAccess` policy. Copy the `RoleArn` output into the console.

Or create the role by hand:

**Permissions on the client role** – attach the AWS-managed `ReadOnlyAccess` policy, or this minimal policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:DescribeRegions", "ec2:DescribeInstances", "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots", "ec2:DescribeImages",
      "guardduty:ListDetectors", "guardduty:GetDetector", "guardduty:ListFindings", "guardduty:GetFindings",
      "securityhub:DescribeHub", "securityhub:GetFindings",
      "inspector2:BatchGetAccountStatus", "inspector2:ListFindings",
      "backup:ListProtectedResources",
      "dlm:GetLifecyclePolicies", "dlm:GetLifecyclePolicy"
    ],
    "Resource": "*"
  }]
}
```

**Trust policy** – allow the identity running this app (replace the principal ARN; add the ExternalId condition if you use one):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<YOUR-INFOSPRINT-ACCOUNT>:user/<or role>" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<optional-external-id>" } }
  }]
}
```

The identity running the app also needs `sts:AssumeRole` on those role ARNs.

## Notes

- DLM policies are matched to an instance/volume when it carries at least one of the policy's target tags (key and value).
- `ReadOnlyAccess` also allows reading data such as S3 objects. If a client objects, use the minimal policy above instead.
- Scans can take a few minutes per account (regions are scanned 4 at a time).
- `data/clients.json` contains account IDs and role ARNs (no secrets). Add it to `.gitignore` if the repo is shared.

## Layout

```
data/clients.json     client list (created automatically)
reports/              generated reports, one folder per client
server/src            Express API, scanner, report generator
client/src            React console
```
