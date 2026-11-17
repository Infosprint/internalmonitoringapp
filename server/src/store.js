'use strict';
// JSON-file storage. No database: everything lives in <project>/data/clients.json
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const DATA_DIR = path.join(ROOT, 'data');
const FILE = path.join(DATA_DIR, 'clients.json');

const PARTNER_TYPES = ['general', 'amc', 'billing'];

function ensure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(FILE)) fs.writeFileSync(FILE, JSON.stringify({ clients: [] }, null, 2));
}

function readAll() {
  ensure();
  const parsed = JSON.parse(fs.readFileSync(FILE, 'utf8') || '{"clients":[]}');
  return Array.isArray(parsed.clients) ? parsed.clients : [];
}

function writeAll(clients) {
  ensure();
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify({ clients }, null, 2));
  fs.renameSync(tmp, FILE); // atomic replace so a crash never leaves a half-written file
}

function normalize(input, existing) {
  const clientName = String(input.clientName || '').trim();
  const accountId = String(input.accountId || '').trim();
  let role = String(input.roleArn || '').trim();
  const externalId = String(input.externalId || '').trim();

  if (!clientName) throw new Error('Client name is required');
  // AWS STS only accepts these characters in an External ID (2-1224 chars)
  if (externalId && !/^[\w+=,.@:\/-]{2,1224}$/.test(externalId)) {
    throw new Error('External ID may only contain letters, digits and + = , . @ : / - (2-1224 chars). Leave it blank if the stack was created without one.');
  }
  if (!/^\d{12}$/.test(accountId)) throw new Error('AWS account ID must be exactly 12 digits');
  if (!role) throw new Error('IAM role is required');

  if (!role.startsWith('arn:')) {
    if (!/^[\w+=,.@\-\/]+$/.test(role)) throw new Error('IAM role name contains invalid characters');
    role = `arn:aws:iam::${accountId}:role/${role.replace(/^\//, '')}`;
  }
  const m = role.match(/^arn:aws[a-z-]*:iam::(\d{12}):role\/.+$/);
  if (!m) throw new Error('IAM role must be a role name or a full role ARN');
  if (m[1] !== accountId) throw new Error(`Role ARN belongs to account ${m[1]}, but account ID is ${accountId}`);

  const now = new Date().toISOString();
  return {
    id: existing?.id || crypto.randomUUID(),
    clientName,
    accountId,
    roleArn: role,
    externalId,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
    lastScan: existing?.lastScan || null,
    partnerType: PARTNER_TYPES.includes(existing?.partnerType) ? existing.partnerType : 'general',
  };
}

const store = {
  list: () => readAll(),
  get: (id) => readAll().find((c) => c.id === id) || null,
  create(input) {
    const clients = readAll();
    const c = normalize(input);
    if (clients.some((x) => x.accountId === c.accountId)) {
      throw new Error(`Account ${c.accountId} is already registered`);
    }
    clients.push(c);
    writeAll(clients);
    return c;
  },
  update(id, input) {
    const clients = readAll();
    const i = clients.findIndex((c) => c.id === id);
    if (i < 0) throw Object.assign(new Error('Client not found'), { status: 404 });
    const c = normalize(input, clients[i]);
    if (clients.some((x) => x.id !== id && x.accountId === c.accountId)) {
      throw new Error(`Account ${c.accountId} is already registered`);
    }
    clients[i] = c;
    writeAll(clients);
    return c;
  },
  remove(id) {
    const clients = readAll();
    const next = clients.filter((c) => c.id !== id);
    if (next.length === clients.length) throw Object.assign(new Error('Client not found'), { status: 404 });
    writeAll(next);
  },
  setPartnerType(id, partnerType) {
    if (!PARTNER_TYPES.includes(partnerType)) throw new Error('Partner type must be general, amc or billing');
    const clients = readAll();
    const c = clients.find((x) => x.id === id);
    if (!c) throw Object.assign(new Error('Client not found'), { status: 404 });
    c.partnerType = partnerType;
    c.updatedAt = new Date().toISOString();
    writeAll(clients);
    return c;
  },
  setLastScan(id, lastScan) {
    const clients = readAll();
    const c = clients.find((x) => x.id === id);
    if (!c) return;
    c.lastScan = lastScan;
    writeAll(clients);
  },
  PARTNER_TYPES,
  paths: { ROOT, DATA_DIR, FILE, REPORTS_DIR: path.join(ROOT, 'reports') },
};

module.exports = store;
