'use strict';
// Wording shown in place of a missing value, shared by the report, the Word file and the console.
const NO_RAM_SSM = 'Install and enable the SSM agent on this EC2 machine to collect RAM input';
const NO_RAM_CW = 'Enable the CloudWatch agent memory metric (mem_used_percent) on this EC2 machine to collect RAM input';
const NO_STORAGE = 'Enable CloudWatch metric to collect storage inputs';
const STOPPED = 'Server is stopped';

function ramNote(i) {
  if (i.memory) return null;
  if (i.state !== 'running') return STOPPED;
  return i.ssm && (i.ssm.status === 'NOT_INSTALLED' || i.ssm.status === 'OFFLINE') ? NO_RAM_SSM : NO_RAM_CW;
}
function storageNote(i) {
  if (i.storage.usedGiB !== null && i.storage.freeGiB !== null) return null;
  return i.state !== 'running' ? STOPPED : NO_STORAGE;
}
module.exports = { ramNote, storageNote };
