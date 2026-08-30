#!/usr/bin/env node
/**
 * Writes SHA-256 gate hash into portal/gate.js + dashboard/gate.js.
 * The password is NEVER written to disk — only salt + hash.
 *
 * Usage (from repo root):
 *   node portal/set-gate-pass.mjs "YourStrongSecretPass"
 *
 * Keep the password in a password manager. Do not commit it.
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const pass = process.argv[2];
if (!pass || pass.length < 10) {
  console.error('Usage: node portal/set-gate-pass.mjs "<pass at least 10 chars>"');
  process.exit(1);
}

const salt = 'immortal.gate.v3';
const hash = crypto.createHash('sha256').update(salt + ':' + pass).digest('hex');

const body = `/* Gate config — HASH ONLY. Never put plaintext user/pass here.
 * Rotate with: node portal/set-gate-pass.mjs "NewPass"
 */
(function (w) {
  w.IMMORTAL_GATE = {
    salt: '${salt}',
    hash: '${hash}',
    maxAttempts: 5,
    lockMs: 15 * 60 * 1000,
    sessionMs: 4 * 60 * 60 * 1000,
  };
})(window);
`;

const root = path.join(__dirname, '..');
const targets = [
  path.join(root, 'portal', 'gate.js'),
  path.join(root, 'dashboard', 'gate.js'),
];

for (const file of targets) {
  fs.writeFileSync(file, body, 'utf8');
  console.log('updated', path.relative(root, file));
}

console.log('ok — password was NOT written to any file. Remember it yourself.');
