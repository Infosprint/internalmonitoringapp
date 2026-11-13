'use strict';
// Creates the first admin (or resets an admin's password if that email already exists).
// Run on the server:  npm run create-admin
// Non-interactive:    ADMIN_NAME=... ADMIN_EMAIL=... ADMIN_PASSWORD=... npm run create-admin
const readline = require('readline');
const auth = require('./auth');

function ask(question, hidden) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const write = rl._writeToOutput.bind(rl);
    rl._writeToOutput = (s) => { if (!rl.muted) write(s); };
    rl.question(question, (answer) => { rl.close(); if (hidden) process.stdout.write('\n'); resolve(answer); });
    rl.muted = !!hidden; // the prompt text is already printed; hide what is typed
  });
}

(async () => {
  const env = process.env;
  const name = env.ADMIN_NAME || await ask('Admin name: ');
  const email = env.ADMIN_EMAIL || await ask('Admin email: ');
  let password = env.ADMIN_PASSWORD;
  if (!password) {
    password = await ask(`Password (min ${auth.MIN_PW} characters): `, true);
    const again = await ask('Repeat password: ', true);
    if (password !== again) throw new Error('Passwords do not match');
  }
  const r = await auth.upsertAdmin({ name, email, password });
  console.log(r.created ? `Admin created: ${r.user.email}` : `Existing user ${r.user.email} is now an active admin and the password was reset.`);
})().catch((e) => { console.error(`Error: ${e.message}`); process.exit(1); });
