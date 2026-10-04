#!/usr/bin/env node
// Prints fresh random values for the secrets in .env. Nothing is written to disk.
const { randomBytes } = require('crypto');
const r = (n) => randomBytes(n).toString('hex');
console.log('# Paste these into .env (each run produces new values)');
console.log(`JWT_SECRET=${r(48)}`);
console.log(`JWT_REFRESH_SECRET=${r(48)}`);
console.log(`API_KEY_HASH_PEPPER=${r(24)}`);
console.log(`BOOTSTRAP_ADMIN_PASSWORD=${r(12)}`);
