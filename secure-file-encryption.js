#!/usr/bin/env node
'use strict';

const { webcrypto: crypto } = require('node:crypto');
const { openSync, writeSync } = require('node:fs');
const { ReadStream } = require('node:tty');
const { createInterface } = require('node:readline');
const { Writable } = require('node:stream');

// Read from the controlling terminal, independently of piped stdin/stdout.
function readPassword() {
  return new Promise((resolve, reject) => {
    let fd;
    try { fd = openSync('/dev/tty', 'r+'); }
    catch { reject(new Error('A controlling terminal (/dev/tty) is required to enter a password.')); return; }
    const input = new ReadStream(fd);
    const output = new Writable({ write(chunk, encoding, done) { done(); } });
    const rl = createInterface({ input, output, terminal: true, historySize: 0 });
    let settled = false;
    function finish(error, password) {
      if (settled) return;
      settled = true;
      rl.close(); // Restores terminal echo/raw mode before releasing the fd.
      writeSync(fd, '\n');
      input.destroy();
      output.destroy();
      if (error) reject(error);
      else resolve(password);
    }
    input.on('error', error => finish(error));
    rl.on('SIGINT', () => finish(new Error('Password entry cancelled.')));
    rl.on('close', () => finish(new Error('Password entry cancelled.')));
    writeSync(fd, 'Password: ');
    rl.question('', password => finish(password ? null : new Error('Password must not be empty.'), password));
  });
}

async function encryptBytes(password, bytes, filename = 'stdin.bin') {
  if (!password) throw new Error('Password must not be empty.');
  const name = Buffer.from(filename, 'utf8');
  if (name.length > 65535) throw new Error('Filename is too long.');
  const header = Buffer.alloc(44);
  header.set([87, 69, 78, 67, 2, 1]); // WENC, version 2, suite 1.
  header.writeUInt16LE(16, 6);
  header.writeUInt16LE(32, 8);
  header.writeUInt16LE(44, 10);
  header.writeUInt32LE(600000, 12);
  crypto.getRandomValues(header.subarray(16, 32));
  crypto.getRandomValues(header.subarray(32, 44));
  const payload = Buffer.alloc(2 + name.length + bytes.length);
  payload.writeUInt16LE(name.length, 0);
  name.copy(payload, 2);
  payload.set(bytes, 2 + name.length);
  try {
    const material = await crypto.subtle.importKey('raw', Buffer.from(password, 'utf8'), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: header.subarray(16, 32), iterations: 600000, hash: 'SHA-256' },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: header.subarray(32, 44), additionalData: header, tagLength: 128 }, key, payload);
    return Buffer.concat([header, Buffer.from(ciphertext)]);
  } finally { payload.fill(0); }
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const bytes = Buffer.concat(chunks);
  try {
    const password = await readPassword();
    const encrypted = await encryptBytes(password, bytes);
    process.stdout.write(encrypted.toString('base64') + '\n');
  } finally {
    bytes.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

if (require.main === module) {
  process.stdout.on('error', error => {
    process.stderr.write(`Error: ${error.message}\n`);
    process.exitCode = 1;
  });
  main().catch(error => {
    process.stderr.write(`Error: ${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { encryptBytes };
