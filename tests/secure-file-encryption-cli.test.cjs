const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { webcrypto } = require('node:crypto');
const vm = require('node:vm');
const { encryptBytes } = require('../secure-file-encryption.js');
const html = readFileSync(require('node:path').join(__dirname, '../secure-file-encryption.html'), 'utf8');
const page = vm.createContext({ crypto: webcrypto, TextEncoder, TextDecoder, Uint8Array, DataView, atob });
vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], page);

test('CLI Base64 decrypts in the HTML page with exact binary bytes and filename', async () => {
  const password = '  café 🔑  ';
  for (const input of [Buffer.alloc(0), Buffer.from(Array.from({ length: 256 }, (_, i) => i))]) {
    const encrypted = await encryptBytes(password, input);
    const decoded = page.fromBase64(encrypted.toString('base64') + '\n');
    const recovered = await page.decryptBytes(password, decoded);
    assert.equal(recovered.filename, 'stdin.bin');
    assert.deepEqual(Buffer.from(recovered.bytes), input);
    await assert.rejects(page.decryptBytes('wrong', decoded), /Incorrect password/);
    assert.notDeepEqual(await encryptBytes(password, input), encrypted);
  }
  await assert.rejects(encryptBytes('', Buffer.alloc(0)), /empty/);
});
