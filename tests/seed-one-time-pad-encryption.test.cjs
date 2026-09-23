// Run with: node --test tests/seed-one-time-pad-encryption.test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { createContext, runInContext } = require('node:vm');
const { webcrypto, createHash, randomBytes } = require('node:crypto');
const html = readFileSync(resolve(__dirname, '../seed-one-time-pad-encryption.html'), 'utf8');
function setup(crypto = webcrypto) {
  const nodes = new Map();
  function node(key) {
    if (!nodes.has(key)) nodes.set(key, {
      value: '', textContent: '', hidden: true, open: false, disabled: true,
      classList: { add() {}, remove() {}, toggle() {} }, events: {},
      addEventListener(type, fn) { this.events[type] = fn; },
      removeAttribute(key) { delete this[key]; }, setAttribute(key, value) { this[key] = value; },
      close() { this.open = false; }, showModal() { this.open = true; }
    });
    return nodes.get(key);
  }
  const qrButtons = [node('qr-pad'), node('qr-ciphertext')];
  const context = createContext({ crypto, Uint8Array, console,
    document: { querySelector: node, querySelectorAll: selector => selector === '[data-show-qr], [data-download-qr]' ? qrButtons : [] },
    window: { addEventListener() {}, requestAnimationFrame(fn) { fn(); } }
  });
  for (const script of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) runInContext(script[1], context);
  return { context, node, evaluate: source => runInContext(source, context) };
}
const known = 'abandon '.repeat(11) + 'about';
test('BIP39 known vectors preserve exactly 132 bits and leading zeros', async () => {
  const { evaluate } = setup();
  for (const [phrase, expected] of [
    [known, '0'.repeat(32) + '3'],
    ['legal winner thank year wave sausage worth useful legal winner thank yellow', '7f'.repeat(16) + '8'],
    ['letter advice cage absurd amount doctor acoustic avoid letter advice cage above', '80'.repeat(16) + '4'],
    ['zoo '.repeat(11) + 'wrong', 'ff'.repeat(16) + '5']
  ]) assert.equal(await evaluate(`encodePhrase(${JSON.stringify(phrase)})`), expected);
  assert.equal(await evaluate(`encodePhrase(${JSON.stringify('  ' + known.toUpperCase().replaceAll(' ', '\n\t') + '  ')})`), '0'.repeat(32) + '3');
});
test('rejects wrong length, unknown words and incorrect checksum', async () => {
  const { evaluate } = setup();
  for (const [phrase, error] of [['', /exactly 12/], ['abandon '.repeat(11), /exactly 12/], ['abandon '.repeat(13), /exactly 12/], ['abandon '.repeat(11) + 'invalidword', /Word 12/], ['abandon '.repeat(12), /checksum/]]) {
    await assert.rejects(evaluate(`encodePhrase(${JSON.stringify(phrase)})`), error);
  }
});
test('independently generated entropy round trips through word packing and XOR', async () => {
  const { evaluate } = setup();
  const words = evaluate('WORDS');
  assert.equal(words.length, 2048);
  assert.equal(new Set(words).size, 2048);
  for (let i = 0; i < 100; i++) {
    const entropy = randomBytes(16);
    const expected = entropy.toString('hex') + (createHash('sha256').update(entropy).digest()[0] >>> 4).toString(16);
    const bits = BigInt('0x' + expected).toString(2).padStart(132, '0');
    const phrase = bits.match(/.{11}/g).map(b => words[parseInt(b, 2)]).join(' ');
    assert.equal(await evaluate(`encodePhrase(${JSON.stringify(phrase)})`), expected);
    const { pad, ciphertext } = evaluate(`encryptHex('${expected}')`);
    assert.match(pad, /^[0-9a-f]{33}$/);
    assert.match(ciphertext, /^[0-9a-f]{33}$/);
    assert.equal((BigInt('0x' + pad) ^ BigInt('0x' + ciphertext)).toString(16).padStart(33, '0'), expected);
  }
});
test('pad uses 132 random bits including final nibble; no insecure RNG fallback', () => {
  const { evaluate } = setup({ getRandomValues(bytes) { bytes.fill(255); return bytes; } });
  assert.equal(evaluate(`encryptHex('${'0'.repeat(33)}').pad`), 'f'.repeat(33));
  assert.throws(() => setup({}).evaluate(`encryptHex('${'0'.repeat(33)}')`), /Secure randomness/);
});
test('submission displays outputs; edits and reset invalidate pending validation', async () => {
  const { node } = setup();
  const field = node('#plaintext'), form = node('#encryption-form');
  field.value = known;
  await form.events.submit({ preventDefault() {} });
  assert.equal(node('#results').hidden, false);
  assert.equal(node('#pad').textContent.length, 33);
  field.events.input();
  assert.equal(node('#results').hidden, true);
  for (const event of [() => field.events.input(), () => form.events.reset()]) {
    const pending = form.events.submit({ preventDefault() {} });
    event();
    await pending;
    assert.equal(node('#results').hidden, true);
    assert.equal(node('#pad').textContent, '');
  }
  field.value = 'abandon '.repeat(12);
  await form.events.submit({ preventDefault() {} });
  assert.match(node('#form-message').textContent, /checksum/);
  assert.equal(node('#results').hidden, true);
});
test('embedded QR encoder accepts the full HEX payload with error correction', () => {
  const { evaluate } = setup();
  assert.equal(evaluate(`(() => { const qr = qrcode(0, 'L'); qr.addData('0123456789ABCDEF0123456789ABCDEF0', 'Alphanumeric'); qr.make(); return qr.getModuleCount(); })()`), 25);
  assert.doesNotMatch(html, /<script[^>]+src=|<link[^>]+href=|\bfetch\(/i);
});
test('checksum repair preserves entropy across all 128 possible final entropy groups', async () => {
  const { evaluate, node } = setup();
  const words = evaluate('WORDS');
  for (let group = 0; group < 128; group++) {
    const entropy = Buffer.alloc(16); entropy[15] = group;
    const checksum = createHash('sha256').update(entropy).digest()[0] >>> 4;
    const wrong = words[(group << 4) | (checksum ^ 1)];
    node('#plaintext').value = 'abandon '.repeat(11) + wrong;
    await node('#plaintext').events.input();
    assert.equal(node('#repair-checksum').disabled, false);
    await node('#repair-checksum').events.click();
    assert.equal(node('#plaintext').value, 'abandon '.repeat(11) + words[(group << 4) | checksum]);
    assert.equal(await evaluate(`encodePhrase(${JSON.stringify(node('#plaintext').value)})`), entropy.toString('hex') + checksum.toString(16));
    assert.equal(node('#repair-checksum').disabled, true);
    assert.equal(node('#results').hidden, true);
  }
});
test('repair disabled for valid, unknown, incomplete phrases and stale asynchronous checks', async () => {
  const { node } = setup();
  for (const phrase of [known, 'abandon '.repeat(11) + 'unknownword', 'abandon '.repeat(11), 'invalid ' + 'abandon '.repeat(11)]) {
    node('#plaintext').value = phrase;
    await node('#plaintext').events.input();
    assert.equal(node('#repair-checksum').disabled, true);
  }
  node('#plaintext').value = 'abandon '.repeat(12);
  await node('#encryption-form').events.submit({ preventDefault() {} });
  assert.equal(node('#repair-checksum').disabled, false);
  const pending = node('#repair-checksum').events.click();
  node('#plaintext').value = known;
  await node('#plaintext').events.input();
  await pending;
  assert.equal(node('#plaintext').value, known);
  assert.equal(node('#repair-checksum').disabled, true);
});
test('HEX spacing preserves the trailing nibble and exports remain compact', () => {
  const { evaluate, node } = setup();
  const hex = '0123456789abcdef0123456789abcdef0';
  const spaced = evaluate(`spacedHex('${hex}')`);
  assert.equal(spaced, '01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef 0');
  node('#ciphertext').textContent = spaced;
  node('#pad').textContent = spaced;
  assert.equal(evaluate("qrValue('ciphertext')"), hex);
  assert.equal(evaluate("qrValue('pad')"), hex);
  assert.equal(evaluate("spacedHex('')"), '');
});
test('decryption restores words, accepts spaced uppercase shares and rejects invalid shares', async () => {
  const { evaluate } = setup();
  const encoded = await evaluate(`encodePhrase('${known}')`);
  const shares = evaluate(`encryptHex('${encoded}')`);
  assert.equal(await evaluate(`decryptShares('${shares.ciphertext.toUpperCase().match(/.{1,2}/g).join(' ')}', '${shares.pad}')`), known);
  for (const bad of ['', '0'.repeat(32), '0'.repeat(34), 'g'.repeat(33)]) {
    await assert.rejects(evaluate(`decryptShares('${bad}', '${shares.pad}')`), /33 HEX/);
    await assert.rejects(evaluate(`decryptShares('${shares.ciphertext}', '${bad}')`), /33 HEX/);
  }
  await assert.rejects(evaluate(`decryptShares('${'0'.repeat(33)}', '${'0'.repeat(33)}')`), /checksum/);
});
test('decryption UI clears stale results on edits, mode switch and pending reset', async () => {
  const { node, evaluate } = setup();
  evaluate('setMode(true)');
  assert.equal(node('#encryption-form').hidden, true);
  assert.equal(node('#decryption-form').hidden, false);
  node('#encrypted-hex').value = '0'.repeat(32) + '3';
  node('#pad-hex').value = '0'.repeat(33);
  await node('#decryption-form').events.submit({ preventDefault() {} });
  assert.equal(node('#restored-phrase').textContent, known.split(' ').map((word, i) => `${String(i + 1).padStart(2, " ")}. ${word}`).join('\n'));
  assert.equal(node('#decrypted-results').hidden, false);
  node('#encrypted-hex').events.input();
  assert.equal(node('#restored-phrase').textContent, '');
  const pending = node('#decryption-form').events.submit({ preventDefault() {} });
  node('#decryption-form').events.reset();
  await pending;
  assert.equal(node('#decrypted-results').hidden, true);
  evaluate('setMode(false)');
  assert.equal(node('#encryption-form').hidden, false);
  assert.equal(node('#decryption-form').hidden, true);
  assert.equal(node('#encrypted-hex').value, '');
  assert.equal(node('#pad-hex').value, '');
});
test('decryption mask toggles independently, formats edits and preserves HEX for recovery', async () => {
  const { node, evaluate } = setup();
  const hex = '0'.repeat(32) + '3';
  node('#encrypted-hex').value = hex;
  node('#pad-hex').value = '0'.repeat(33);
  node('#space-encrypted-hex').events.click();
  assert.equal(node('#encrypted-hex').value, hex.match(/.{1,2}/g).join(' '));
  assert.equal(node('#pad-hex').value, '0'.repeat(33));
  node('#space-pad-hex').events.click();
  await node('#decryption-form').events.submit({ preventDefault() {} });
  assert.equal(node('#restored-phrase').textContent, known.split(' ').map((word, i) => `${String(i + 1).padStart(2, " ")}. ${word}`).join('\n'));
  node('#space-encrypted-hex').events.click();
  assert.equal(node('#encrypted-hex').value, hex);
  node('#pad-hex').value = 'ABCDef0123';
  node('#pad-hex').events.input();
  assert.equal(node('#pad-hex').value, 'AB CD ef 01 23');
  node('#space-pad-hex').events.click();
  assert.equal(node('#pad-hex').value, 'ABCDef0123');
  node('#space-pad-hex').events.click();
  node('#pad-hex').value = '12!xyz';
  node('#pad-hex').events.input();
  assert.equal(node('#pad-hex').value, '12 !x yz');
  assert.throws(() => evaluate("parseShare(decryptPadField.value, 'Pad')"), /33 HEX/);
});
test('provided pad preserves every nibble, normalizes whitespace and bypasses randomness', async () => {
  const { evaluate } = setup({ subtle: webcrypto.subtle, getRandomValues() { throw new Error('Must not generate a pad'); } });
  const pad = '00' + '123456789abcdef'.repeat(2) + '0';
  const shares = evaluate(`encryptHex('${'0'.repeat(32)}3', '${pad.toUpperCase().match(/.{1,2}/g).join(' ')}')`);
  assert.equal(shares.pad, pad);
  assert.equal(shares.ciphertext, pad.slice(0, -1) + '3');
  assert.equal(await evaluate(`decryptShares('${shares.ciphertext}', '${pad}')`), known);
  for (const bad of ['', '0'.repeat(32), '0'.repeat(34), 'g'.repeat(33)]) {
    assert.throws(() => evaluate(`encryptHex('${'0'.repeat(32)}3', '${bad}')`), /33 HEX/);
  }
});
test('provided pad UI validates, invalidates pending work and resets to automatic generation', async () => {
  const { node, evaluate } = setup();
  const checkbox = node('#use-provided-pad');
  const pad = node('#provided-pad');
  const form = node('#encryption-form');
  assert.equal(pad.disabled, true);
  checkbox.checked = true;
  checkbox.events.change();
  assert.equal(pad.disabled, false);
  assert.equal(node('#provided-pad-fields').hidden, false);
  node('#plaintext').value = known;
  pad.value = 'invalid';
  await form.events.submit({ preventDefault() {} });
  assert.match(node('#form-message').textContent, /33 HEX/);
  assert.equal(pad['aria-invalid'], 'true');
  assert.equal(node('#plaintext')['aria-invalid'], undefined);
  pad.value = '0'.repeat(32) + 'A';
  pad.events.input();
  await form.events.submit({ preventDefault() {} });
  assert.equal(node('#pad').textContent, '0'.repeat(32) + 'a');
  assert.equal(node('#ciphertext').textContent, '0'.repeat(32) + '9');
  for (const invalidate of [() => pad.events.input(), () => checkbox.events.change(), () => form.events.reset()]) {
    const pending = form.events.submit({ preventDefault() {} });
    invalidate();
    await pending;
    assert.equal(node('#results').hidden, true);
    assert.equal(node('#pad').textContent, '');
  }
  assert.equal(checkbox.checked, false);
  assert.equal(pad.value, '');
  assert.equal(pad.disabled, true);
  pad.value = 'invalid hidden pad';
  await form.events.submit({ preventDefault() {} });
  assert.equal(node('#results').hidden, false);
  evaluate('setMode(true)');
  assert.equal(pad.value, '');
  assert.equal(checkbox.checked, false);
});
test('all final pad digits round trip as 33-digit shares without byte padding', async () => {
  const { evaluate, node } = setup();
  node('#plaintext').value = known;
  node('#use-provided-pad').checked = true;
  node('#use-provided-pad').events.change();
  for (let last = 0; last < 16; last++) {
    const pad = '0'.repeat(32) + last.toString(16);
    // Sixteen full bytes followed by one standalone HEX digit.
    node('#provided-pad').value = pad.match(/.{1,2}/g).join(' ');
    await node('#encryption-form').events.submit({ preventDefault() {} });
    const ciphertext = node('#ciphertext').textContent;
    assert.equal(node('#results').hidden, false);
    assert.equal(node('#pad').textContent, pad);
    assert.equal(ciphertext, '0'.repeat(32) + (3 ^ last).toString(16));
    assert.equal(ciphertext.length, 33);
    assert.equal(await evaluate(`decryptShares('${ciphertext}', '${pad}')`), known);
    assert.equal(evaluate("qrValue('pad')"), pad);
  }
});
test('SeedQR is offered only for verified decryption and clears with shares', async () => {
  const { node, evaluate } = setup();
  const button = node('#show-seedqr');
  const panel = node('#seedqr-panel');
  const image = node('#seedqr-image');
  const form = node('#decryption-form');
  button.events.click();
  assert.equal(evaluate('verifiedSeedQrPayload'), '');
  node('#encrypted-hex').value = '0'.repeat(32) + '3';
  node('#pad-hex').value = '0'.repeat(33);
  await form.events.submit({ preventDefault() {} });
  assert.equal(button.disabled, false);
  assert.equal(panel.hidden, true);
  assert.equal(evaluate('verifiedSeedQrPayload'), '0000'.repeat(11) + '0003');
  button.events.click();
  assert.equal(panel.hidden, false);
  assert.match(image.innerHTML, /^<svg/);
  assert.equal(button['aria-expanded'], 'true');
  button.events.click();
  assert.equal(panel.hidden, true);
  assert.equal(image.innerHTML, '');
  button.events.click();
  node('#encrypted-hex').events.input();
  assert.equal(image.innerHTML, '');
  assert.equal(panel.hidden, true);
  assert.equal(button.disabled, true);
  assert.equal(evaluate('verifiedSeedQrPayload'), '');
  node('#encrypted-hex').value = '0'.repeat(33);
  await form.events.submit({ preventDefault() {} });
  assert.equal(button.disabled, true);
  button.events.click();
  assert.equal(image.innerHTML, '');
  node('#encrypted-hex').value = '0'.repeat(32) + '3';
  const pending = form.events.submit({ preventDefault() {} });
  form.events.reset();
  await pending;
  assert.equal(button.disabled, true);
  assert.equal(evaluate('verifiedSeedQrPayload'), '');
});
