const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const html = readFileSync(require('node:path').join(__dirname, '../yeti-encoder-decoder.html'), 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1].split('const input = document')[0];
const context = vm.createContext({ crypto: webcrypto, TextEncoder, setTimeout });
vm.runInContext(script, context);
const encode = text => context.encodeYeti(text);
const python = `
import sys, hashlib
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
nato = 'alfa bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa quebec romeo sierra tango uniform victor whiskey x-ray yankee zulu'.split()
digits = 'ZERO ONE TWO THREE FOUR FIVE SIX SEVEN EIGHT NINE'.split()
words = {chr(97+i): w for i,w in enumerate(nato)}
words.update({chr(65+i): w.upper() for i,w in enumerate(nato)})
words.update(zip('123456789', digits[1:]))
data = bytes.fromhex(sys.argv[1])
n = int.from_bytes(data, 'big')
b58 = ''
while n:
    n,r = divmod(n,58)
    b58 = alphabet[r] + b58
b58 = '1' * (len(data)-len(data.lstrip(b'\\x00'))) + b58
rows = []
for offset in range(0,len(b58),4):
    group = b58[offset:offset+4]
    check = alphabet[sum(alphabet.index(c) for c in group)%58]
    rows.append(' '.join(words[c] for c in group+check))
body = '\\n'.join(rows)
final = int.from_bytes(hashlib.sha256(body.encode()).digest()[-2:], 'big')
print(body)
print(' '.join(digits[int(d)] for d in f'{final:05d}'))
`;
test('matches Python including leading zeros, case, row checksums and final hash', async () => {
  const cases = ['', '00', 'ff', '000001', 'ab'.repeat(33), 'ab'.repeat(257), '00'.repeat(32), '00'.repeat(31)+'01', 'ff'.repeat(32), '00'.repeat(5)+'ab'.repeat(27), Array.from({length:32}, (_,i)=>i.toString(16).padStart(2,'0')).join('')];
  for (const hex of cases) {
    const expected = execFileSync('python3', ['-c', python, hex], {encoding:'utf8'}).trim();
    assert.equal(await encode(Buffer.from(hex, 'hex')), expected);
  }
});
test('UTF-8 preserves Unicode, whitespace and hex-looking text as literal bytes', async () => {
  for (const text of [' Hello \n世界 👋 ', 'ABCDEF12=abcd', '00ff', ' '.repeat(16385)]) {
    const bytes = new TextEncoder().encode(text);
    const expected = execFileSync('python3', ['-c', python, Buffer.from(bytes).toString('hex')], {encoding:'utf8'}).trim();
    assert.equal(await encode(bytes), expected);
  }
});
test('reports unavailable SHA-256 and supports cancellation', async () => {
  const unavailable = vm.createContext({TextEncoder, setTimeout});
  vm.runInContext(script, unavailable);
  await assert.rejects(unavailable.encodeYeti(new Uint8Array([1])), /SHA-256 is unavailable/);
  await assert.rejects(context.encodeYeti(new Uint8Array([1]), () => false), /cancelled/);
});
test('file submission preserves binary bytes and clear cancels pending file reads', async () => {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'', checked:false, files:[], disabled:false, className:'', textContent:'', handlers:{}, addEventListener(event, handler) { this.handlers[event] = handler; }, focus() {}});
    return elements.get(id);
  };
  const ui = vm.createContext({crypto:webcrypto, TextEncoder, setTimeout, window:{addEventListener(){}}, document:{getElementById:element}});
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], ui);
  element('mode-file').checked = true;
  element('mode-file').handlers.change();
  assert.equal(element('file-panel').hidden, false);
  assert.equal(element('text-panel').hidden, true);
  const bytes = new Uint8Array([0, 255, 128, 13, 10, 0]);
  element('file').files = [{arrayBuffer:async () => bytes.buffer}];
  await element('converter').handlers.submit({preventDefault(){}});
  assert.equal(element('output').value, await encode(bytes));
  assert.equal(element('download').disabled, false);
  assert.equal(element('output-gutter').hidden, false);
  assert.equal(element('output-line-numbers').textContent, element('output').value.split('\n').map((_, i) => i + 1).join('\n'));
  assert.equal(element('output').wrap, 'off');
  element('output').scrollTop = 80;
  element('output').handlers.scroll();
  assert.equal(element('output-line-numbers').scrollTop, 80);
  element('mode-file').checked = false;
  element('mode-text').handlers.change();
  assert.equal(element('file-panel').hidden, true);
  assert.equal(element('text-panel').hidden, false);
  assert.equal(element('output').value, '');
  element('input').value = 'Hello';
  await element('converter').handlers.submit({preventDefault(){}});
  assert.equal(element('output').value, await encode(new TextEncoder().encode('Hello')));
  element('mode-file').checked = true;
  element('mode-file').handlers.change();
  let finish;
  element('file').files = [{arrayBuffer:() => new Promise(resolve => {finish = resolve;})}];
  const pending = element('converter').handlers.submit({preventDefault(){}});
  element('clear').handlers.click();
  finish(bytes.buffer);
  await pending;
  assert.equal(element('output').value, '');
  assert.equal(element('download').disabled, true);
});
test('print numbers vertically through both columns and includes checksum as the last row', () => {
  function node(tag) {
    return {tag, children:[], textContent:'', addEventListener(){}, append(...items){this.children.push(...items);}, appendChild(item){this.children.push(item);}};
  }
  const elements = new Map();
  const document = {createElement:node, getElementById(id) {
    if (!elements.has(id)) elements.set(id, node(id));
    return elements.get(id);
  }};
  const ui = vm.createContext({document, window:{addEventListener(){}}, TextEncoder, setTimeout});
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], ui);
  document.getElementById('output').value = 'alfa bravo\nCHARLIE delta\necho foxtrot\nONE TWO THREE FOUR FIVE';
  ui.preparePrint();
  const pairs = document.getElementById('print-rows').children;
  assert.equal(pairs.length, 2);
  assert.deepEqual(pairs.map(row => row.children.length), [2, 2]);
  assert.equal(pairs[0].children[0].children[0].children[0].textContent, '1.');
  assert.equal(pairs[0].children[1].children[0].children[0].textContent, '3.');
  assert.equal(pairs[1].children[0].children[0].children[1].textContent, 'CHARLIE delta');
  assert.equal(pairs[1].children[1].children[0].children[0].textContent, '4.');
  assert.equal(pairs[1].children[1].children[0].children[1].textContent, 'ONE TWO THREE FOUR FIVE');
  assert.doesNotMatch(html, /<h1>Yeti record<|id="print-checksum"/);
});
test('decoder round trips arbitrary bytes, zero bytes, empty data and UTF-8', async () => {
  for (const bytes of [Buffer.alloc(0), Buffer.alloc(32), Buffer.from([0,0,255,128,10]), Buffer.from('Hello 世界 👋\n'), Buffer.from(Array.from({length:256}, (_,i)=>i))]) {
    const words = await encode(bytes);
    assert.deepEqual(Buffer.from(await context.decodeYeti(words.split('\n'))), bytes);
  }
});
test('decoder rejects mixed case, excluded Base58 letters, bad row and final checksums', async () => {
  const lines = (await encode(Buffer.from('test data'))).split('\n');
  const changed = [...lines]; changed[0] = 'Alfa ' + changed[0].split(' ').slice(1).join(' ');
  await assert.rejects(context.decodeYeti(changed), /case-sensitive/);
  assert.match(context.inspectYetiRow('INDIA alfa alfa alfa alfa',0,3).error, /case-sensitive/);
  const badRow = [...lines]; const words = badRow[0].split(' '); words[4] = words[4] === 'ONE' ? 'TWO' : 'ONE'; badRow[0] = words.join(' ');
  await assert.rejects(context.decodeYeti(badRow), /Row checksum mismatch/);
  const final = [...lines]; final[final.length-1] = 'ZERO ZERO ZERO ZERO ZERO';
  await assert.rejects(context.decodeYeti(final), /final SHA-256 checksum mismatch/);
  assert.match(context.inspectYetiRow('ONE TWO THREE FOUR',0,1).error, /five/);
});
test('autocomplete matches complete prefixes case-insensitively including digit words', () => {
  assert.deepEqual(Array.from(context.suggestWords('',false)), []);
  assert.deepEqual(Array.from(context.suggestWords('a',false)), ['alfa','ALFA']);
  assert.deepEqual(Array.from(context.suggestWords('AL',false)), ['ALFA','alfa']);
  assert.deepEqual(Array.from(context.suggestWords('ON',false)), ['ONE']);
  assert.deepEqual(Array.from(context.suggestWords('z',true)), ['ZERO']);
  assert.deepEqual(Array.from(context.suggestWords('o',false)), ['oscar', 'OSCAR', 'ONE']);
  assert.deepEqual(Array.from(context.suggestWords('OS',false)), ['OSCAR', 'oscar']);
  assert.deepEqual(Array.from(context.suggestWords('O',false)), ['OSCAR', 'ONE', 'oscar']);
  assert.deepEqual(Array.from(context.suggestWords('os',false)), ['oscar', 'OSCAR']);
  assert.deepEqual(Array.from(context.suggestWords('on',false)), ['ONE']);
  assert.deepEqual(Array.from(context.suggestWords('ox',false)), []);
});

test('encrypted Yeti records interoperate with standalone encryption in both directions', async () => {
  const standaloneHTML = readFileSync(require('node:path').join(__dirname, '../secure-file-encryption.html'), 'utf8');
  const standaloneScript = standaloneHTML.match(/<script>([\s\S]*?)<\/script>/)[1];
  const globals = {crypto:webcrypto, TextEncoder, TextDecoder, Uint8Array, DataView, setTimeout};
  const standalone = vm.createContext({...globals});
  const yeti = vm.createContext({...globals});
  vm.runInContext(standaloneScript, standalone);
  vm.runInContext(script, yeti);
  // Keep the embedded cryptographic implementation identical across offline pages.
  assert.ok(script.includes(standaloneScript));
  for (const bytes of [new Uint8Array(), new TextEncoder().encode('  秘密 👋\n'), new Uint8Array([0,255,128,0])]) {
    for (const [encryptor, decryptor] of [[yeti,standalone], [standalone,yeti]]) {
      const encrypted = await encryptor.encryptBytes('passphrase', bytes, '秘密.bin');
      const words = await yeti.encodeYeti(encrypted);
      const decoded = await yeti.decodeYeti(words.split('\n'));
      const result = await decryptor.decryptBytes('passphrase', decoded);
      assert.equal(result.filename, '秘密.bin');
      assert.deepEqual(Buffer.from(result.bytes), Buffer.from(bytes));
      await assert.rejects(decryptor.decryptBytes('wrong', decoded), /Incorrect password/);
    }
  }
});

test('encryption option validates passwords, encrypts UI input, and invalidates pending output', async () => {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'', checked:false, files:[], handlers:{}, addEventListener(event,handler){this.handlers[event]=handler;}, focus(){}});
    return elements.get(id);
  };
  const ui = vm.createContext({crypto:webcrypto, TextEncoder, TextDecoder, Uint8Array, DataView, setTimeout, window:{addEventListener(){}}, document:{getElementById:element}});
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], ui);
  const submit = () => element('converter').handlers.submit({preventDefault(){}});
  element('encrypt-enabled').checked = true;
  element('encrypt-enabled').handlers.change();
  assert.equal(element('encrypt-options').hidden, false);
  element('input').value = ' secret text\n';
  await submit(); assert.match(element('status').textContent, /Enter a password/);
  element('encrypt-password').value = 'secret';
  await submit(); assert.match(element('status').textContent, /Passwords do not match/);
  element('encrypt-confirm').value = 'secret';
  await submit();
  const bytes = await ui.decodeYeti(element('output').value.split('\n'));
  const result = await ui.decryptBytes('secret', bytes);
  assert.equal(result.filename, 'text.txt');
  assert.equal(new TextDecoder().decode(result.bytes), ' secret text\n');
  const pending = submit();
  element('encrypt-password').handlers.input();
  await pending;
  assert.equal(element('output').value, '');
  assert.equal(element('download').disabled, true);
});

test('hex input converts digits to binary bytes, preserving zeros and padding odd lengths with a trailing zero', async () => {
  for (const [hex, expected] of [['00 fF\n80', '00ff80'], ['abc', 'abc0'], ['f', 'f0'], ['0'.repeat(32)+'3', '0'.repeat(32)+'30'], ['0001', '0001']]) {
    const bytes = context.hexToBytes(hex);
    assert.equal(Buffer.from(bytes).toString('hex'), expected);
    assert.deepEqual(Buffer.from(await context.decodeYeti((await encode(bytes)).split('\n'))), Buffer.from(expected, 'hex'));
  }
  for (const invalid of ['', ' \n', '0x12', '12gg', '-1']) assert.throws(() => context.hexToBytes(invalid), /hex/i);
});

test('hex encoding UI uses binary input and clears stale output on edits and mode changes', async () => {
  const elements = new Map();
  const element = id => {
    if (!elements.has(id)) elements.set(id, {value:'', checked:false, files:[], handlers:{}, addEventListener(event,handler){this.handlers[event]=handler;}, focus(){}});
    return elements.get(id);
  };
  const ui = vm.createContext({crypto:webcrypto, TextEncoder, setTimeout, window:{addEventListener(){}}, document:{getElementById:element}});
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], ui);
  element('mode-hex').checked = true;
  element('mode-hex').handlers.change();
  assert.equal(element('hex-panel').hidden, false);
  assert.equal(element('text-panel').hidden, true);
  assert.equal(element('hex-input').disabled, false);
  element('hex-input').value = '00ff';
  const submit = () => element('converter').handlers.submit({preventDefault(){}});
  await submit();
  assert.equal(element('output').value, await encode(Buffer.from('00ff', 'hex')));
  const pending = submit();
  element('hex-input').value = 'xyz';element('hex-input').handlers.input();
  await pending;
  assert.equal(element('output').value, '');
  await submit();assert.match(element('status').textContent, /hex digits/);
  element('clear').handlers.click();assert.equal(element('hex-input').value, '');
  element('mode-hex').checked = false;element('mode-text').handlers.change();
  assert.equal(element('hex-panel').hidden, true);assert.equal(element('hex-input').disabled, true);
  assert.equal(element('text-panel').hidden, false);
});

test('decoded display defaults by UTF-8 validity and toggles without changing bytes', async () => {
  const elements = new Map(), events = {};
  const node = () => ({value:'', checked:false, children:[], handlers:{}, attributes:{},
    addEventListener(name,fn){this.handlers[name]=fn;}, setAttribute(name,value){this.attributes[name]=value;},
    append(...items){this.children.push(...items);}, insertBefore(item){this.children.push(item);},
    replaceChildren(...items){this.children=items;}, focus(){}});
  const element = id => {if(!elements.has(id))elements.set(id,node());return elements.get(id);};
  const ui = vm.createContext({crypto:webcrypto, TextEncoder, TextDecoder, setTimeout, URL,
    window:{addEventListener(name,fn){events[name]=fn;}}, document:{getElementById:element,createElement:node}});
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], ui);
  events.DOMContentLoaded();
  for (const bytes of [Buffer.from('Hi'), Buffer.from([0,255,128]), Buffer.from([0xef,0xbb,0xbf,65])]) {
    const lines = (await encode(bytes)).split('\n');
    while(element('decode-rows').children.length < lines.length)element('add-row').handlers.click();
    element('decode-rows').children.forEach((row,i)=>{row.children[0].children[1].value=lines[i];});
    await element('decode-button').handlers.click();
    const valid = bytes[1] !== 255;
    assert.equal(element('decoded-format').value, valid ? 'utf8' : 'hex');
    assert.equal(element('decoded-format').disabled, false);
    assert.match(element('decoded-text').value, /^\*+$/);
    element('reveal-decoded').handlers.click();
    const text = new TextDecoder('utf-8',{ignoreBOM:true}).decode(bytes);
    assert.equal(element('decoded-text').value, valid ? text : bytes.toString('hex'));
    element('decoded-format').value='hex';element('decoded-format').handlers.change();
    assert.equal(element('decoded-text').value,bytes.toString('hex'));
    element('decoded-format').value='utf8';element('decoded-format').handlers.change();
    assert.equal(element('decoded-text').value,text);
    assert.equal(Boolean(element('decoded-format-note').textContent),!valid);
    element('clear-decode').handlers.click();
    assert.equal(element('decoded-text').value,'');assert.equal(element('decoded-format').disabled,true);
  }
});
