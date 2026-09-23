// Run with: node --test tests/bip39-seed-generator.test.cjs
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {resolve}=require('node:path');
const {createContext,runInContext}=require('node:vm');
const {webcrypto,createHash,randomBytes}=require('node:crypto');
const html=readFileSync(resolve(__dirname,'../bip39-seed-generator.html'),'utf8');
function setup(crypto=webcrypto){
  const nodes=new Map();
  const make=()=>({value:'',textContent:'',hidden:true,disabled:false,dataset:{},events:{},children:[],attributes:{},append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;this.textContent='';},setAttribute(k,v){this.attributes[k]=v;},addEventListener(k,f){this.events[k]=f;},focus(){},select(){}});
  const node=id=>{if(!nodes.has(id))nodes.set(id,make());return nodes.get(id);};
  const modes=['auto','dice','coin','lottery','hex'].map(value=>Object.assign(make(),{value}));
  const document={getElementById:node,createElement:make,querySelectorAll(selector){return selector==='input[name="mode"]'?modes:[...node('dice-buttons').children,...['heads','tails','add-roll','roll-input'].map(node)];}};
  const context=createContext({crypto,document,Uint8Array,Uint16Array,navigator:{},console});
  for(const s of html.matchAll(/<script(?: id="[^"]+")?>([\s\S]*?)<\/script>/g))runInContext(s[1],context);
  return {node,run:s=>runInContext(s,context),mode:async value=>modes.find(m=>m.value===value).events.change()};
}
test('official BIP39 entropy vectors and Standard SeedQR payload',async()=>{
 const {run}=setup();
 for(const [hex,phrase] of [
 ['00'.repeat(16),'abandon '.repeat(11)+'about'],
 ['7f'.repeat(16),'legal winner thank year wave sausage worth useful legal winner thank yellow'],
 ['80'.repeat(16),'letter advice cage absurd amount doctor acoustic avoid letter advice cage above'],
 ['ff'.repeat(16),'zoo '.repeat(11)+'wrong']]){
 const bits=Array.from(Buffer.from(hex,'hex'),b=>b.toString(2).padStart(8,'0')).join('');
 const result=await run(`makeMnemonic('${bits}')`);
 assert.equal(result.words.join(' '),phrase);assert.equal(result.bits.length,132);assert.match(result.payload,/^\d{48}$/);
 assert.equal(result.payload.match(/.{4}/g).map(i=>run(`WORDS[${Number(i)}]`)).join(' '),phrase);
 }
 assert.equal((await run(`makeMnemonic('${'0'.repeat(128)}')`)).payload,'0000'.repeat(11)+'0003');
});
test('random entropy agrees with independent SHA256 and preserves last seven bits',async()=>{
 const {run}=setup();assert.equal(run('new Set(WORDS).size'),2048);
 for(let i=0;i<100;i++){
 const entropy=randomBytes(16),bits=Array.from(entropy,b=>b.toString(2).padStart(8,'0')).join('');
 const result=await run(`makeMnemonic('${bits}')`);
 assert.equal(result.checksum,(createHash('sha256').update(entropy).digest()[0]>>>4).toString(2).padStart(4,'0'));
 assert.equal(result.indices[11]>>>4,parseInt(bits.slice(121),2));
 }
 for(let suffix=0;suffix<16;suffix++)assert.equal(run(`entropyFromIndices([...Array(11).fill(0),${(73<<4)|suffix}])`),'0'.repeat(121)+(73).toString(2).padStart(7,'0'));
});
test('auto requests twelve secure words and fails closed without crypto',async()=>{
 let calls=0;const {run,node}=setup({subtle:webcrypto.subtle,getRandomValues(values){calls++;assert.equal(values.length,12);values.fill(65535);return values;}});
 await node('generate').events.click();assert.equal(calls,1);assert.equal(node('phrase').value,'zoo '.repeat(11)+'wrong');
 assert.equal(run('result.entropy'),'1'.repeat(128));
 assert.throws(()=>setup({}).run('randomIndices()'),/Secure randomness/);
 await assert.rejects(setup({}).run(`makeMnemonic('${'0'.repeat(128)}')`),/SHA-256/);
});
test('dice mapping is balanced within each output length, truncates final extra bit and supports undo',async()=>{
 const {run,node,mode}=setup();await mode('dice');
 assert.equal(run('[1,2,3,4,5,6].map(diceBits).join(",")'),'00,01,10,11,0,1');
 for(const bad of [0,7,1.5,NaN])assert.throws(()=>run(`diceBits(${bad})`),/one roll/);
 for(let i=0;i<127;i++)await run('addEntry(5)');await run('addEntry(2)');
 assert.equal(run('result.entropy'),'0'.repeat(128));assert.equal(run('records.length'),128);
 assert.equal(node('sequence').children[0].children[1].children.at(-1).children[4].textContent,'1');
 await run('addEntry(6)');assert.equal(run('records.length'),128);
 node('undo').events.click();assert.equal(node('results').hidden,true);assert.equal(node('progress').value,127);
 await run('addEntry(6)');assert.equal(run('result.entropy'),'0'.repeat(127)+'1');
});
test('coin labels preserve bits and exactly 128 flips finish generation',async()=>{
 const {run,node,mode}=setup();await mode('coin');node('heads-label').value='<img src=x>';node('heads-label').events.input();
 assert.equal(node('heads').textContent,'<img src=x> → 0');
 for(let i=0;i<128;i++)await node('heads').events.click();
 assert.equal(node('phrase').value,'abandon '.repeat(11)+'about');
 node('heads-label').value='Eagle';node('heads-label').events.input();assert.equal(run('result.entropy'),'0'.repeat(128));
});
test('lottery validates entries, autocompletes all words and corrects checksum',async()=>{
 const {run,node,mode}=setup();await mode('lottery');assert.equal(node('suggestions').children.length,2048);
 run('fields.forEach(f=>f.value=" ABANDON ");validateWords()');assert.equal(node('calculate').disabled,false);
 await node('calculate').events.click();assert.equal(node('phrase').value,'abandon '.repeat(11)+'about');
 run('fields[11].value="invalid";validateWords()');assert.equal(node('results').hidden,true);assert.equal(node('calculate').disabled,true);
 assert.throws(()=>run('lotteryIndices(fields.map(f=>f.value))'),/Word 12/);
});
test('SeedQR uses 25x25 numeric QR, hides and clears with source changes',async()=>{
 const {run,node,mode}=setup();await run(`calculate('${'0'.repeat(128)}')`);node('show-qr').events.click();
 assert.equal(node('qr-panel').hidden,false);assert.equal(node('qr-payload').textContent,'0000'.repeat(11)+'0003');assert.match(node('qr-image').innerHTML,/<svg/);
 assert.equal(run('(()=>{const q=qrcode(2,"L");q.addData(result.payload,"Numeric");q.make();return q.getModuleCount();})()'),25);
 node('show-qr').events.click();assert.equal(node('qr-panel').hidden,true);
 await mode('dice');assert.equal(node('phrase').value,'');assert.equal(run('result'),null);
});
test('pending SHA256 cannot resurrect results after reset or mode changes',async()=>{
 for(const action of ['reset','mode']){
 let release;const {run,node,mode}=setup({getRandomValues:webcrypto.getRandomValues.bind(webcrypto),subtle:{digest:()=>new Promise(resolve=>{release=resolve;})}});
 const pending=run(`calculate('${'0'.repeat(128)}')`);
 if(action==='reset')node('reset').events.click();else await mode('coin');
 release(new Uint8Array(32).buffer);await pending;assert.equal(node('results').hidden,true);assert.equal(run('result'),null);
 }
});
test('invalid entropy is rejected and page has no network or persistence dependencies',async()=>{
 const {run}=setup();for(const bits of ['','0'.repeat(127),'0'.repeat(129),'x'.repeat(128)])await assert.rejects(run(`makeMnemonic('${bits}')`),/128 binary/);
 assert.doesNotMatch(html,/<script[^>]+src=|<link[^>]+href=|\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b/);
});

test('hex source validates input, preserves entropy and replaces any supplied checksum',async()=>{
 const {run,node,mode}=setup();await mode('hex');
 assert.equal(node('hex-panel').hidden,false);assert.equal(node('auto-panel').hidden,true);
 for(const invalid of ['', '0'.repeat(32), '0'.repeat(34), 'g'.repeat(33), ' '+ '0'.repeat(32)]){
  node('hex-input').value=invalid;node('hex-input').events.input();
  assert.equal(node('calculate-hex').disabled,true);
  assert.throws(()=>run(`entropyFromHex(${JSON.stringify(invalid)})`),/33 hex characters/);
 }
 for(const [entropy,phrase] of [['0'.repeat(32),'abandon '.repeat(11)+'about'],['F'.repeat(32),'zoo '.repeat(11)+'wrong']]){
  for(const suffix of '0123456789ABCDEF'){
   node('hex-input').value=entropy+suffix;node('hex-input').events.input();
   assert.equal(node('calculate-hex').disabled,false);
   await node('calculate-hex').events.click();
   assert.equal(node('phrase').value,phrase);
   const expected=entropy.toLowerCase()+createHash('sha256').update(Buffer.from(entropy,'hex')).digest('hex')[0];
   assert.equal(node('combined-hex').textContent+node('combined-hex').children[0].textContent,expected);
  }
 }
 node('hex-input').events.input();assert.equal(node('results').hidden,true);assert.equal(node('phrase').value,'');
 node('reset').events.click();assert.equal(node('hex-input').value,'');assert.equal(node('calculate-hex').disabled,true);
});
test('editing hex input invalidates a pending checksum calculation',async()=>{
 let release;const {node,mode,run}=setup({subtle:{digest:()=>new Promise(resolve=>{release=resolve;})}});
 await mode('hex');node('hex-input').value='0'.repeat(33);node('hex-input').events.input();
 const pending=node('calculate-hex').events.click();
 node('hex-input').value='f'.repeat(33);node('hex-input').events.input();
 release(new Uint8Array(32).buffer);await pending;
 assert.equal(node('results').hidden,true);assert.equal(run('result'),null);
});
