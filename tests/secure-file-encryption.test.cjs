const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {webcrypto,pbkdf2Sync,createDecipheriv}=require('node:crypto');
const vm=require('node:vm');
const html=readFileSync(require('node:path').join(__dirname,'../secure-file-encryption.html'),'utf8');
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const globals={crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,DataView,btoa,atob,Blob};
const core=vm.createContext(globals);vm.runInContext(scripts[0],core);
test('raw bytes and UTF-8 round trip with exact overhead and independent crypto verification',async()=>{
 for(const bytes of [Buffer.alloc(0),Buffer.from('  Hello 世界 👋\n'),Buffer.from(Array.from({length:256},(_,i)=>i))]){
  const name='秘密.bin', password=' test 🔑 ';
  const encrypted=await core.encryptBytes(password,bytes,name);
  assert.equal(encrypted.length,bytes.length+62+Buffer.byteLength(name));
  const recovered=await core.decryptBytes(password,encrypted);
  assert.equal(recovered.filename,name);assert.deepEqual(Buffer.from(recovered.bytes),bytes);
  const key=pbkdf2Sync(password,encrypted.subarray(16,32),600000,32,'sha256');
  const decipher=createDecipheriv('aes-256-gcm',key,encrypted.subarray(32,44));
  decipher.setAAD(encrypted.subarray(0,44));decipher.setAuthTag(encrypted.subarray(-16));
  const payload=Buffer.concat([decipher.update(encrypted.subarray(44,-16)),decipher.final()]);
  assert.deepEqual(payload.subarray(2+payload.readUInt16LE(0)),bytes);
  assert.deepEqual(core.fromBase64(core.toBase64(encrypted)),encrypted);
 }
});
test('fresh randomness, wrong passwords, tampering, truncation and legacy rejection',async()=>{
 const bytes=await core.encryptBytes('secret',new Uint8Array([0,255]),'x');
 assert.notDeepEqual(await core.encryptBytes('secret',new Uint8Array([0,255]),'x'),bytes);
 await assert.rejects(core.decryptBytes('wrong',bytes),/Incorrect password/);
 for(const offset of [0,4,5,6,8,10,12,16,32,44,bytes.length-1]){
  const damaged=bytes.slice();damaged[offset]^=1;
  await assert.rejects(core.decryptBytes('secret',damaged));
 }
 for(const length of [0,4,43,61,bytes.length-1]) await assert.rejects(core.decryptBytes('secret',bytes.slice(0,length)));
 const legacy=bytes.slice();legacy[4]=1;assert.throws(()=>core.parseHeader(legacy),/Only binary version 2/);
 const weak=bytes.slice();new DataView(weak.buffer).setUint32(12,100000,true);assert.throws(()=>core.parseHeader(weak),/header/);
 assert.throws(()=>core.parseHeader(new TextEncoder().encode(JSON.stringify({version:1,encrypted:'x'.repeat(100)}))),/Not a WENC/);
 for(const input of ['', 'abcd!', 'abc', 'a===']) assert.throws(()=>core.fromBase64(input),/complete Base64/);
});
test('UI supports both operations with file and text, binary downloads and stale-result cleanup',async()=>{
 const nodes=new Map();
 const get=id=>{if(!nodes.has(id)) nodes.set(id,{value:'',checked:['encrypt','file-mode'].includes(id),files:[],hidden:false,handlers:{},addEventListener(event,fn){this.handlers[event]=fn;},removeAttribute(name){delete this[name];}});return nodes.get(id);};
 const blobs=new Map();let counter=0;
 const ui=vm.createContext({...globals,document:{getElementById:get},window:{addEventListener(){}},URL:{createObjectURL(blob){const url='blob:'+counter++;blobs.set(url,blob);return url;},revokeObjectURL(url){blobs.delete(url);}}});
 scripts.forEach(script=>vm.runInContext(script,ui));
 const submit=()=>get('form').handlers.submit({preventDefault(){}});
 get('password').value=get('confirm').value='secret';
 const original=new Uint8Array([0,255,128,10]);get('file').files=[{name:'raw.bin',arrayBuffer:async()=>original.buffer}];
 await submit();assert.equal(get('download').download,'raw.bin.wec');
 const encrypted=new Uint8Array(await blobs.get(get('download').href).arrayBuffer());
 get('armor').handlers.click();assert.equal(get('output').value,core.toBase64(encrypted));
 get('decrypt').checked=true;get('encrypt').checked=false;get('decrypt').handlers.change();
 assert.equal(get('result').hidden,true);assert.equal(blobs.size,0);
 get('file').files=[{arrayBuffer:async()=>encrypted.buffer}];await submit();
 assert.deepEqual(new Uint8Array(await blobs.get(get('download').href).arrayBuffer()),original);
 get('file-mode').checked=false;get('text-mode').checked=true;get('text-mode').handlers.change();
 assert.equal(get('text-panel').hidden,false);get('input').value=core.toBase64(encrypted);await submit();
 assert.equal(get('download').download,'raw.bin');
 get('decrypt').checked=false;get('encrypt').checked=true;get('encrypt').handlers.change();get('input').value='  café 世界\n';await submit();
 const textEncrypted=new Uint8Array(await blobs.get(get('download').href).arrayBuffer());
 assert.equal(new TextDecoder().decode((await core.decryptBytes('secret',textEncrypted)).bytes),'  café 世界\n');
 get('decrypt').checked=true;get('decrypt').handlers.change();get('input').value=core.toBase64(textEncrypted);await submit();
 assert.equal(get('output').value,'  café 世界\n');assert.equal(get('output-panel').hidden,false);
 get('password').value='wrong';await submit();assert.equal(get('result').hidden,true);assert.match(get('status').textContent,/Incorrect password/);assert.equal(get('controls').disabled,false);
});
