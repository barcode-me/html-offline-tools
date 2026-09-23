const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const path=require('node:path');
const scripts=name=>[...fs.readFileSync(path.join(__dirname,'..',name),'utf8').matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
const globals={crypto:webcrypto,TextEncoder,TextDecoder,Uint8Array,DataView,AbortController};
const code=scripts('nfc-card-reader-writer.html');
const core=vm.createContext({...globals});vm.runInContext(code[0],core);
const existing=vm.createContext({...globals});vm.runInContext(scripts('secure-file-encryption.html')[0],existing);
const record=(bytes,extra={})=>({recordType:'mime',mediaType:'application/octet-stream',data:new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),...extra});
test('hex preserves raw bytes and rejects invalid input; text preserves whitespace',async()=>{
 assert.deepEqual([...core.parseHex('00 ff\n80 41')],[0,255,128,65]);
 for(const bad of ['0','xx','0x00','ff:00'])assert.throws(()=>core.parseHex(bad));
 assert.equal((await core.makeRecord('  café\n','text',null)).data,'  café\n');
 const binary=await core.makeRecord('0041ff','hex',null);
 assert.equal(binary.recordType,'mime');assert.deepEqual([...binary.data],[0,65,255]);
 const sliced=new Uint8Array([99,0,65,255,99]).subarray(1,4);
 assert.equal((await core.readRecord(record(sliced),null)).value,'00 41 ff');
 assert.equal((await core.readRecord(record(new TextEncoder().encode('世界'),{recordType:'text',encoding:'utf-8'}),null)).value,'世界');
 assert.equal((await core.readRecord(record(new Uint8Array([255]),{recordType:'text'}),null)).format,'Hex');
});
test('WENC is interoperable in both directions and authenticates data',async()=>{
 for(const [value,encoding,name] of [['  世界\n','text','text.txt'],['00ff8041','hex','data.bin']]){
  const written=await core.makeRecord(value,encoding,'secret');
  const decoded=await existing.decryptBytes('secret',written.data);
  assert.equal(decoded.filename,name);assert.deepEqual([...decoded.bytes],[...core.inputBytes(value,encoding)]);
  const encrypted=await existing.encryptBytes('secret',decoded.bytes,name);
  const displayed=await core.readRecord(record(encrypted),'secret');
  assert.equal(displayed.value,encoding==='text'?value:'00 ff 80 41');
  await assert.rejects(core.readRecord(record(encrypted),'wrong'),/Incorrect password/);
  encrypted[encrypted.length-1]^=1;
  await assert.rejects(core.readRecord(record(encrypted),'secret'),/Incorrect password/);
 }
 await assert.rejects(core.makeRecord('hello','text',''),/password/);
});
function ui(overrides={},confirm=()=>true){
 const nodes=new Map();
 function element(){return {value:'',checked:false,disabled:false,hidden:false,children:[],handlers:{},addEventListener(event,fn){this.handlers[event]=fn;},replaceChildren(){this.children=[];},append(...nodes){this.children.push(...nodes);},appendChild(node){this.children.push(node);},setAttribute(){},showModal(){this.open=true;},close(){this.open=false;},focus(){this.focused=true;},scrollIntoView(){this.scrolled=true;}};}
 const get=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
 get('read').checked=true;get('encoding-text').checked=true;
 const readers=[];
 const timers=new Map();let timerId=0;
 const setTimeout=(fn,delay)=>{timers.set(++timerId,{fn,delay});return timerId;};
 const clearTimeout=id=>timers.delete(id);
 class NDEFReader{constructor(){readers.push(this);}async scan(options){this.scanOptions=options;if(!this.options)this.options=options;}async write(message,options){this.message=message;this.options=options;}}
 const context=vm.createContext({...globals,isSecureContext:true,NDEFReader,setTimeout,clearTimeout,...overrides,document:{getElementById:get,createElement:element},window:{addEventListener(){},confirm}});
 code.forEach(script=>vm.runInContext(script,context));
 return {get,readers,timers,submit:()=>get('form').handlers.submit({preventDefault(){}})};
}
test('UI reads, cancels scans, writes raw hex, and clears sensitive values',async()=>{
 const {get,readers,timers,submit}=ui();
 await submit();assert.equal(get('controls').disabled,true);assert.equal(get('nfc-dialog').open,true);
 await readers[0].onreading({message:{records:[record(new Uint8Array([0,255]))]}});
 assert.equal(get('records').children[0].children[2].value,'00 ff');
 assert.equal(get('nfc-dialog').open,false);assert.equal(get('result').scrolled,true);
 assert.equal(readers[0].options.signal.aborted,false);
 const timer=[...timers.values()][0];assert.equal(timer.delay,5000);
 await readers[0].onreading({message:{records:[record(new Uint8Array([42]))]}});
 assert.equal(get('records').children.length,1);
 assert.equal(get('records').children[0].children[2].value,'00 ff');
 timer.fn();assert.equal(timers.size,0);
 assert.equal(get('controls').disabled,false);assert.equal(readers[0].options.signal.aborted,true);
 await submit();get('cancel').handlers.click();assert.equal(readers[1].options.signal.aborted,true);
 await readers[1].onreading({message:{records:[record(new Uint8Array([42]))]}});
 assert.equal(get('result').hidden,true);
 get('write').checked=true;get('read').checked=false;get('encoding-text').checked=false;get('encoding-hex').checked=true;get('input').value='00ff';get('write').handlers.change();
 await submit();assert.deepEqual([...readers[2].message.records[0].data],[0,255]);assert.equal(readers[2].options.overwrite,true);
 get('password').value='secret';get('clear').handlers.click();assert.equal(get('password').value,'');assert.equal(get('input').value,'');
});

test('unsupported contexts allow attempts and display the underlying browser error',async()=>{
 const {get,submit}=ui({isSecureContext:false,NDEFReader:undefined});
 get('write').checked=true;get('read').checked=false;
 assert.equal(get('start').disabled,false);
 await submit();
 assert.match(get('status').textContent,/TypeError: NDEFReader is not a constructor/);
 assert.equal(get('nfc-error-dialog').open,true);
 assert.equal(get('nfc-error-message').textContent,get('status').textContent);
 get('nfc-error-close').handlers.click();assert.equal(get('nfc-error-dialog').open,false);
 assert.equal(get('start').disabled,false);
 assert.equal(get('controls').disabled,false);
});
test('write permission errors retain their original name and message',async()=>{
 class DeniedReader {async write(){const error=new Error('NFC permission denied.');error.name='NotAllowedError';throw error;}}
 const {get,submit}=ui({NDEFReader:DeniedReader});
 get('write').checked=true;get('read').checked=false;
 await submit();
 assert.equal(get('status').textContent,'NotAllowedError: NFC permission denied.');
 assert.equal(get('start').disabled,false);
});

test('permanent locking requires native confirmation before any write',async()=>{
 let warning='';
 const {get,readers,submit}=ui({},message=>{warning=message;return false;});
 get('write').checked=true;get('read-only').checked=true;
 await submit();
 assert.match(warning,/cannot be reversed/);assert.equal(readers.length,0);
 assert.match(get('status').textContent,/Nothing was written or locked/);
});
test('confirmed lock follows successful write and resets the option',async()=>{
 const calls=[];
 class Reader {async scan(){calls.push('scan');}async write(){calls.push('write');}async makeReadOnly(options){assert.equal(options.signal.aborted,false);calls.push('lock');}}
 const {get,submit}=ui({NDEFReader:Reader});
 get('write').checked=true;get('read-only').checked=true;
 await submit();
 assert.deepEqual(calls,['write','lock','scan']);assert.equal(get('read-only').checked,false);
 assert.match(get('status').textContent,/made permanently read-only/);
 assert.equal(get('nfc-success-dialog').open,true);
 assert.match(get('nfc-success-message').textContent,/made permanently read-only/);
});
test('lock errors report successful write and preserve browser error',async()=>{
 class Reader {async write(){}async makeReadOnly(){throw new Error('Tag cannot be locked');}}
 const {get,submit}=ui({NDEFReader:Reader});
 get('write').checked=true;get('read-only').checked=true;
 await submit();
 assert.match(get('status').textContent,/Card was written, but permanent locking was not confirmed. Error: Tag cannot be locked/);
 assert.equal(get('start').disabled,false);
});
test('failed writes never proceed to permanent locking',async()=>{
 let locked=false;
 class Reader {async write(){throw new Error('Write failed');}async makeReadOnly(){locked=true;}}
 const {get,submit}=ui({NDEFReader:Reader});
 get('write').checked=true;get('read-only').checked=true;
 await submit();assert.equal(locked,false);
 assert.equal(get('status').textContent,'Error: Write failed');
});

test('write prompt remains open while waiting and dialog cancellation aborts writing',async()=>{
 let signal;
 class Reader {write(message,options){signal=options.signal;return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('Aborted'))));}}
 const {get,submit}=ui({NDEFReader:Reader});get('write').checked=true;
 const pending=submit();await new Promise(resolve=>setImmediate(resolve));
 assert.equal(get('nfc-dialog').open,true);
 assert.match(get('nfc-dialog-status').textContent,/Hold the card/);
 get('nfc-dialog-cancel').handlers.click();await pending;
 assert.equal(signal.aborted,true);assert.equal(get('nfc-dialog').open,false);
 assert.equal(get('start').disabled,false);
});

test('scan security failures replace the waiting dialog with the browser error',async()=>{
 class Reader {async scan(){const error=new Error('Access requires a secure context.');error.name='SecurityError';throw error;}}
 const {get,submit}=ui({NDEFReader:Reader});await submit();
 assert.equal(get('nfc-dialog').open,false);
 assert.equal(get('nfc-error-dialog').open,true);
 assert.equal(get('nfc-error-message').textContent,'SecurityError: Access requires a secure context.');
 assert.equal(get('start').disabled,false);
});

test('successful writes keep a scan active for five seconds and cancellation clears its timer',async()=>{
 for(const cancelEarly of [false,true]){
  const {get,readers,timers,submit}=ui();get('write').checked=true;
  await submit();
  assert.equal(get('nfc-success-dialog').open,true);
  assert.equal(get('nfc-success-message').textContent,'Card written successfully.');
  get('nfc-success-close').handlers.click();
  assert.equal(get('nfc-success-dialog').open,false);
  const signal=readers[0].scanOptions.signal;
  assert.equal(signal.aborted,false);assert.equal(get('nfc-dialog').open,false);
  const timer=[...timers.values()][0];assert.equal(timer.delay,5000);
  assert.match(get('status').textContent,/five seconds/);
  if(cancelEarly)get('cancel').handlers.click();else timer.fn();
  assert.equal(signal.aborted,true);assert.equal(timers.size,0);
  assert.equal(get('start').disabled,false);
 }
});
test('post-write scan failure does not claim the write or locking failed',async()=>{
 class Reader {async write(){}async scan(){throw new Error('Scan unavailable');}}
 const {get,submit}=ui({NDEFReader:Reader});get('write').checked=true;await submit();
 assert.equal(get('nfc-error-message').textContent,'Writing completed, but the NFC session could not stay active. Error: Scan unavailable');
 assert.equal(get('start').disabled,false);
});

test('plain-text NFC records render password/TOTP cards and clear live entries; binary stays hex',async()=>{
 const intervals=new Map();let counter=0,copied='';
 const {get,readers,submit}=ui({URL,navigator:{clipboard:{async writeText(value){copied=value;}}},setInterval(fn){intervals.set(++counter,fn);return counter;},clearInterval(id){intervals.delete(id);}});
 const plaintext='Mail: secret:123\notpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
 await submit();
 await readers[0].onreading({message:{records:[record(new TextEncoder().encode(plaintext),{recordType:'text',encoding:'utf-8'})]}});
 const content=get('records').children[0];
 const totps=content.children[2], passwords=content.children[3],full=content.children[5],revealFull=content.children[6];
 assert.equal(totps.children.length,1);assert.equal(totps.children[0].children[0].textContent,'Example · alice');
 assert.equal(intervals.size,1);
 const password=passwords.children[0];assert.equal(password.children[0].textContent,'Mail');
 assert.equal(password.children[1].textContent,'***********');
 await password.children[2].children[1].handlers.click();assert.equal(copied,' secret:123');
 password.children[2].children[0].handlers.click();assert.equal(password.children[1].textContent,' secret:123');
 assert.equal(full.value.includes('secret'),false);revealFull.handlers.click();assert.equal(full.value,plaintext);
 get('clear').handlers.click();assert.equal(intervals.size,0);assert.equal(full.value,'');assert.equal(passwords.children.length,0);
 await submit();
 await readers[1].onreading({message:{records:[record(new TextEncoder().encode(plaintext))]}});
 assert.equal(get('records').children[0].children.length,3);assert.equal(intervals.size,0);
 assert.equal(get('records').children[0].children[2].value,core.toHex(new TextEncoder().encode(plaintext)));
});
