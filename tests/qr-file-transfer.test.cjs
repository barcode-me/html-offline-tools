const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const html=fs.readFileSync(require('node:path').join(__dirname,'../qr-file-transfer.html'),'utf8');
const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]);
function setup(){
 const nodes=new Map(),copied=[],frames=[];
 function node(){return {value:'',checked:false,hidden:false,disabled:false,textContent:'',files:[],style:{},handlers:{},elements:{},addEventListener(type,fn){(this.handlers[type]??=[]).push(fn);},setAttribute(){},scrollIntoView(){},focus(){},play:async()=>{},querySelector:()=>({disabled:false}),getContext:()=>({fillRect(){}})};}
 const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};
 const form=get('#transfer-setup');form.elements={'role':{value:'send'},mode:{value:'static'},'input-type':{value:'hex'}};
 get('#chunk-bytes').value='400';get('#dwell-seconds').value='2';
 let raw='';
 class Detector{static async getSupportedFormats(){return ['qr_code'];}async detect(){return [{rawValue:raw}];}}
 const qrcode=()=>({addData(value){frames.push(value);},make(){},getModuleCount:()=>1,isDark:()=>false});qrcode.stringToBytesFuncs={default:()=>{},'UTF-8':()=>{}};
 const context=vm.createContext({TextEncoder,TextDecoder,Uint8Array,Blob,crypto:webcrypto,btoa,atob,performance,Event,setTimeout:()=>1,clearTimeout(){},qrcode,BarcodeDetector:Detector,navigator:{clipboard:{async writeText(value){copied.push(value);}},mediaDevices:{async getUserMedia(){return {getTracks:()=>[]};}}},document:{querySelector:get},window:{BarcodeDetector:Detector,addEventListener(){},dispatchEvent(){}}});
 vm.runInContext(scripts[1],context);
 vm.runInContext(scripts[2].replace('      updateEstimate();\n    })();','      globalThis.api={showReceived,inputBytes,beginSend,beginReceive,estimatedInputBytes,receivePayload,encryptForTransfer,getReceived:()=>({blob:receivedBlob,name:receivedName})};\n      updateEstimate();\n    })();'),context);
 return {context,get,form,copied,frames,setRaw:value=>raw=value,fire:async(id,type,event={})=>{for(const fn of get(id).handlers[type]||[])await fn(event);}};
}
test('hex sending preserves leading zeros and rejects malformed pairs',async()=>{
 const {context,get,fire}=setup();get('#hex-input').value='00 ff 80\n41';
 const input=await context.api.inputBytes();assert.deepEqual([...input.bytes],[0,255,128,65]);assert.equal(input.type,'application/octet-stream');
 assert.equal(context.api.estimatedInputBytes(),4);
 for(const value of ['0','0x00','fg','00:ff']){
  get('#hex-input').value=value;await assert.rejects(context.api.inputBytes());await fire('#hex-input','input');assert.equal(get('#review-button').disabled,true);
 }
});
test('invalid UTF-8 displays hex; copying and format switching preserve exact text',async()=>{
 const {context,get,fire,copied}=setup();context.api.showReceived(new Uint8Array([0,255,128,65]));
 assert.equal(get('#received-utf8').disabled,true);assert.equal(get('#received-text').textContent,'00 ff 80 41');
 await fire('#copy-received','click');assert.equal(copied.pop(),'00 ff 80 41');
 const text='\ufeff  café 世界\n';context.api.showReceived(new TextEncoder().encode(text));
 assert.equal(get('#received-utf8').disabled,false);assert.equal(get('#received-text').textContent,text);
 await fire('#copy-received','click');assert.equal(copied.pop(),text);
 get('#received-hex').checked=true;get('#received-utf8').checked=false;await fire('#received-hex','change');
 assert.equal(get('#copy-received').textContent,'Copy hex');await fire('#copy-received','click');
 assert.equal(copied.pop(),Buffer.from(text).toString('hex').match(/../g).join(' '));
});
test('static hex payload survives a text-only native QR decoder',async()=>{
 const {context,get,frames,setRaw}=setup();get('#hex-input').value='00ff8041';
 await context.api.beginSend('static');assert.equal(JSON.parse(frames[0]).type,'binary_static');
 setRaw(frames[0]);await context.api.beginReceive('static');await new Promise(resolve=>setImmediate(resolve));
 assert.equal(get('#received-text').textContent,'00 ff 80 41');assert.equal(get('#received-actions').hidden,false);
});

test('chunked binary data is displayed as hex after integrity verification',async()=>{
 const {context,get}=setup();
 const bytes=Buffer.from([0,255,128,65]);const hash=require('node:crypto').createHash('sha256').update(bytes).digest('hex');
 await context.api.receivePayload(JSON.stringify({type:'file_metadata',filename:'test.bin',sha256:hash,chunks:1}),false);
 await context.api.receivePayload(JSON.stringify({type:'data_chunk',order:0,data:bytes.toString('hex')}),false);
 assert.equal(get('#received-text').textContent,'00 ff 80 41');
 assert.match(get('#session-status').textContent,/SHA-256 verified/);
});
test('encrypted static hex is displayed and copied after decryption',async()=>{
 const {context,get,frames,setRaw,fire,copied}=setup();
 get('#hex-input').value='00ff8041';get('#encrypt-transfer').checked=true;get('#send-password').value='secret';
 await context.api.beginSend('static');setRaw(frames[0]);
 await context.api.beginReceive('static');await new Promise(resolve=>setImmediate(resolve));
 assert.match(get('#session-status').textContent,/not decrypted/);
 assert.equal(get('#received-actions').hidden,false);
 const saved=JSON.parse(await context.api.getReceived().blob.text());
 assert.equal(saved.type,'encrypted_static');assert.equal(saved.encryption.algorithm,'AES-GCM');
 get('#receive-password').value='secret';await fire('#receive-password-panel','submit',{preventDefault(){}});
 assert.equal(get('#received-text').textContent,'00 ff 80 41');
 await fire('#copy-received','click');assert.equal(copied.pop(),'00 ff 80 41');
});

test('encrypted chunked transfers receive without password, auto-decrypt, or allow retries',async()=>{
 for(const password of ['', 'secret', 'wrong']){
  const {context,get,frames,setRaw,fire}=setup();
  const original=new Uint8Array([0,255,128,65]);
  const secured=await context.api.encryptForTransfer(original,'secret','binary.bin','application/octet-stream');
  get('#receive-setup-password').value=password;setRaw('{}');
  await context.api.beginReceive('bidirectional');
  const bytes=Buffer.from(secured.bytes);
  const sha256=require('node:crypto').createHash('sha256').update(bytes).digest('hex');
  await context.api.receivePayload(JSON.stringify({type:'file_metadata',filename:'encrypted-content.bin',sha256,chunks:1,size:bytes.length,encryption:secured.encryption}),true);
  assert.equal(JSON.parse(frames.at(-1)).type,'file_metadata','handshake proceeds without decryption');
  await context.api.receivePayload(JSON.stringify({type:'data_chunk',order:0,data:bytes.toString('hex'),sha256}),true);
  if(password==='secret'){
   assert.equal(get('#received-text').textContent,'00 ff 80 41');
   assert.deepEqual(Buffer.from(await context.api.getReceived().blob.arrayBuffer()),Buffer.from(original));
  }else{
   assert.equal(context.api.getReceived().name,'encrypted-transfer.json');
   const envelope=JSON.parse(await context.api.getReceived().blob.text());
   assert.deepEqual(Buffer.from(envelope.data,'base64'),bytes);
   assert.equal(get('#received-text').textContent,bytes.toString('hex').match(/../g).join(' '));
   if(password==='wrong')assert.match(get('#password-status').textContent,/Incorrect password/);
   get('#receive-password').value='secret';await fire('#receive-password-panel','submit',{preventDefault(){}});
   assert.equal(get('#received-text').textContent,'00 ff 80 41');
  }
 }
});
